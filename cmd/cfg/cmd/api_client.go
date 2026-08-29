// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
)

// Exact warning and confirmation text — referenced by tests for wording match.
const tlsInsecureMTLSWarning = "Warning: --tls-insecure: server certificate is not verified." +
	" mTLS client credential cannot be stolen or replayed (content exposure only).\n"

const tlsInsecureSessionWarning = "Warning: --tls-insecure: server certificate is not verified." +
	" Session token is a replayable bearer credential — a MITM who captures it can replay it against the real controller.\n"

const tlsInsecureConfirmPrompt = "Type 'I understand the risk' to proceed: "

const tlsInsecureConfirmPhrase = "I understand the risk"

// tlsInsecureWriter is the output sink for TLS-insecure warnings and prompts.
// Overridable in tests; defaults to stderr.
var tlsInsecureWriter io.Writer = os.Stderr

// tlsInsecureReader is the input source for TLS-insecure typed confirmation.
// Overridable in tests; defaults to stdin.
var tlsInsecureReader io.Reader = os.Stdin

// isTTYFn reports whether the process stdin is an interactive terminal.
// Overridable in tests.
var isTTYFn = func() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// requireTLSInsecureForSession prompts for confirmation before connecting with a
// plain bearer session token over a connection whose server certificate is not verified.
//
// On a TTY: prints the warning and prompts for tlsInsecureConfirmPhrase.
// Non-interactive: requires CFGMS_TLS_INSECURE_CONFIRM=yes.
// Returns an error if confirmation is denied or unavailable.
func requireTLSInsecureForSession() error {
	_, _ = fmt.Fprint(tlsInsecureWriter, tlsInsecureSessionWarning)
	if isTTYFn() {
		_, _ = fmt.Fprint(tlsInsecureWriter, tlsInsecureConfirmPrompt)
		scanner := bufio.NewScanner(tlsInsecureReader)
		if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != tlsInsecureConfirmPhrase {
			return fmt.Errorf("--tls-insecure with a session token requires typing %q to proceed", tlsInsecureConfirmPhrase)
		}
		return nil
	}
	if os.Getenv("CFGMS_TLS_INSECURE_CONFIRM") != "yes" {
		return fmt.Errorf("--tls-insecure with a session token requires CFGMS_TLS_INSECURE_CONFIRM=yes in non-interactive mode")
	}
	return nil
}

// APIClient provides HTTP client functionality for communicating with the controller API
type APIClient struct {
	baseURL          string
	bearerToken      string
	httpClient       *http.Client
	onTokenRenewed   func(newToken string) error
	onUnauthorized   func() (*APIClient, error)
	onStepUpRequired func(wwwAuthenticate string) (presenceToken string, err error)
}

// APIClientConfig contains configuration for creating an API client
type APIClientConfig struct {
	BaseURL string
	// BearerToken is sent as "Authorization: Bearer <token>". It carries a
	// session token (resolveSessionOrBundleClient) — never an API key; the cfg
	// CLI accepts only mTLS-bundle or session-token credentials (Issue #3688).
	BearerToken   string
	CACertPEM     []byte // CA certificate for server verification (nil to skip verification)
	ClientCertPEM []byte // Client certificate for mTLS authentication
	ClientKeyPEM  []byte // Client private key for mTLS authentication
	TLSInsecure   bool   // Skip TLS verification (development only)
	ServerName    string // Server name for TLS verification (extracted from URL if empty)

	// OnTokenRenewed is called after each response when the server issues a renewed
	// session token via the X-Session-Token response header. Nil = no-op.
	// Errors from this callback are ignored (best-effort write-back).
	OnTokenRenewed func(newToken string) error

	// OnUnauthorized is called when the server returns 401 and may return a
	// fallback APIClient to retry the request with. Nil = no fallback.
	// When the fallback client is non-nil the request is retried once and the
	// message "session expired or revoked — falling back to bundle auth" is
	// printed to stderr.
	OnUnauthorized func() (*APIClient, error)

	// OnStepUpRequired is called when the server returns 401 with
	// WWW-Authenticate: CFGMS-StepUp, indicating that the current assurance level
	// is insufficient for the requested action. This is distinct from a plain
	// session-expired 401 (no CFGMS-StepUp header), which routes to OnUnauthorized.
	//
	// The callback receives the full WWW-Authenticate header value. It should:
	//   - Return a non-empty presence token on success (causes the original request
	//     to be retried with X-Presence-Token).
	//   - Return an error when the step-up cannot be completed (e.g., non-interactive
	//     environment, unsupported assurance elevation).
	//
	// Nil = 401 with CFGMS-StepUp header is returned to the caller unchanged.
	OnStepUpRequired func(wwwAuthenticate string) (presenceToken string, err error)
}

// APITokenCreateRequest represents the request body for creating a registration token
type APITokenCreateRequest struct {
	TenantID      string `json:"tenant_id"`
	ControllerURL string `json:"controller_url"`
	Group         string `json:"group,omitempty"`
	ExpiresIn     string `json:"expires_in,omitempty"`
}

// APITokenResponse represents a registration token in API responses
type APITokenResponse struct {
	Token         string  `json:"token"`
	TenantID      string  `json:"tenant_id"`
	ControllerURL string  `json:"controller_url"`
	Group         string  `json:"group,omitempty"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	Revoked       bool    `json:"revoked"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
}

// TokenListResponse represents a list of tokens from the API
type APITokenListResponse struct {
	Tokens []APITokenResponse `json:"tokens"`
	Total  int                `json:"total"`
}

// NewAPIClient creates a new API client with the given configuration
// Uses pkg/cert for TLS configuration to comply with central provider patterns
func NewAPIClient(cfg *APIClientConfig) (*APIClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Build TLS configuration using pkg/cert
	var tlsConfig *tls.Config
	var err error

	if cfg.TLSInsecure {
		// Development mode: skip server certificate verification.
		// When client certs are provided (mTLS), still include them so the server
		// can authenticate the client; server-side auth is unaffected by InsecureSkipVerify.
		// #nosec G402 - InsecureSkipVerify explicitly requested via --tls-insecure flag
		var insecureCfg tls.Config
		insecureCfg.MinVersion = tls.VersionTLS12
		insecureCfg.InsecureSkipVerify = true // #nosec G402
		if cfg.ServerName != "" {
			insecureCfg.ServerName = cfg.ServerName
		}
		if cfg.ClientCertPEM != nil && cfg.ClientKeyPEM != nil {
			_, _ = fmt.Fprint(tlsInsecureWriter, tlsInsecureMTLSWarning)
			clientCert, certErr := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
			if certErr != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", certErr)
			}
			insecureCfg.Certificates = []tls.Certificate{clientCert}
		}
		tlsConfig = &insecureCfg
	} else if cfg.ClientCertPEM != nil && cfg.ClientKeyPEM != nil {
		// mTLS mode: mutual TLS with client certificate and optional CA cert
		tlsConfig, err = cert.CreateClientTLSConfig(cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM, cfg.ServerName, tls.VersionTLS12)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS config: %w", err)
		}
	} else if cfg.CACertPEM != nil {
		// Server-auth only: use CA cert for server verification via pkg/cert helper
		tlsConfig, err = cert.CreateClientTLSConfig(nil, nil, cfg.CACertPEM, cfg.ServerName, tls.VersionTLS12)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
	} else {
		// Default: use system CA pool via pkg/cert helper (nil certs, nil CA)
		tlsConfig, err = cert.CreateClientTLSConfig(nil, nil, nil, cfg.ServerName, tls.VersionTLS12)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
	}

	return &APIClient{
		baseURL:          cfg.BaseURL,
		bearerToken:      cfg.BearerToken,
		onTokenRenewed:   cfg.OnTokenRenewed,
		onUnauthorized:   cfg.OnUnauthorized,
		onStepUpRequired: cfg.OnStepUpRequired,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

// CreateToken creates a new registration token via the controller API
func (c *APIClient) CreateToken(ctx context.Context, req *APITokenCreateRequest) (*APITokenResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// ListTokens lists registration tokens via the controller API
func (c *APIClient) ListTokens(ctx context.Context, tenantID string) (*APITokenListResponse, error) {
	path := "/api/v1/registration/tokens"
	if tenantID != "" {
		path += "?tenant_id=" + tenantID
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var listResp APITokenListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResp, nil
}

// GetToken retrieves a specific token via the controller API
func (c *APIClient) GetToken(ctx context.Context, tokenStr string) (*APITokenResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/registration/tokens/"+tokenStr, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// DeleteToken deletes a token via the controller API
func (c *APIClient) DeleteToken(ctx context.Context, tokenStr string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/api/v1/registration/tokens/"+tokenStr, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// RevokeToken revokes a token via the controller API
func (c *APIClient) RevokeToken(ctx context.Context, tokenStr string) (*APITokenResponse, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/tokens/"+tokenStr+"/revoke", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// APIRotateTokenRequest is the optional request body for the rotate endpoint.
type APIRotateTokenRequest struct {
	Group string `json:"group,omitempty"`
}

// RotateToken atomically revokes all prior tokens for a tenant+group and returns the new token.
func (c *APIClient) RotateToken(ctx context.Context, tenantID, group string) (*APITokenResponse, error) {
	req := &APIRotateTokenRequest{Group: group}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/tokens/"+tenantID+"/rotate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var tokenResp APITokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// APIPendingRegistration represents a quarantined steward awaiting approval in API responses.
type APIPendingRegistration struct {
	PendingID    string    `json:"pending_id"`
	StewardID    string    `json:"steward_id"`
	TenantID     string    `json:"tenant_id"`
	SourceIP     string    `json:"source_ip"`
	RDNS         string    `json:"rdns,omitempty"` // populated by CLI at display time via net.LookupAddr
	RegisteredAt time.Time `json:"registered_at"`
}

// ListPendingRegistrations lists quarantined stewards awaiting admin approval.
func (c *APIClient) ListPendingRegistrations(ctx context.Context) ([]APIPendingRegistration, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/registration/pending", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var pending []APIPendingRegistration
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return pending, nil
}

// ApproveRegistration approves a quarantined steward registration by pending_id.
func (c *APIClient) ApproveRegistration(ctx context.Context, pendingID string) error {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/"+pendingID+"/approve", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// DenyRegistration denies a quarantined steward registration by pending_id with an optional reason.
func (c *APIClient) DenyRegistration(ctx context.Context, pendingID, reason string) error {
	body, err := json.Marshal(struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: reason})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/"+pendingID+"/deny", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// ApproveAllRegistrations approves all pending registrations and returns the count of newly approved.
func (c *APIClient) ApproveAllRegistrations(ctx context.Context) (int, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/approve-all", nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, c.parseError(resp)
	}

	var result struct {
		Approved int `json:"approved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}
	return result.Approved, nil
}

// ApproveByCIDR approves pending registrations whose source IP falls within the given CIDR.
func (c *APIClient) ApproveByCIDR(ctx context.Context, cidr string) (int, error) {
	body, err := json.Marshal(struct {
		CIDR string `json:"cidr"`
	}{CIDR: cidr})
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/approve-by-cidr", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, c.parseError(resp)
	}

	var result struct {
		Approved int `json:"approved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}
	return result.Approved, nil
}

// AddIPTrust adds a trusted CIDR range for a tenant (pre-seeded by default).
func (c *APIClient) AddIPTrust(ctx context.Context, tenantID, cidr string) error {
	body, err := json.Marshal(struct {
		TenantID  string `json:"tenant_id"`
		CIDR      string `json:"cidr"`
		PreSeeded bool   `json:"pre_seeded"`
	}{TenantID: tenantID, CIDR: cidr, PreSeeded: true})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/registration/ip-trust", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// RevokeIPTrust revokes a trusted CIDR range for a tenant.
func (c *APIClient) RevokeIPTrust(ctx context.Context, tenantID, cidr string) error {
	// PathEscape encodes '/' as '%2F' so the CIDR survives as a single path segment;
	// the server uses {cidr:.+} to match the decoded form.
	path := "/api/v1/registration/ip-trust/" + url.PathEscape(tenantID) + "/" + url.PathEscape(cidr)
	resp, err := c.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// Get performs an HTTP GET request and returns the response.
// Callers are responsible for closing resp.Body.
func (c *APIClient) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.doRequest(ctx, "GET", path, nil)
}

// doRequest performs an HTTP request with authentication
func (c *APIClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	return c.doRequestWithContentType(ctx, method, path, body, "application/json")
}

// doRequestWithContentType performs an HTTP request with the specified Content-Type.
// The path argument must already be percent-encoded (e.g. via url.PathEscape) and
// may include a query string (e.g. "/api/v1/foo?bar=baz").
//
// Go's http.NewRequestWithContext normalizes percent-encoded slashes (%2F → /)
// in path segments when it re-parses the URL string.  To prevent this we build
// the request URL manually: parse the base URL, split path from query, apply the
// pre-encoded path via RawPath, and restore RawPath after NewRequestWithContext.
func (c *APIClient) doRequestWithContentType(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	// Buffer the body so it can be replayed on a 401 fallback retry.
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("failed to buffer request body: %w", err)
		}
	}
	return c.execRequest(ctx, method, path, bodyBytes, contentType, true, "")
}

// execRequest is the inner send-and-receive loop shared by doRequestWithContentType
// and the 401-fallback retry path. allowFallback prevents infinite recursion.
// presenceToken, when non-empty, is attached as X-Presence-Token (step-up retry path).
func (c *APIClient) execRequest(ctx context.Context, method, path string, bodyBytes []byte, contentType string, allowFallback bool, presenceToken string) (*http.Response, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Split path from query string — only the path portion needs RawPath treatment.
	rawPath := path
	rawQuery := ""
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		rawPath = path[:idx]
		rawQuery = path[idx+1:]
	}

	// Decode the path-only portion so we can set both Path and RawPath correctly.
	// url.URL.RequestURI() uses RawPath when set (and when it differs from the
	// escaped form of Path), which is exactly what we need to preserve %2F.
	decodedPath, decErr := url.PathUnescape(rawPath)
	if decErr != nil {
		decodedPath = rawPath
	}
	base.Path = base.Path + decodedPath
	base.RawPath = base.RawPath + rawPath
	base.RawQuery = rawQuery

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// #nosec G704 — SSRF FP: this is an admin CLI tool; the base URL is set by the
	// operator via --url / CFGMS_API_URL or the admin bundle (operator-controlled config).
	// No user-supplied tainted input reaches this URL construction path.
	req, err := http.NewRequestWithContext(ctx, method, base.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	// NewRequestWithContext re-parses the URL string and may normalise %2F.
	// Restore our pre-encoded RawPath so the HTTP client sends the correct wire path.
	req.URL.RawPath = base.RawPath

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	if presenceToken != "" {
		req.Header.Set("X-Presence-Token", presenceToken)
	}

	resp, err := c.httpClient.Do(req) // #nosec G704 — see comment above
	if err != nil {
		return nil, err
	}

	// Rolling token renewal: persist the rotated token when the server issues one.
	if newToken := resp.Header.Get("X-Session-Token"); newToken != "" && c.onTokenRenewed != nil {
		_ = c.onTokenRenewed(newToken) // best-effort; never fail the request
	}

	if allowFallback && resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(wwwAuth, "CFGMS-StepUp") {
			// Step-up challenge: distinct from a session-expired 401. Only the presence
			// of the CFGMS-StepUp scheme in WWW-Authenticate routes here; plain 401s
			// (session expired/revoked) route to onUnauthorized below.
			if c.onStepUpRequired != nil {
				_ = resp.Body.Close()
				token, stepUpErr := c.onStepUpRequired(wwwAuth)
				if stepUpErr != nil {
					return nil, stepUpErr
				}
				if token != "" {
					return c.execRequest(ctx, method, path, bodyBytes, contentType, false, token)
				}
				return nil, fmt.Errorf("step-up required")
			}
			return resp, nil
		}
		// Ordinary 401 (no CFGMS-StepUp header): session expired or revoked.
		// Transparently retry with a bundle-auth client if one is available.
		if c.onUnauthorized != nil {
			fallbackClient, fallbackErr := c.onUnauthorized()
			if fallbackErr == nil && fallbackClient != nil {
				_ = resp.Body.Close()
				fmt.Fprintln(os.Stderr, "session expired or revoked — falling back to bundle auth")
				return fallbackClient.execRequest(ctx, method, path, bodyBytes, contentType, false, "")
			}
		}
	}

	return resp, nil
}

// APITenantCreateRequest is the request body for POST /api/v1/tenants.
type APITenantCreateRequest struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

// APITenantResponse represents a tenant returned by the controller API.
type APITenantResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Status      string            `json:"status"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// ErrTenantAlreadyExists is returned by CreateTenantViaAPI when the server responds HTTP 409.
var ErrTenantAlreadyExists = fmt.Errorf("tenant already exists")

// CreateTenantViaAPI creates a tenant via the controller REST API.
// Returns ErrTenantAlreadyExists when the server responds HTTP 409 (idempotent callers
// should treat that as success and exit 0).
func (c *APIClient) CreateTenantViaAPI(ctx context.Context, req *APITenantCreateRequest) (*APITenantResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/tenants", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return nil, ErrTenantAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var tenant APITenantResponse
	if err := json.Unmarshal(envelope.Data, &tenant); err != nil {
		return nil, fmt.Errorf("failed to decode tenant data: %w", err)
	}
	return &tenant, nil
}

// GetTenantViaAPI retrieves a tenant by ID via the controller REST API.
func (c *APIClient) GetTenantViaAPI(ctx context.Context, tenantID string) (*APITenantResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/tenants/"+tenantID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var tenant APITenantResponse
	if err := json.Unmarshal(envelope.Data, &tenant); err != nil {
		return nil, fmt.Errorf("failed to decode tenant data: %w", err)
	}
	return &tenant, nil
}

// APIDispatchUpgradeRequest is the request body for POST /api/v1/stewards/upgrade.
type APIDispatchUpgradeRequest struct {
	Selector string `json:"selector"`
	Version  string `json:"version"`
	Platform string `json:"platform,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

// APIDispatchUpgradeResponse is the response from POST /api/v1/stewards/upgrade.
type APIDispatchUpgradeResponse struct {
	UpgradeID    string `json:"upgrade_id"`
	StewardCount int    `json:"steward_count"`
	Status       string `json:"status"`
}

// APIUpgradeStewardStatus represents per-steward upgrade status within an upgrade record.
type APIUpgradeStewardStatus struct {
	Device      string `json:"device"`
	Status      string `json:"status"`
	Version     string `json:"version,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// APIUpgradeStatusResponse is the response from GET /api/v1/stewards/upgrade/{id}
// and from GET /api/v1/stewards/upgrade?selector=<selector>.
type APIUpgradeStatusResponse struct {
	UpgradeID string                    `json:"upgrade_id"`
	Stewards  []APIUpgradeStewardStatus `json:"stewards"`
}

// APIRollbackRequest is the optional request body for POST /api/v1/stewards/upgrade/{id}/rollback.
type APIRollbackRequest struct {
	ToVersion string `json:"to_version,omitempty"`
}

// DispatchUpgrade calls POST /api/v1/stewards/upgrade and returns the dispatch result.
func (c *APIClient) DispatchUpgrade(ctx context.Context, req *APIDispatchUpgradeRequest) (*APIDispatchUpgradeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/stewards/upgrade", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIDispatchUpgradeResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode dispatch data: %w", err)
	}
	return &result, nil
}

// GetUpgradeStatus calls GET /api/v1/stewards/upgrade/{id} and returns the status.
func (c *APIClient) GetUpgradeStatus(ctx context.Context, upgradeID string) (*APIUpgradeStatusResponse, error) {
	result, _, err := c.GetUpgradeStatusWithHTTPStatus(ctx, upgradeID)
	return result, err
}

// GetUpgradeStatusWithHTTPStatus calls GET /api/v1/stewards/upgrade/{id} and
// returns the parsed status, the raw HTTP status code, and any transport error.
// The caller may inspect the HTTP status code before deciding whether to retry or abort.
func (c *APIClient) GetUpgradeStatusWithHTTPStatus(ctx context.Context, upgradeID string) (*APIUpgradeStatusResponse, int, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stewards/upgrade/"+url.PathEscape(upgradeID), nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, resp.StatusCode, fmt.Errorf("upgrade status request failed with status %d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, c.parseError(resp)
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIUpgradeStatusResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to decode status data: %w", err)
	}
	return &result, resp.StatusCode, nil
}

// ListUpgradeStatusBySelector calls GET /api/v1/stewards/upgrade?selector=<selector>
// to retrieve the most recent upgrade status per steward matching the selector.
func (c *APIClient) ListUpgradeStatusBySelector(ctx context.Context, selector string) (*APIUpgradeStatusResponse, error) {
	path := "/api/v1/stewards/upgrade?selector=" + url.QueryEscape(selector)

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIUpgradeStatusResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode status data: %w", err)
	}
	return &result, nil
}

// RollbackUpgrade calls POST /api/v1/stewards/upgrade/{id}/rollback.
func (c *APIClient) RollbackUpgrade(ctx context.Context, upgradeID string, req *APIRollbackRequest) (*APIUpgradeStatusResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/stewards/upgrade/"+url.PathEscape(upgradeID)+"/rollback", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, c.parseError(resp)
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIUpgradeStatusResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode rollback data: %w", err)
	}
	return &result, nil
}

// ListPendingRefreshes lists pending registration-refresh requests.
// An empty tenantID returns entries for all tenants.
func (c *APIClient) ListPendingRefreshes(ctx context.Context, tenantID string) ([]APIPendingRefreshEntry, error) {
	path := "/api/v1/stewards/refresh/pending"
	if tenantID != "" {
		path += "?tenant_id=" + url.QueryEscape(tenantID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var entries []APIPendingRefreshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return entries, nil
}

// ApproveRefresh approves a pending registration-refresh request by pending_id.
func (c *APIClient) ApproveRefresh(ctx context.Context, pendingID string) (*APIApproveRefreshResponse, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/stewards/refresh/"+url.PathEscape(pendingID)+"/approve", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result APIApproveRefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &result, nil
}

// RejectRefresh rejects a pending registration-refresh request by pending_id.
func (c *APIClient) RejectRefresh(ctx context.Context, pendingID, reason string) error {
	body, err := json.Marshal(struct {
		Reason string `json:"reason,omitempty"`
	}{Reason: reason})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/stewards/refresh/"+url.PathEscape(pendingID)+"/reject", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// GetRefreshPolicy retrieves the per-tenant registration-refresh policy.
func (c *APIClient) GetRefreshPolicy(ctx context.Context, tenantID string) (*APIRefreshPolicyResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/tenants/"+url.PathEscape(tenantID)+"/refresh-policy", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var policy APIRefreshPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &policy, nil
}

// SetRefreshPolicy creates or replaces the per-tenant registration-refresh policy.
func (c *APIClient) SetRefreshPolicy(ctx context.Context, tenantID, mode string, maxDormancyDays *int) error {
	reqBody := struct {
		Mode            string `json:"mode"`
		MaxDormancyDays *int   `json:"max_dormancy_days,omitempty"`
	}{
		Mode:            mode,
		MaxDormancyDays: maxDormancyDays,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "PUT", "/api/v1/tenants/"+url.PathEscape(tenantID)+"/refresh-policy", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// APIResolveSelectorRequest is the request body for POST /api/v1/fleet/resolve.
type APIResolveSelectorRequest struct {
	Selector string `json:"selector"`
}

// ResolveSelector calls POST /api/v1/fleet/resolve and returns the matched stewards.
// The response is unwrapped from the standard {"data": [...]} envelope.
func (c *APIClient) ResolveSelector(ctx context.Context, selector string) ([]StewardInfo, error) {
	body, err := json.Marshal(APIResolveSelectorRequest{Selector: selector})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/fleet/resolve", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data []StewardInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// parseError extracts error message from HTTP response
func (c *APIClient) parseError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	// Try to parse as JSON error
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil {
		if errResp.Error != "" {
			return fmt.Errorf("API error: %s", errResp.Error)
		}
		if errResp.Message != "" {
			return fmt.Errorf("API error: %s", errResp.Message)
		}
	}

	// Return raw body as error message
	return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
}

// sessionIssueRequest is the JSON body for POST /api/v1/sessions.
type sessionIssueRequest struct {
	ConnectionName string `json:"connection_name"`
}

// sessionIssueResponse is the JSON response from POST /api/v1/sessions (HTTP 201).
type sessionIssueResponse struct {
	SessionID      string    `json:"session_id"`
	Token          string    `json:"token"`
	IssuedAt       time.Time `json:"issued_at"`
	IdleTTLSeconds int64     `json:"idle_ttl_seconds"`
	AbsoluteExpiry time.Time `json:"absolute_expiry"`
}

// IssueSession calls POST /api/v1/sessions and returns the session response.
// The caller must be using an admin mTLS credential (client cert).
func (c *APIClient) IssueSession(ctx context.Context, connectionName string) (*sessionIssueResponse, error) {
	body, err := json.Marshal(sessionIssueRequest{ConnectionName: connectionName})
	if err != nil {
		return nil, fmt.Errorf("session create: marshal: %w", err)
	}
	resp, err := c.doRequestWithContentType(ctx, "POST", "/api/v1/sessions", bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, fmt.Errorf("session create: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}
	var out sessionIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("session create: decode response: %w", err)
	}
	return &out, nil
}

// RevokeSession calls DELETE /api/v1/sessions/{id}.
// A 404 is treated as success (already gone).
func (c *APIClient) RevokeSession(ctx context.Context, sessionID string) error {
	resp, err := c.doRequestWithContentType(ctx, "DELETE", "/api/v1/sessions/"+url.PathEscape(sessionID), nil, "")
	if err != nil {
		return fmt.Errorf("session revoke: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil // already revoked or never existed
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// --- WebAuthn credential management (Issue #2783) ---

// APIWebAuthnCredentialInfo is the CLI-side view of a registered WebAuthn credential.
type APIWebAuthnCredentialInfo struct {
	ID           string   `json:"id"`
	Label        string   `json:"label,omitempty"`
	Transport    []string `json:"transport,omitempty"`
	RegisteredAt string   `json:"registered_at"`
}

// APIWebAuthnListResponse is the response from GET /api/v1/accounts/{username}/webauthn/credentials.
type APIWebAuthnListResponse struct {
	Username    string                      `json:"username"`
	Credentials []APIWebAuthnCredentialInfo `json:"credentials"`
}

// APIWebAuthnRegisterFinishResponse is the response from POST .../webauthn/register/finish.
type APIWebAuthnRegisterFinishResponse struct {
	CredentialID []byte `json:"credential_id"`
	Label        string `json:"label,omitempty"`
	RegisteredAt string `json:"registered_at"`
}

// WebAuthnListCredentials calls GET /api/v1/accounts/{username}/webauthn/credentials
// and returns the list of registered credentials for that account.
func (c *APIClient) WebAuthnListCredentials(ctx context.Context, username string) (*APIWebAuthnListResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/accounts/"+url.PathEscape(username)+"/webauthn/credentials", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIWebAuthnListResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode credential list: %w", err)
	}
	return &result, nil
}

// WebAuthnBeginRegistration calls POST /api/v1/accounts/{username}/webauthn/register/begin
// and returns the raw PublicKeyCredentialCreationOptions JSON (the data field from the
// APIResponse envelope). The caller passes this JSON to the browser's navigator.credentials.create().
func (c *APIClient) WebAuthnBeginRegistration(ctx context.Context, username string) (json.RawMessage, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/accounts/"+url.PathEscape(username)+"/webauthn/register/begin", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// WebAuthnFinishRegistration calls POST /api/v1/accounts/{username}/webauthn/register/finish
// with the authenticator response JSON from the browser's navigator.credentials.create() result.
// label is attached as a query parameter. Returns the registered credential metadata.
func (c *APIClient) WebAuthnFinishRegistration(ctx context.Context, username, label string, credResponseJSON []byte) (*APIWebAuthnRegisterFinishResponse, error) {
	path := "/api/v1/accounts/" + url.PathEscape(username) + "/webauthn/register/finish"
	if label != "" {
		path += "?label=" + url.QueryEscape(label)
	}

	resp, err := c.doRequest(ctx, "POST", path, bytes.NewReader(credResponseJSON))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result APIWebAuthnRegisterFinishResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode finish response: %w", err)
	}
	return &result, nil
}

// WebAuthnPresenceBegin calls POST /api/v1/webauthn/presence/begin to start a
// presence assertion ceremony. Returns the raw PublicKeyCredentialRequestOptions JSON
// (the data field from the APIResponse envelope). The caller passes this JSON to the
// browser's navigator.credentials.get() to produce an authenticator assertion.
func (c *APIClient) WebAuthnPresenceBegin(ctx context.Context) (json.RawMessage, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/webauthn/presence/begin", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode presence begin response: %w", err)
	}
	return envelope.Data, nil
}

// WebAuthnPresenceFinish calls POST /api/v1/webauthn/presence/finish with the
// authenticator assertion response JSON from the browser's navigator.credentials.get()
// result. Returns the single-use presence token to attach as X-Presence-Token on the
// guarded action request. The token is valid for presenceTokenTTL (30 s) server-side.
func (c *APIClient) WebAuthnPresenceFinish(ctx context.Context, assertionResponseJSON []byte) (string, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/webauthn/presence/finish", bytes.NewReader(assertionResponseJSON))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", c.parseError(resp)
	}

	var result struct {
		PresenceToken string `json:"presence_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode presence finish response: %w", err)
	}
	if result.PresenceToken == "" {
		return "", fmt.Errorf("server returned empty presence token")
	}
	return result.PresenceToken, nil
}

// --- Enrolment tokens and headless credential enrolment (Issue #3720) ---

// MintEnrolmentTokenResponse mirrors api.EnrolmentTokenResponse on the controller.
// Token carries the raw secret only in the mint response; every other path
// (including revoke) leaves it empty.
type MintEnrolmentTokenResponse struct {
	ID          string  `json:"id"`
	Token       string  `json:"token,omitempty"`
	TokenPrefix string  `json:"token_prefix"`
	TenantID    string  `json:"tenant_id"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   string  `json:"expires_at"`
	Revoked     bool    `json:"revoked"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
}

// MintEnrolmentToken calls POST /api/v1/enrolment-tokens. The caller must already be
// authenticated (admin mTLS bundle or a stepped-up session) — this method attaches no
// credential of its own, it only sends the request through whatever bearer/mTLS
// configuration c already carries.
func (c *APIClient) MintEnrolmentToken(ctx context.Context, tenantID string) (*MintEnrolmentTokenResponse, error) {
	body, err := json.Marshal(struct {
		TenantID string `json:"tenant_id"`
	}{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/enrolment-tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data MintEnrolmentTokenResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &envelope.Data, nil
}

// RevokeEnrolmentToken calls POST /api/v1/enrolment-tokens/{id}/revoke. The response
// never carries the raw token value — revocation does not re-disclose a secret that
// was already shown once at mint time.
func (c *APIClient) RevokeEnrolmentToken(ctx context.Context, id string) (*MintEnrolmentTokenResponse, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/enrolment-tokens/"+url.PathEscape(id)+"/revoke", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data MintEnrolmentTokenResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &envelope.Data, nil
}

// LodgeCredentialRequestBody mirrors api.LodgeCredentialRequestBody on the controller.
// CSRPEM is the only field that carries key material, and it carries only the public
// key: it is a PEM CERTIFICATE REQUEST self-signed by a private key that never appears
// in this struct, or anywhere else in a lodge request (Issue #3720 [REQUIRED TEST]).
// Hostname, Label, Platform and Purpose are display-only text.
type LodgeCredentialRequestBody struct {
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname,omitempty"`
	Label    string `json:"label,omitempty"`
	Platform string `json:"platform,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
}

// LodgeCredentialRequestResponse mirrors api.LodgeCredentialRequestResponse.
// CollectSecret is returned exactly once, by this call alone — no later call ever
// re-discloses it.
type LodgeCredentialRequestResponse struct {
	RequestID                 string `json:"request_id"`
	PublicKeyFingerprint      string `json:"public_key_fingerprint"`
	PublicKeyFingerprintShort string `json:"public_key_fingerprint_short"`
	CollectSecret             string `json:"collect_secret"`
	ExpiresAt                 string `json:"expires_at"`
}

// LodgeCredentialRequest calls POST /api/v1/credential-requests/lodge, authenticated
// by this client's bearer token — the enrolment token itself. Unlike every other
// method in this file the controller accepts no API key, mTLS certificate, or session
// on this call; the enrolment token is the only credential involved.
func (c *APIClient) LodgeCredentialRequest(ctx context.Context, body LodgeCredentialRequestBody) (*LodgeCredentialRequestResponse, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/credential-requests/lodge", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data LodgeCredentialRequestResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &envelope.Data, nil
}

// CollectCredentialRequestResponse mirrors api.CollectCredentialRequestResponse —
// the signed certificate, returned exactly once on a successful collection.
type CollectCredentialRequestResponse struct {
	CertificatePEM   string   `json:"certificate_pem"`
	CACertificatePEM string   `json:"ca_certificate_pem"`
	SerialNumber     string   `json:"serial_number"`
	AccountID        string   `json:"account_id"`
	GrantedMarkers   []string `json:"granted_markers"`
	ExpiresAt        string   `json:"expires_at"`
}

// CollectCredentialRequestResult is the outcome of one poll against the collect
// endpoint. Exactly one of Certificate, AlreadyGone, or a non-empty Status is
// meaningful: Status is one of "pending", "denied", "expired" (echoed from the
// controller), or the client-synthesized "retry" for a 503 (the controller is not the
// authoritative node for minting right now; the request itself is untouched).
type CollectCredentialRequestResult struct {
	Status      string
	Certificate *CollectCredentialRequestResponse
	AlreadyGone bool
}

// CollectCredentialRequest calls POST /api/v1/credential-requests/{id}/collect,
// authenticated by this client's bearer token — the collect secret returned once by
// LodgeCredentialRequest. It performs exactly one poll; the caller decides whether and
// how often to call it again. An unknown request ID and a wrong collect secret are
// indistinguishable on the wire (both 404) and are surfaced here as an error, since
// that condition can never resolve itself by polling again.
func (c *APIClient) CollectCredentialRequest(ctx context.Context, requestID string) (*CollectCredentialRequestResult, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/credential-requests/"+url.PathEscape(requestID)+"/collect", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusGone:
		return &CollectCredentialRequestResult{AlreadyGone: true}, nil
	case http.StatusServiceUnavailable:
		return &CollectCredentialRequestResult{Status: "retry"}, nil
	case http.StatusOK:
		var envelope struct {
			Data struct {
				Status           string   `json:"status,omitempty"`
				CertificatePEM   string   `json:"certificate_pem,omitempty"`
				CACertificatePEM string   `json:"ca_certificate_pem,omitempty"`
				SerialNumber     string   `json:"serial_number,omitempty"`
				AccountID        string   `json:"account_id,omitempty"`
				GrantedMarkers   []string `json:"granted_markers,omitempty"`
				ExpiresAt        string   `json:"expires_at,omitempty"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		if envelope.Data.Status != "" {
			return &CollectCredentialRequestResult{Status: envelope.Data.Status}, nil
		}
		return &CollectCredentialRequestResult{Certificate: &CollectCredentialRequestResponse{
			CertificatePEM:   envelope.Data.CertificatePEM,
			CACertificatePEM: envelope.Data.CACertificatePEM,
			SerialNumber:     envelope.Data.SerialNumber,
			AccountID:        envelope.Data.AccountID,
			GrantedMarkers:   envelope.Data.GrantedMarkers,
			ExpiresAt:        envelope.Data.ExpiresAt,
		}}, nil
	default:
		return nil, c.parseError(resp)
	}
}

// --- browser-authenticated CLI login (Issue #3721) ---

// LodgeCliLoginRequestBody is the POST /api/v1/cli-login/lodge body. VerifierHash is the
// SHA-256 hex digest of a verifier generated and retained locally — the raw value is
// never sent here.
type LodgeCliLoginRequestBody struct {
	VerifierHash string `json:"verifier_hash"`
}

// LodgeCliLoginResponse mirrors api.LodgeCliLoginResponse.
type LodgeCliLoginResponse struct {
	RequestID string `json:"request_id"`
	UserCode  string `json:"user_code"`
	ExpiresAt string `json:"expires_at"`
}

// LodgeCliLogin calls POST /api/v1/cli-login/lodge. Unauthenticated — this is the
// bootstrap path for an operator holding no prior credential.
func (c *APIClient) LodgeCliLogin(ctx context.Context, verifierHash string) (*LodgeCliLoginResponse, error) {
	reqBody, err := json.Marshal(LodgeCliLoginRequestBody{VerifierHash: verifierHash})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/cli-login/lodge", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data LodgeCliLoginResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &envelope.Data, nil
}

// CollectCliLoginResult is the outcome of one poll against the cli-login collect
// endpoint. Exactly one of Token (on success), AlreadyGone, or a non-empty Status is
// meaningful: Status is one of "pending", "denied", "expired" (echoed from the
// controller).
type CollectCliLoginResult struct {
	Status         string
	Token          string
	SessionID      string
	AbsoluteExpiry time.Time
	AlreadyGone    bool
}

// CollectCliLogin calls POST /api/v1/cli-login/{id}/collect, authenticated by this
// client's bearer token — the verifier generated at lodge time. It performs exactly one
// poll; the caller decides whether and how often to call it again. An unknown request ID
// and a wrong verifier are indistinguishable on the wire (both 404) and are surfaced here
// as an error, since that condition can never resolve itself by polling again.
func (c *APIClient) CollectCliLogin(ctx context.Context, requestID string) (*CollectCliLoginResult, error) {
	resp, err := c.doRequest(ctx, "POST", "/api/v1/cli-login/"+url.PathEscape(requestID)+"/collect", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusGone:
		return &CollectCliLoginResult{AlreadyGone: true}, nil
	case http.StatusOK:
		var envelope struct {
			Data struct {
				Status         string    `json:"status"`
				Token          string    `json:"token,omitempty"`
				SessionID      string    `json:"session_id,omitempty"`
				AbsoluteExpiry time.Time `json:"absolute_expiry,omitempty"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		return &CollectCliLoginResult{
			Status:         envelope.Data.Status,
			Token:          envelope.Data.Token,
			SessionID:      envelope.Data.SessionID,
			AbsoluteExpiry: envelope.Data.AbsoluteExpiry,
		}, nil
	default:
		return nil, c.parseError(resp)
	}
}

// apiErrorCode extracts the structured error code from a JSON error response body
// shaped {"error":{"code":"...","message":"..."}}, consuming resp.Body. Returns "" when
// the body does not carry that shape.
func apiErrorCode(resp *http.Response) string {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return ""
	}
	return envelope.Error.Code
}

// WebAuthnRevokeCredential calls POST /api/v1/accounts/{username}/webauthn/revoke/{credential_id}
// to remove the specified credential from the account. credential_id must be the base64url-encoded
// credential ID (as returned by WebAuthnListCredentials).
func (c *APIClient) WebAuthnRevokeCredential(ctx context.Context, username, credentialID string) error {
	path := "/api/v1/accounts/" + url.PathEscape(username) + "/webauthn/revoke/" + url.PathEscape(credentialID)
	resp, err := c.doRequest(ctx, "POST", path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}
	return nil
}
