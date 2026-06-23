// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
)

// APIClient provides HTTP client functionality for communicating with the controller API
type APIClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// APIClientConfig contains configuration for creating an API client
type APIClientConfig struct {
	BaseURL       string
	APIKey        string
	CACertPEM     []byte // CA certificate for server verification (nil to skip verification)
	ClientCertPEM []byte // Client certificate for mTLS authentication
	ClientKeyPEM  []byte // Client private key for mTLS authentication
	TLSInsecure   bool   // Skip TLS verification (development only)
	ServerName    string // Server name for TLS verification (extracted from URL if empty)
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
		// Development mode: skip verification (requires explicit opt-in).
		// pkg/cert has no insecure helper; build config via field assignment.
		// #nosec G402 - InsecureSkipVerify explicitly requested via --tls-insecure flag
		var insecureCfg tls.Config
		insecureCfg.MinVersion = tls.VersionTLS12
		insecureCfg.InsecureSkipVerify = true // #nosec G402
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
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
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

	req, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	// NewRequestWithContext re-parses the URL string and may normalise %2F.
	// Restore our pre-encoded RawPath so the HTTP client sends the correct wire path.
	req.URL.RawPath = base.RawPath

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	return c.httpClient.Do(req)
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
