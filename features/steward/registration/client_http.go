// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// RegistrationRequest represents a registration request to the controller.
type RegistrationRequest struct {
	Token          string `json:"token"`
	DeviceID       string `json:"device_id,omitempty"`        // 64-char hex SHA-256 of Ed25519 public key (Issue #2094)
	IdentityKeyPub string `json:"identity_key_pub,omitempty"` // base64-encoded Ed25519 public key (Issue #2094)
}

// RegistrationResponse represents the response from the controller for an approved registration.
type RegistrationResponse struct {
	Success       bool   `json:"success"`
	StewardID     string `json:"steward_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	ControllerURL string `json:"controller_url,omitempty"`
	Group         string `json:"group,omitempty"`
	Error         string `json:"error,omitempty"`

	// Unified transport address for gRPC-over-QUIC connection (Issue #513)
	TransportAddress string `json:"transport_address,omitempty"`

	// Certificate fields
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
	CACert     string `json:"ca_cert,omitempty"`

	// Controller's server certificate for configuration signature verification (Story #315)
	// Used by steward to verify configurations signed by this controller
	// In HA clusters, stewards collect and trust certs from all controllers
	ServerCert string `json:"server_cert,omitempty"`

	// Story #377: Dedicated config signing certificate (separated architecture)
	// When present, steward should prefer this for config signature verification
	SigningCert string `json:"signing_cert,omitempty"`
}

// RegistrationStatusResponse is the response from GET /api/v1/registration/status/{pending_id}.
// When status is "claimed", all cert fields are populated; other statuses include only Status.
type RegistrationStatusResponse struct {
	Status string `json:"status"`

	StewardID        string `json:"steward_id,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	Group            string `json:"group,omitempty"`
	ControllerURL    string `json:"controller_url,omitempty"`
	TransportAddress string `json:"transport_address,omitempty"`
	ClientCert       string `json:"client_cert,omitempty"`
	ClientKey        string `json:"client_key,omitempty"`
	CACert           string `json:"ca_cert,omitempty"`
	ServerCert       string `json:"server_cert,omitempty"`
	SigningCert      string `json:"signing_cert,omitempty"`
}

// RegistrationPendingResponse is returned by the controller with HTTP 202 when a registration
// is quarantined pending operator approval. It contains no certificate fields (Issue #1693).
// Callers must check whether Register returned a pending response and enter a poll loop (story 7).
type RegistrationPendingResponse struct {
	PendingID string `json:"pending_id"`
	StewardID string `json:"steward_id"`
	TenantID  string `json:"tenant_id"`
	Group     string `json:"group"`
	Status    string `json:"status"`
}

// HTTPClient handles steward registration via REST API
type HTTPClient struct {
	controllerURL string
	httpClient    *http.Client
	logger        logging.Logger
}

// HTTPConfig holds configuration for HTTP registration
type HTTPConfig struct {
	ControllerURL string
	Timeout       time.Duration
	// CACertPath is the optional path to a PEM-encoded CA certificate used to verify
	// the controller's TLS certificate during registration. When empty, system root CAs are used.
	CACertPath string
	Logger     logging.Logger
}

// NewHTTPClient creates a new HTTP-based registration client
func NewHTTPClient(cfg *HTTPConfig) (*HTTPClient, error) {
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller URL is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{}
	if cfg.CACertPath != "" {
		caPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %q: %w", cfg.CACertPath, err)
		}

		parsed, err := url.Parse(cfg.ControllerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse controller URL: %w", err)
		}

		tlsCfg, err := cert.CreateClientTLSConfig(nil, nil, caPEM, parsed.Hostname(), tls.VersionTLS12)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config from CA cert: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	return &HTTPClient{
		controllerURL: cfg.ControllerURL,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		logger: cfg.Logger,
	}, nil
}

// Register registers the steward with the controller using a registration token.
//
// Returns (*RegistrationResponse, nil, nil) on HTTP 200 (approved).
// Returns (nil, *RegistrationPendingResponse, nil) on HTTP 202 (quarantined, pending approval).
// Returns (nil, nil, error) on any other status or transport failure.
// Callers must distinguish the pending case and enter a poll loop (story 7).
func (c *HTTPClient) Register(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, *RegistrationPendingResponse, error) {
	registrationURL := fmt.Sprintf("%s/api/v1/register", c.controllerURL)

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	c.logger.Info("Sending registration request to controller", "url", registrationURL)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var regResp RegistrationResponse
		if err := json.Unmarshal(body, &regResp); err != nil {
			return nil, nil, fmt.Errorf("failed to parse registration response: %w", err)
		}
		c.logger.Info("Registration successful",
			"steward_id", regResp.StewardID,
			"tenant_id", regResp.TenantID,
			"group", regResp.Group)
		return &regResp, nil, nil

	case http.StatusAccepted:
		var pending RegistrationPendingResponse
		if err := json.Unmarshal(body, &pending); err != nil {
			return nil, nil, fmt.Errorf("failed to parse pending registration response: %w", err)
		}
		c.logger.Info("Registration pending operator approval",
			"pending_id", pending.PendingID,
			"steward_id", pending.StewardID,
			"tenant_id", pending.TenantID)
		return nil, &pending, nil

	default:
		return nil, nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}
}

// PollStatus polls GET /api/v1/registration/status/{pendingID} once, authenticating with regToken.
// Before the HTTP call it sleeps for computePollInterval(baseInterval, jitter); pass both as 0 to
// skip the sleep (useful in tests). On HTTP 410 Gone the entry was already claimed; returns
// &RegistrationStatusResponse{Status:"claimed"} so callers can stop polling.
func (c *HTTPClient) PollStatus(ctx context.Context, pendingID, regToken string, baseInterval, jitter time.Duration) (*RegistrationStatusResponse, error) {
	if interval := computePollInterval(baseInterval, jitter); interval > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	pollURL := fmt.Sprintf("%s/api/v1/registration/status/%s", c.controllerURL, pendingID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+regToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to poll registration status: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("Failed to close status response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read status response body: %w", err)
	}

	if resp.StatusCode == http.StatusGone {
		return &RegistrationStatusResponse{Status: "claimed"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status poll failed with HTTP %d: %s", resp.StatusCode, string(body))
	}

	var statusResp RegistrationStatusResponse
	if err := json.Unmarshal(body, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}
	return &statusResp, nil
}

// computePollInterval returns base + a random duration in [0, jitter).
// Returns base unchanged when jitter is 0 (test/immediate-poll mode).
func computePollInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	return base + time.Duration(rand.N(uint64(jitter)))
}

// RefreshChallenge requests a nonce from the controller for the registration-refresh handshake.
// Returns ErrRefreshRejected when the controller returns HTTP 403 (revoked or dormant device).
// Returns the challenge response on HTTP 200.
func (c *HTTPClient) RefreshChallenge(ctx context.Context, deviceID string) (*RefreshChallengeResponse, error) {
	challengeURL := fmt.Sprintf("%s/api/v1/stewards/%s/refresh/challenge", c.controllerURL, deviceID)

	reqBody, err := json.Marshal(struct {
		DeviceID string `json:"device_id"`
	}{DeviceID: deviceID})
	if err != nil {
		return nil, fmt.Errorf("marshal refresh challenge request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, challengeURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create refresh challenge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send refresh challenge request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("Failed to close refresh challenge response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh challenge response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var cr RefreshChallengeResponse
		if err := json.Unmarshal(body, &cr); err != nil {
			return nil, fmt.Errorf("parse refresh challenge response: %w", err)
		}
		return &cr, nil
	case http.StatusForbidden:
		return nil, ErrRefreshRejected
	default:
		return nil, fmt.Errorf("refresh challenge failed with HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// RefreshComplete submits the proof-of-possession signature to complete the registration-refresh handshake.
// pop is the Ed25519 signature over sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64).
// issuedAt must be the server_ts value from the challenge response (Unix nanoseconds), used by the
// controller's IssuedAt gate to verify the request arrived within the 60s nonce window.
//
// Returns (*RefreshCompleteResponse, nil) on HTTP 200 (cert issued immediately).
// Returns (nil, ErrRefreshPending) on HTTP 202 (request queued for manual approval).
// Returns (nil, ErrRefreshRejected) on HTTP 403 (device revoked or dormant).
func (c *HTTPClient) RefreshComplete(ctx context.Context, deviceID, tenantID, nonce string, issuedAt int64, pop []byte) (*RefreshCompleteResponse, error) {
	completeURL := fmt.Sprintf("%s/api/v1/stewards/%s/refresh/complete", c.controllerURL, deviceID)

	reqBody, err := json.Marshal(struct {
		TenantID  string `json:"tenant_id,omitempty"`
		Nonce     string `json:"nonce"`
		IssuedAt  int64  `json:"issued_at"` // server_ts from challenge (Unix nanoseconds)
		Signature string `json:"signature"` // base64url Ed25519 sig over PoP digest
	}{
		TenantID:  tenantID,
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		Signature: base64.RawURLEncoding.EncodeToString(pop),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal refresh complete request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, completeURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create refresh complete request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send refresh complete request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("Failed to close refresh complete response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh complete response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var cr RefreshCompleteResponse
		if err := json.Unmarshal(body, &cr); err != nil {
			return nil, fmt.Errorf("parse refresh complete response: %w", err)
		}
		return &cr, nil
	case http.StatusAccepted:
		return nil, ErrRefreshPending
	case http.StatusForbidden:
		return nil, ErrRefreshRejected
	default:
		return nil, fmt.Errorf("refresh complete failed with HTTP %d: %s", resp.StatusCode, string(body))
	}
}
