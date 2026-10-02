// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"time"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// RegistrationRequest represents a registration request to the controller.
type RegistrationRequest struct {
	Token          string `json:"token"`
	DeviceID       string `json:"device_id,omitempty"`        // 64-char hex SHA-256 of Ed25519 public key (Issue #2094)
	IdentityKeyPub string `json:"identity_key_pub,omitempty"` // base64-encoded Ed25519 public key (Issue #2094)

	// CSRPEM is a PEM-encoded CERTIFICATE REQUEST over a keypair the steward
	// generates locally at registration time (Issue #3780). The controller signs
	// this public key into the steward's mTLS client certificate; the matching
	// private key never crosses the wire. Set by Register, not by callers.
	CSRPEM string `json:"csr_pem,omitempty"`

	// Best-effort identity hints seeded into initial DNA so the controller is not
	// blind to connected stewards before their first DNA sync (Issue #2640).
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
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
	CACert     string `json:"ca_cert,omitempty"`

	// ClientKeyPEM is never part of the wire response (Issue #3780: the controller
	// never generates or sees a private key for this credential). Register
	// populates it locally, after the response is decoded, by combining the
	// locally generated CSR keypair with the returned certificate.
	ClientKeyPEM string `json:"-"`

	// IssuerChain is the PEM-concatenated chain from ClientCert's direct issuer up
	// to (but not including) CACert (Issue #3778). Empty for a self-hosted,
	// root-only controller; populated when the controller's cert manager is backed
	// by an imported regional intermediate.
	IssuerChain string `json:"issuer_chain,omitempty"`

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
	CACert           string `json:"ca_cert,omitempty"`

	// ClientKeyPEM is never part of the wire response (Issue #3780). PollStatus
	// populates it locally, after the response is decoded, from the keypair the
	// original Register call generated for this pending registration's CSR.
	ClientKeyPEM string `json:"-"`

	IssuerChain string `json:"issuer_chain,omitempty"`
	ServerCert  string `json:"server_cert,omitempty"`
	SigningCert string `json:"signing_cert,omitempty"`
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

// enrollmentStatusClaimed is the registration status the controller reports once a
// pending registration has been approved and its certificate set issued.
const enrollmentStatusClaimed = "claimed"

// HTTPClient handles steward registration via REST API
type HTTPClient struct {
	controllerURL string
	httpClient    *http.Client
	logger        logging.Logger

	// fenceRatchet is the steward's persisted Raft-term fence state (Issue #3437).
	// It is non-nil only when HTTPConfig.CertStoreDir is set. A completed enrollment
	// that returns a verified fresh certificate set clears it; see
	// resetFenceRatchetOnEnrollment.
	fenceRatchet *stewardconfig.FenceRatchet

	// pendingClientKey is the private key generated by the most recent Register
	// call, held only in memory (Issue #3780). Register submits its public half as
	// a CSR; when the matching certificate arrives later via a claimed PollStatus
	// response, this key is what pairs with it. Never serialized, never sent.
	pendingClientKey *ecdsa.PrivateKey
}

// HTTPConfig holds configuration for HTTP registration
type HTTPConfig struct {
	ControllerURL string
	Timeout       time.Duration
	// CACertPath is the optional path to a PEM-encoded CA certificate used to verify
	// the controller's TLS certificate during registration. When empty, system root CAs are used
	// (unless CAPEM is set).
	CACertPath string
	// CAPEM is an inline PEM-encoded CA certificate. Takes precedence over CACertPath when set.
	// Used in install-pinned and TOFU modes to provide the pinned CA without requiring a disk read.
	CAPEM string
	// CertStoreDir is the steward's on-disk state root (the same directory the transport
	// client uses for the fence ratchet, features/steward/client/client_transport.go).
	// When set, a completed enrollment whose certificate set verifies clears the persisted
	// Raft-term fence ratchet stored there (Issue #3437). When empty, the client performs
	// no ratchet reset at all — callers that do not own the steward's durable state, such
	// as the certificate-refresh path, leave it unset deliberately.
	CertStoreDir string
	Logger       logging.Logger
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

	// Resolve CA PEM: inline CAPEM takes precedence over CACertPath.
	var caPEM []byte
	if cfg.CAPEM != "" {
		caPEM = []byte(cfg.CAPEM)
	} else if cfg.CACertPath != "" {
		var err error
		caPEM, err = os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %q: %w", cfg.CACertPath, err)
		}
	}

	transport := &http.Transport{}
	if len(caPEM) > 0 {
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

	client := &HTTPClient{
		controllerURL: cfg.ControllerURL,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		logger: cfg.Logger,
	}
	if cfg.CertStoreDir != "" {
		client.fenceRatchet = stewardconfig.NewFenceRatchet(cfg.CertStoreDir)
	}

	return client, nil
}

// Register registers the steward with the controller using a registration token.
//
// Returns (*RegistrationResponse, nil, nil) on HTTP 200 (approved).
// Returns (nil, *RegistrationPendingResponse, nil) on HTTP 202 (quarantined, pending approval).
// Returns (nil, nil, error) on any other status or transport failure.
// Callers must distinguish the pending case and enter a poll loop (story 7).
func (c *HTTPClient) Register(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, *RegistrationPendingResponse, error) {
	registrationURL := fmt.Sprintf("%s/api/v1/register", c.controllerURL)

	// Generate the steward's mTLS keypair locally and submit only the public half
	// as a CSR (Issue #3780). priv is held on the client (not sent) so a later
	// claimed PollStatus response for this same pending registration can be
	// paired with it.
	priv, err := GenerateStewardKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate steward keypair: %w", err)
	}
	csrPEM, err := BuildRegistrationCSR(priv, req.DeviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build registration certificate signing request: %w", err)
	}
	req.CSRPEM = csrPEM
	c.pendingClientKey = priv

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
		// Combine the controller-issued certificate with the locally held private
		// key before handing the pair to the caller. No client_key field exists on
		// the wire response to read (Issue #3780).
		keyPEM, keyErr := EncodeECDSAPrivateKeyPEM(priv)
		if keyErr != nil {
			return nil, nil, fmt.Errorf("failed to encode steward private key: %w", keyErr)
		}
		regResp.ClientKeyPEM = keyPEM
		c.logger.Info("Registration successful",
			"steward_id", regResp.StewardID,
			"tenant_id", regResp.TenantID,
			"group", regResp.Group)
		// Enrollment completed with a fresh certificate set: clear the persisted
		// Raft-term fence so a rebuilt controller cluster (terms restart at 1) is not
		// permanently rejected (Issue #3437).
		c.resetFenceRatchetForEnrollment(regResp.enrollmentCertSet())
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
		// Already claimed elsewhere: no certificate set is issued to this caller, so
		// this is not an enrollment completion and never resets the fence ratchet.
		return &RegistrationStatusResponse{Status: enrollmentStatusClaimed}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status poll failed with HTTP %d: %s", resp.StatusCode, string(body))
	}

	var statusResp RegistrationStatusResponse
	if err := json.Unmarshal(body, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}
	if statusResp.Status == enrollmentStatusClaimed {
		// Pair the controller-signed certificate with the private key generated by
		// this client's original Register call for this pending registration's CSR
		// (Issue #3780). c.pendingClientKey is nil when this client instance never
		// called Register — e.g. a steward resuming a pending registration across a
		// restart, which cannot recover a key that only ever lived in the previous
		// process's memory.
		if c.pendingClientKey != nil {
			keyPEM, keyErr := EncodeECDSAPrivateKeyPEM(c.pendingClientKey)
			if keyErr != nil {
				return nil, fmt.Errorf("failed to encode steward private key: %w", keyErr)
			}
			statusResp.ClientKeyPEM = keyPEM
		} else if statusResp.ClientCert != "" {
			// A real claim (cert fields populated) reached this process instance with
			// no matching key: either the pending record was never resumed via
			// ResumePendingClientKey, or the persisted key was lost. Loud, not silent —
			// the caller must not treat this as a usable enrollment (Issue #3780 follow-up).
			c.logger.Warn("Claimed registration has no matching in-memory steward private key; the issued certificate cannot be paired with a usable identity on this process instance",
				"pending_id", logging.SanitizeLogValue(pendingID),
				"steward_id", logging.SanitizeLogValue(statusResp.StewardID))
		}
		// Approved registration carrying the issued certificate set: same enrollment
		// completion as Register's HTTP 200 branch, reached via operator approval.
		c.resetFenceRatchetForEnrollment(statusResp.enrollmentCertSet())
	}
	return &statusResp, nil
}

// PendingClientKeyPEM returns the PKCS8 PEM encoding of the private key this
// client generated for its most recent Register call. A caller that persists
// pending-registration state across restarts (e.g. cmd/steward's PendingState)
// uses this to save the key alongside the pending ID, so a later process
// instance can resume polling without losing the ability to pair an eventually
// claimed certificate with the key that was actually submitted in the CSR
// (Issue #3780 follow-up: without this, a restart during the quarantine poll
// window orphans the steward — see ResumePendingClientKey).
// Returns an error if Register has not been called on this client instance.
func (c *HTTPClient) PendingClientKeyPEM() (string, error) {
	if c.pendingClientKey == nil {
		return "", fmt.Errorf("no pending client key: Register has not been called on this client instance")
	}
	return EncodeECDSAPrivateKeyPEM(c.pendingClientKey)
}

// ResumePendingClientKey restores a private key generated by an earlier process
// instance's Register call (via PendingClientKeyPEM), so this client's
// PollStatus can pair a later claimed certificate with it exactly as if this
// instance had generated the key itself (Issue #3780 follow-up).
func (c *HTTPClient) ResumePendingClientKey(keyPEM string) error {
	priv, err := decodeECDSAPrivateKeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("failed to decode persisted steward private key: %w", err)
	}
	c.pendingClientKey = priv
	return nil
}

// GenerateStewardKeypair generates a fresh ECDSA P-256 keypair for a steward
// registration or registration-refresh CSR. Mirrors cmd/cfg/cmd/credential_enroll.go's
// generateECDSAP256Keypair — the steward package cannot import cmd/cfg/cmd, so
// this is a parallel implementation of the same pattern. Exported so cmd/steward
// can generate the fresh keypair a refresh renews the credential with (Issue #3781)
// without duplicating the implementation. The private key this returns never
// leaves the process that called it.
func GenerateStewardKeypair() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	return priv, nil
}

// BuildRegistrationCSR generates a self-signed PEM CERTIFICATE REQUEST over priv's
// public key. Mirrors cmd/cfg/cmd/credential_enroll.go's buildEnrolCSR exactly —
// the controller's registration handler verifies this request's own signature
// (features/controller/api/handlers_credential_requests.go parseAndVerifyCSR)
// before ever seeing priv's public key. priv never appears in the result. Exported
// so cmd/steward can build the CSR for a registration-refresh renewal (Issue #3781).
func BuildRegistrationCSR(priv *ecdsa.PrivateKey, commonName string) (string, error) {
	if commonName == "" {
		commonName = "cfgms-steward"
	}
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(cryptorand.Reader, template, priv)
	if err != nil {
		return "", fmt.Errorf("failed to create registration certificate signing request: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// EncodeECDSAPrivateKeyPEM PKCS8-encodes priv for local combination with the
// controller-issued certificate. priv is never marshaled anywhere but into this
// in-memory PEM value, which the caller pairs with a certificate and never
// transmits. Exported so cmd/steward can encode the fresh key it generates for a
// registration-refresh renewal (Issue #3781).
func EncodeECDSAPrivateKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal steward private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// decodeECDSAPrivateKeyPEM is the inverse of EncodeECDSAPrivateKeyPEM, used by
// ResumePendingClientKey to restore a persisted pending-registration key.
func decodeECDSAPrivateKeyPEM(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in steward private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 steward private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("steward private key is not an ECDSA key")
	}
	return ecKey, nil
}

// computePollInterval returns base + a random duration in [0, jitter).
// Returns base unchanged when jitter is 0 (test/immediate-poll mode).
func computePollInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	// #nosec G115,G404 -- jitter is a positive int64 duration, so the uint64
	// conversion is lossless; math/rand is intentionally used for non-security
	// poll scheduling and never influences authentication or authorization.
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

// RefreshComplete submits the proof-of-possession signature and a CSR over a fresh
// keypair to complete the registration-refresh handshake (Issue #3781).
// pop is the Ed25519 signature over sha256(nonce_bytes || device_id_utf8 || server_ts_big_endian_uint64).
// issuedAt must be the server_ts value from the challenge response (Unix nanoseconds), used by the
// controller's IssuedAt gate to verify the request arrived within the 60s nonce window.
// csrPEM is a PEM-encoded CERTIFICATE REQUEST over a keypair the caller generates locally
// for the renewed credential (see GenerateStewardKeypair / BuildRegistrationCSR) — the
// controller signs this public key; the matching private key never crosses the wire.
//
// Returns (*RefreshCompleteResponse, nil) on HTTP 200 (cert issued immediately).
// Returns (nil, ErrRefreshPending) on HTTP 202 (request queued for manual approval).
// Returns (nil, ErrRefreshRejected) on HTTP 403 (device revoked or dormant).
func (c *HTTPClient) RefreshComplete(ctx context.Context, deviceID, tenantID, nonce string, issuedAt int64, pop []byte, csrPEM string) (*RefreshCompleteResponse, error) {
	completeURL := fmt.Sprintf("%s/api/v1/stewards/%s/refresh/complete", c.controllerURL, deviceID)

	reqBody, err := json.Marshal(struct {
		TenantID  string `json:"tenant_id,omitempty"`
		Nonce     string `json:"nonce"`
		IssuedAt  int64  `json:"issued_at"` // server_ts from challenge (Unix nanoseconds)
		Signature string `json:"signature"` // base64url Ed25519 sig over PoP digest
		CSRPEM    string `json:"csr_pem"`
	}{
		TenantID:  tenantID,
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		Signature: base64.RawURLEncoding.EncodeToString(pop),
		CSRPEM:    csrPEM,
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

// enrollmentCertSet is the certificate material a completed enrollment exchange
// returns. It is the evidence the fence-ratchet reset verifies before it touches
// the steward's persisted fence state.
type enrollmentCertSet struct {
	stewardID   string
	clientCert  string
	clientKey   string
	caCert      string
	issuerChain string
}

// complete reports whether the response carried a full certificate set. Responses
// that carry none (a 202 pending registration, a 410 already-claimed poll) are not
// enrollment completions and never trigger the reset. issuerChain is additive
// (Issue #3778) and never required: a self-hosted, root-only controller carries
// none, and that is not a partial set.
func (s enrollmentCertSet) complete() bool {
	return s.clientCert != "" && s.clientKey != "" && s.caCert != ""
}

// enrollmentCertSet extracts the certificate material from an approved
// registration. clientKey is sourced from the locally generated CSR keypair
// (ClientKeyPEM), never from the wire response — no client_key field exists on
// the wire to read (Issue #3780).
func (r *RegistrationResponse) enrollmentCertSet() enrollmentCertSet {
	return enrollmentCertSet{
		stewardID:   r.StewardID,
		clientCert:  r.ClientCert,
		clientKey:   r.ClientKeyPEM,
		caCert:      r.CACert,
		issuerChain: r.IssuerChain,
	}
}

// enrollmentCertSet extracts the certificate material from a claimed status
// poll. clientKey is sourced from the locally generated CSR keypair
// (ClientKeyPEM), never from the wire response (Issue #3780).
func (r *RegistrationStatusResponse) enrollmentCertSet() enrollmentCertSet {
	return enrollmentCertSet{
		stewardID:   r.StewardID,
		clientCert:  r.ClientCert,
		clientKey:   r.ClientKeyPEM,
		caCert:      r.CACert,
		issuerChain: r.IssuerChain,
	}
}

// verifyEnrollmentCertSet checks that the certificate material really is a freshly
// issued steward identity from the CA the same exchange presented, rather than any
// well-formed JSON body that happens to reach the client. It proves three things:
//
//  1. The client certificate and private key are a usable pair (the steward can
//     actually authenticate with what it was handed).
//  2. The leaf chains to the CA certificate delivered alongside it — by way of any
//     delivered issuerChain, when the issuing CA is an intermediate (Issue #3778)
//     — is currently within its validity window, and carries the client-auth EKU.
//  3. Nothing is missing — a partial set fails rather than half-verifying.
//
// It deliberately does not attempt to prove the CA is a *different* cluster's CA:
// the registration response carries no cluster identity, and inventing one here
// would be a controller-side protocol change (out of scope for #3437).
func verifyEnrollmentCertSet(set enrollmentCertSet) error {
	if !set.complete() {
		return fmt.Errorf("enrollment response carries no complete certificate set")
	}

	if _, err := cert.LoadTLSCertificate([]byte(set.clientCert), []byte(set.clientKey)); err != nil {
		return fmt.Errorf("enrollment client certificate and key are not a usable pair: %w", err)
	}

	leaf, err := cert.ParseCertificateFromPEM([]byte(set.clientCert))
	if err != nil {
		return fmt.Errorf("parse enrollment client certificate: %w", err)
	}

	roots, err := cert.CertPoolFromPEM([]byte(set.caCert))
	if err != nil {
		return fmt.Errorf("build verification pool from enrollment CA certificate: %w", err)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if set.issuerChain != "" {
		intermediates, err := cert.CertPoolFromPEM([]byte(set.issuerChain))
		if err != nil {
			return fmt.Errorf("build intermediate pool from enrollment issuer chain: %w", err)
		}
		verifyOpts.Intermediates = intermediates
	}

	if _, err := leaf.Verify(verifyOpts); err != nil {
		return fmt.Errorf("enrollment client certificate does not chain to the enrollment CA: %w", err)
	}

	return nil
}

// resetFenceRatchetOnEnrollment clears the persisted Raft-term fence ratchet after a
// steward enrollment into a controller cluster completes, so a legitimate cluster
// rebuild (which restarts Raft terms at 1) does not permanently lock the steward out.
//
// The reset is conditional, not a proxy for ClearRatchet: it runs only after
// verifyEnrollmentCertSet accepts the certificate set the enrollment exchange
// returned. A response that carries no certificate set, a mismatched key pair, or a
// leaf that does not chain to the delivered CA leaves the persisted fence untouched
// and returns an error.
//
// The function is unexported on purpose. Its two call sites are the enrollment
// completions in this file — Register's HTTP 200 branch and PollStatus's claimed
// branch — and the Go compiler, not a convention, is what keeps every other package
// (features/steward/client, the command-receive path, above all) from calling it. The
// AST-walk test in architecture_test.go covers the underlying ClearRatchet method and
// this function's name for both packages and any future re-export.
//
// Safety contingency: what this verification establishes is that the certificate set
// came from whichever CA the enrollment exchange presented, over a TLS connection the
// steward verified against its configured/pinned CA — not that the endpoint is the
// legitimate controller when no CA is pinned. Closing that gap is a forthcoming story
// (tracked as a private draft under the parent epic). Until it lands, the reset is
// safe against routine restarts and legitimate cluster rebuilds but not against a
// network adversary who can both spoof the registration endpoint and be trusted by
// the steward's configured trust store. See
// docs/architecture/steward-operating-model.md §Fencing-Token Command Fence.
func resetFenceRatchetOnEnrollment(r *stewardconfig.FenceRatchet, set enrollmentCertSet) error {
	if err := verifyEnrollmentCertSet(set); err != nil {
		return fmt.Errorf("fence ratchet retained: %w", err)
	}
	if r == nil {
		// No durable ratchet configured (CertStoreDir unset): nothing to clear.
		return nil
	}
	return r.ClearRatchet()
}

// resetFenceRatchetForEnrollment is the wiring between an enrollment completion and
// the reset. It is a no-op when the client owns no durable ratchet or when the
// response carried no certificate set, and it never fails the enrollment: a
// verification failure leaves the fence in place (fail-closed) and is logged.
func (c *HTTPClient) resetFenceRatchetForEnrollment(set enrollmentCertSet) {
	if c.fenceRatchet == nil || !set.complete() {
		return
	}

	if err := resetFenceRatchetOnEnrollment(c.fenceRatchet, set); err != nil {
		c.logger.Warn("Raft-term fence ratchet not reset: enrollment certificate set failed verification",
			"steward_id", logging.SanitizeLogValue(set.stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}

	c.logger.Info("Raft-term fence ratchet cleared after verified enrollment",
		"steward_id", logging.SanitizeLogValue(set.stewardID))
}
