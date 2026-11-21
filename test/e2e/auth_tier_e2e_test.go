// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// TestAuthTierE2E_Tier3Enforcement verifies the full Tier-3 auth enforcement path
// against a real controller using real TLS+mTLS credentials. No mocks, no context
// injection — the test exercises authenticationMiddleware → extractAdminPrincipal →
// requireTier(TierMTLSOnly) end-to-end.
//
// Sub-test Tier3_APIKeyHolder_Gets403:
//
//	An API-key principal carrying api-key:create is rejected with HTTP 403
//	INSUFFICIENT_PERMISSIONS on POST /api/v1/api-keys — the assurance floor (ADR-021
//	Decision 2) fires before the permission gate, so even a key with the exact matching
//	permission is blocked. An API key can never step up, so it gets a plain 403.
//
// Sub-test Tier3_AdminCertHolder_PassesTierCheck:
//
//	An mTLS admin-cert principal passes the assurance floor and receives any response
//	other than 403, proving the gate does not block admin principals. Creating the key
//	itself needs a per-action presence tap (ADR-021 Amendment 13), which the test
//	answers through the CLI presence relay with a passkey seeded on the bound account.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgapi "github.com/cfgis/cfgms/features/controller/api"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/features/controller/server"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtestutil "github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

// tier3ErrorResp mirrors the JSON error envelope returned by writeErrorResponse.
type tier3ErrorResp struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// tier3KeyCreateResp mirrors the JSON data envelope from handleCreateAPIKey.
type tier3KeyCreateResp struct {
	Data struct {
		Key string `json:"key"`
	} `json:"data"`
}

// seedPasskeyOperator writes an account bound to cert and holding one ordinary
// (zero-AAGUID) WebAuthn credential into the controller's account store.
func seedPasskeyOperator(t *testing.T, cfg *controllerConfig.Config, username string, cert *x509.Certificate, pub, credID []byte) {
	t.Helper()
	ctx := context.Background()
	store, err := cfgapi.NewSecretStore(cfg)
	require.NoError(t, err, "open account store")
	defer func() { require.NoError(t, store.Close()) }()

	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	require.NoError(t, initialization.BindAdminCertificate(ctx, store, username, cert.SerialNumber.String(), fingerprint))

	recs, err := store.ListSecrets(ctx, &secretsinterfaces.SecretFilter{
		Tags: []string{"account"},
		Metadata: map[string]string{
			secretsinterfaces.MetadataKeySecretType: "account",
			"username":                              username,
		},
	})
	require.NoError(t, err)
	require.Len(t, recs, 1, "the bound account must exist")
	rec := recs[0]

	creds, err := json.Marshal([]cfgapi.WebAuthnCredential{{
		ID: credID, PublicKey: pub, Label: "seeded operator passkey",
		RegisteredAt: time.Now().UTC(), AAGUID: make([]byte, 16),
	}})
	require.NoError(t, err)
	meta := map[string]string{}
	for k, v := range rec.Metadata {
		meta[k] = v
	}
	meta["credentials"] = string(creds)
	require.NoError(t, store.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		Key: rec.Key, Value: "", TenantID: rec.TenantID, CreatedBy: rec.CreatedBy,
		Description: rec.Description, Tags: rec.Tags, Metadata: meta,
	}))
}

// mintPresenceToken runs the CLI presence relay for the account behind client: lodge the
// request, answer the challenge with a real WebAuthn assertion, collect the token. The
// token is bound to the exact method, path, body and permission.
func mintPresenceToken(ctx context.Context, t *testing.T, client *http.Client, base string,
	key *ecdsa.PrivateKey, credID []byte, method, path string, body []byte, permission string) string {
	t.Helper()

	post := func(target string, payload []byte, wantStatus int) []byte {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+target, rd)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		b, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, wantStatus, resp.StatusCode, "POST %s: %s", target, string(b))
		return b
	}
	unwrap := func(raw []byte, v interface{}) {
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(raw, &env))
		require.NoError(t, json.Unmarshal(env.Data, v), "decode %s", string(raw))
	}

	sum := sha256.Sum256(body)
	lodgeBody, err := json.Marshal(map[string]string{
		"method": method, "path": path, "body_sha256": hex.EncodeToString(sum[:]), "permission": permission,
	})
	require.NoError(t, err)
	var lodged struct {
		RequestID string `json:"request_id"`
	}
	unwrap(post("/api/v1/cli-presence/lodge", lodgeBody, http.StatusCreated), &lodged)

	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	unwrap(post("/api/v1/webauthn/presence/begin?cli_presence_request_id="+lodged.RequestID, nil, http.StatusOK), &opts)

	assertion := webauthntest.Assert(t, key, credID, "localhost", base, opts.PublicKey.Challenge,
		webauthntest.WithSignCount(1)).Body()
	post("/api/v1/webauthn/presence/finish?cli_presence_request_id="+lodged.RequestID, assertion, http.StatusOK)

	var collected struct {
		Status        string `json:"status"`
		PresenceToken string `json:"presence_token"`
	}
	unwrap(post("/api/v1/cli-presence/"+lodged.RequestID+"/collect", nil, http.StatusOK), &collected)
	require.Equal(t, "collected", collected.Status)
	require.NotEmpty(t, collected.PresenceToken)
	return collected.PresenceToken
}

func TestAuthTierE2E_Tier3Enforcement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	tempDir := t.TempDir()
	logger := logging.NewNoopLogger()

	// ── 1. Certificate manager — creates CA at tempDir/certs. ──────────────────
	certPath := filepath.Join(tempDir, "certs")
	require.NoError(t, os.MkdirAll(certPath, 0755))

	certMgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certPath,
		CAConfig: &cert.CAConfig{
			Organization:       "CFGMS Auth-Tier E2E Test CA",
			Country:            "US",
			State:              "Test",
			City:               "Test",
			OrganizationalUnit: "Auth-Tier E2E",
			ValidityDays:       1,
			KeySize:            2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 1,
	})
	require.NoError(t, err, "cert manager init")

	// ── 2. Boot a real controller with TLS+mTLS enabled. ───────────────────────
	httpPort := findFreePort(t)
	transportPort := findFreePort(t)

	metricsAddr, err := pkgtestutil.ReserveLoopbackAddress()
	require.NoError(t, err, "reserve metrics listener address")

	cfg := &controllerConfig.Config{
		ListenAddr:        fmt.Sprintf("localhost:%d", httpPort),
		ExternalURL:       fmt.Sprintf("https://localhost:%d", httpPort),
		MetricsListenAddr: metricsAddr,
		CertPath:          certPath,
		DataDir:           filepath.Join(tempDir, "data"),
		LogLevel:          "error",
		Storage: &controllerConfig.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(tempDir, "storage"),
			SQLitePath:   filepath.Join(tempDir, "cfgms.db"),
		},
		Certificate: &controllerConfig.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 filepath.Join(certPath, "ca"),
			RenewalThresholdDays:   1,
			ServerCertValidityDays: 1,
			ClientCertValidityDays: 1,
			Server: &controllerConfig.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Test Organization",
			},
		},
		Transport: &controllerConfig.TransportConfig{
			ListenAddr:      fmt.Sprintf("localhost:%d", transportPort),
			UseCertManager:  true,
			MaxConnections:  10,
			KeepalivePeriod: controllerConfig.Duration(30 * time.Second),
			IdleTimeout:     controllerConfig.Duration(5 * time.Minute),
		},
		Registration: &controllerConfig.RegistrationConfig{
			Workflow: "auto-approve",
		},
	}

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "storage"), 0755))

	ctrl, err := server.New(cfg, logger)
	require.NoError(t, err, "server.New")

	ctrlErrCh := make(chan error, 1)
	go func() {
		ctrlErrCh <- ctrl.Start()
	}()

	httpBase := fmt.Sprintf("https://localhost:%d", httpPort)
	waitForControllerHTTP(t, certMgr, httpBase, 30*time.Second)

	t.Cleanup(func() {
		if err := ctrl.Stop(); err != nil && err.Error() != "controller not running" {
			t.Logf("controller Stop returned: %v", err)
		}
		select {
		case err := <-ctrlErrCh:
			if err != nil && err.Error() != "controller not running" {
				t.Logf("controller Start returned: %v", err)
			}
		default:
		}
	})

	// ── 3. Build CA pool and admin mTLS client cert. ───────────────────────────
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "CA pool append")

	adminCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "e2e-auth-tier-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err, "issue admin cert")

	adminTLSCert, err := tls.X509KeyPair(adminCert.CertificatePEM, adminCert.PrivateKeyPEM)
	require.NoError(t, err)

	adminHTTPClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{adminTLSCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	// ── 3b. Bind the admin cert to an account that holds a passkey. ────────────
	// api-key:create needs a per-action presence tap (ADR-021 Amendment 13). A
	// certificate that is not bound to an account cannot tap, and a fresh controller's
	// first operator has no passkey to tap with, so the account is seeded straight into
	// the account store the way the bootstrap step binds the first admin certificate.
	mgr := ctrl.GetTenantManager()
	require.NotNil(t, mgr, "controller tenant manager")
	_, err = mgr.CreateTenant(ctx, &tenant.TenantRequest{ID: "root", Name: "root"})
	require.NoError(t, err, "create root tenant")

	adminLeaf, err := x509.ParseCertificate(adminTLSCert.Certificate[0])
	require.NoError(t, err)
	passkeyKey, passkeyPub := webauthntest.NewKey(t)
	passkeyID := []byte("e2e-auth-tier-operator-credential")
	seedPasskeyOperator(t, cfg, "e2e-auth-tier-admin", adminLeaf, passkeyPub, passkeyID)

	apiSrv := ctrl.GetAPIServer()
	require.NotNil(t, apiSrv, "controller must expose its API server")
	wa, err := cfgapi.NewWebAuthnFromConfig("localhost", "localhost", []string{httpBase})
	require.NoError(t, err)
	apiSrv.SetWebAuthn(wa)

	// ── 4. Mint an API key via admin mTLS (itself a Tier-3 call). ──────────────
	// Creating the key through POST /api/v1/api-keys with the admin cert also proves
	// that step works before the sub-tests exercise the rejection path.
	createBody, err := json.Marshal(map[string]interface{}{
		"name":        "e2e-tier3-test-key",
		"permissions": []string{"api-key:create"},
	})
	require.NoError(t, err)

	createReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		httpBase+"/api/v1/api-keys", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-Presence-Token", mintPresenceToken(ctx, t, adminHTTPClient, httpBase,
		passkeyKey, passkeyID, http.MethodPost, "/api/v1/api-keys", createBody, "api-key:create"))

	createResp, err := adminHTTPClient.Do(createReq)
	require.NoError(t, err)
	createRespBytes, err := io.ReadAll(createResp.Body)
	_ = createResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, createResp.StatusCode,
		"admin POST /api/v1/api-keys must succeed (body: %s)", string(createRespBytes))

	var keyResult tier3KeyCreateResp
	require.NoError(t, json.Unmarshal(createRespBytes, &keyResult))
	apiKeyValue := keyResult.Data.Key
	require.NotEmpty(t, apiKeyValue, "created API key must be non-empty")

	// ── 5. Plain HTTPS client (no mTLS cert) for API-key auth. ────────────────
	apiKeyHTTPClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	// ── Sub-test A: API-key holder gets 403 MTLS_REQUIRED. ────────────────────
	t.Run("Tier3_APIKeyHolder_Gets403", func(t *testing.T) {
		reqBody, err := json.Marshal(map[string]interface{}{
			"name":        "e2e-apikey-attempt",
			"permissions": []string{"api-key:create"},
		})
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			httpBase+"/api/v1/api-keys", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKeyValue)

		resp, err := apiKeyHTTPClient.Do(req)
		require.NoError(t, err)
		bodyBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, "read response body")

		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"API-key principal must receive 403 on Tier-3 endpoint (body: %s)", string(bodyBytes))

		var errResp tier3ErrorResp
		require.NoError(t, json.Unmarshal(bodyBytes, &errResp),
			"response must be valid JSON error envelope (body: %s)", string(bodyBytes))
		assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code,
			"error code must be INSUFFICIENT_PERMISSIONS, got %q", errResp.Error.Code)
	})

	// ── Sub-test B: Admin cert holder passes the Tier-3 gate. ─────────────────
	// The assertion is NOT 403: any non-403 proves requireTier(TierMTLSOnly) passed the
	// admin principal through. Handler-level codes (201 success, 409 conflict, etc.)
	// are all acceptable — they come from the handler, not the tier gate. A TLS
	// handshake failure (cert rejected by server) would surface as a transport error
	// caught by require.NoError, not as a 403, so that path is also covered.
	t.Run("Tier3_AdminCertHolder_PassesTierCheck", func(t *testing.T) {
		reqBody, err := json.Marshal(map[string]interface{}{
			"name":        "e2e-admin-cert-check",
			"permissions": []string{"api-key:create"},
		})
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			httpBase+"/api/v1/api-keys", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := adminHTTPClient.Do(req)
		require.NoError(t, err)
		bodyBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, "read response body")

		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"mTLS admin cert principal must not be rejected by the Tier-3 gate (body: %s)", string(bodyBytes))
	})
}
