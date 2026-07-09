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
//	An API-key principal carrying api-key:create is rejected with HTTP 403 MTLS_REQUIRED
//	on POST /api/v1/api-keys — the tier gate fires before the permission gate, so even a
//	key with the exact matching permission is blocked.
//
// Sub-test Tier3_AdminCertHolder_PassesTierCheck:
//
//	An mTLS admin-cert principal passes the Tier-3 gate and receives any response other
//	than 403, proving the gate does not block admin principals.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
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

	cfg := &controllerConfig.Config{
		ListenAddr: fmt.Sprintf("localhost:%d", httpPort),
		CertPath:   certPath,
		DataDir:    filepath.Join(tempDir, "data"),
		LogLevel:   "error",
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

	ctrl, err := controller.New(cfg, logger)
	require.NoError(t, err, "controller.New")

	ctrlErrCh := make(chan error, 1)
	go func() {
		ctrlErrCh <- ctrl.Start(ctx)
	}()

	httpBase := fmt.Sprintf("https://localhost:%d", httpPort)
	waitForControllerHTTP(t, certMgr, httpBase, 30*time.Second)

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if err := ctrl.Stop(stopCtx); err != nil && err.Error() != "controller not running" {
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
		assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code,
			"error code must be MTLS_REQUIRED, got %q", errResp.Error.Code)
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
