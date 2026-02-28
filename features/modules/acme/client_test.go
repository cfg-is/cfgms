// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build integration

package acme

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests require a running Pebble ACME test server.
// Start it with:
//   docker run -d --name pebble -p 14000:14000 -p 5002:5002 \
//     -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_VA_ALWAYS_VALID=1 \
//     letsencrypt/pebble:latest pebble -config /test/config/pebble-config.json
//
// Run tests with:
//   ACME_TEST_SERVER=https://localhost:14000/dir go test -tags integration -v ./features/modules/acme/

func getPebbleURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("ACME_TEST_SERVER")
	if url == "" {
		t.Skip("ACME_TEST_SERVER not set; skipping integration test (requires Pebble)")
	}

	// Verify Pebble is reachable
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - Pebble uses self-signed cert
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Skipf("Pebble not reachable at %s: %v", url, err)
	}
	resp.Body.Close()

	return url
}

func TestIntegration_ObtainCertificate_HTTP01(t *testing.T) {
	pebbleURL := getPebbleURL(t)
	tmpDir := t.TempDir()

	store, err := NewACMECertStore(tmpDir)
	require.NoError(t, err)

	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"test.example.com"},
		Email:                "test@example.com",
		ACMEServer:           pebbleURL,
		ChallengeType:        "http-01",
		HTTPBindAddress:      ":5002",
		KeyType:              "ec256",
		RenewalThresholdDays: 30,
		CertStorePath:        tmpDir,
	}

	solver := NewHTTPChallengeSolver(cfg.HTTPBindAddress)
	client, err := NewACMEClient(cfg, store, solver)
	require.NoError(t, err)

	certPEM, keyPEM, issuerPEM, err := client.ObtainCertificate()
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)
	assert.NotEmpty(t, issuerPEM)

	// Store and verify round-trip
	err = store.StoreCertificate("test.example.com", certPEM, keyPEM, issuerPEM, nil)
	require.NoError(t, err)

	loadedCert, loadedKey, err := store.LoadCertificate("test.example.com")
	require.NoError(t, err)
	assert.Equal(t, certPEM, loadedCert)
	assert.Equal(t, keyPEM, loadedKey)
}

func TestIntegration_ModuleSetGet_HTTP01(t *testing.T) {
	pebbleURL := getPebbleURL(t)
	tmpDir := t.TempDir()

	m := New()
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"module-test.example.com"},
		Email:                "test@example.com",
		ACMEServer:           pebbleURL,
		ChallengeType:        "http-01",
		HTTPBindAddress:      ":5002",
		KeyType:              "ec256",
		RenewalThresholdDays: 30,
		CertStorePath:        tmpDir,
	}

	ctx := context.Background()

	// Set should obtain the certificate
	err := m.Set(ctx, "module-test.example.com", cfg)
	require.NoError(t, err)

	// Get should return the certificate
	state, err := m.Get(ctx, "module-test.example.com")
	require.NoError(t, err)
	require.NotNil(t, state)

	resultCfg, ok := state.(*ACMEConfig)
	require.True(t, ok)
	assert.Equal(t, "present", resultCfg.State)
	assert.NotNil(t, resultCfg.CertificateStatus)
	assert.True(t, resultCfg.CertificateStatus.DaysUntilExpiry > 0)
}

func TestIntegration_ModuleSetIdempotent_HTTP01(t *testing.T) {
	pebbleURL := getPebbleURL(t)
	tmpDir := t.TempDir()

	m := New()
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"idempotent-test.example.com"},
		Email:                "test@example.com",
		ACMEServer:           pebbleURL,
		ChallengeType:        "http-01",
		HTTPBindAddress:      ":5002",
		KeyType:              "ec256",
		RenewalThresholdDays: 30,
		CertStorePath:        tmpDir,
	}

	ctx := context.Background()

	// First Set: obtains certificate
	err := m.Set(ctx, "idempotent-test.example.com", cfg)
	require.NoError(t, err)

	// Second Set: should be no-op (certificate is valid)
	err = m.Set(ctx, "idempotent-test.example.com", cfg)
	require.NoError(t, err)
}
