// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout replaces os.Stdout with a pipe, calls fn, and returns the captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stdout
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig

	data, err := io.ReadAll(r)
	require.NoError(t, err)

	return string(data)
}

// newTokenServer creates an httptest server that serves canned token API responses.
func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()

	expiresAt := "2026-06-01T00:00:00Z"
	token := APITokenResponse{
		Token:         "abc123testtoken",
		TenantID:      "test-tenant",
		ControllerURL: "controller.example.com:4433",
		Group:         "production",
		CreatedAt:     "2026-05-01T00:00:00Z",
		ExpiresAt:     &expiresAt,
		SingleUse:     false,
		Revoked:       false,
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/registration/tokens":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(token)
		case r.Method == "GET" && r.URL.Path == "/api/v1/registration/tokens":
			resp := APITokenListResponse{
				Tokens: []APITokenResponse{token},
				Total:  1,
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/registration/tokens/"):
			_ = json.NewEncoder(w).Encode(token)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunTokenCreate_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	// Save and restore package-level flag vars
	origAPIURL := tokenAPIURL
	origAPIKey := tokenAPIKey
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origGroup := tokenGroup
	origExpiresIn := tokenExpiresIn
	origSingleUse := tokenSingleUse
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenAPIKey = origAPIKey
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenGroup = origGroup
		tokenExpiresIn = origExpiresIn
		tokenSingleUse = origSingleUse
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenGroup = ""
	tokenExpiresIn = ""
	tokenSingleUse = false
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenCreate(tokenCreateCmd, nil)
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenResponse
	var parsed APITokenResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, "abc123testtoken", parsed.Token)
	assert.Equal(t, "test-tenant", parsed.TenantID)
	assert.Equal(t, "controller.example.com:4433", parsed.ControllerURL)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Registration Token:")
	assert.NotContains(t, output, "Deployment Examples:")
}

func TestRunTokenCreate_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origAPIKey := tokenAPIKey
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origGroup := tokenGroup
	origExpiresIn := tokenExpiresIn
	origSingleUse := tokenSingleUse
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenAPIKey = origAPIKey
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenGroup = origGroup
		tokenExpiresIn = origExpiresIn
		tokenSingleUse = origSingleUse
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenGroup = ""
	tokenExpiresIn = ""
	tokenSingleUse = false
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenCreate(tokenCreateCmd, nil)
		require.NoError(t, err)
	})

	// Human-readable output must be present
	assert.Contains(t, output, "Registration Token:")
	assert.Contains(t, output, "abc123testtoken")
	assert.Contains(t, output, "Deployment Examples:")

	// Must not be bare JSON
	assert.False(t, json.Valid([]byte(strings.TrimSpace(output))), "text output must not be valid JSON")
}

func TestRunTokenCreate_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origControllerURL := tokenControllerURL
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenControllerURL = origControllerURL
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = "test-tenant"
	tokenControllerURL = "controller.example.com:4433"
	tokenJSONOutput = false

	err := runTokenCreate(tokenCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create token")
}

func TestRunTokenList_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenListResponse
	var parsed APITokenListResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, 1, parsed.Total)
	require.Len(t, parsed.Tokens, 1)
	assert.Equal(t, "abc123testtoken", parsed.Tokens[0].Token)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Found")
	assert.NotContains(t, output, "token(s):")
}

func TestRunTokenList_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Human-readable output must be present
	assert.Contains(t, output, "Found 1 token(s):")
	assert.Contains(t, output, "abc123testtoken")
}

func TestRunTokenList_JSONOutput_EmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := APITokenListResponse{Tokens: []APITokenResponse{}, Total: 0}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenList(tokenListCmd, nil)
		require.NoError(t, err)
	})

	// Even with zero tokens, JSON path must emit valid JSON
	var parsed APITokenListResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")
	assert.Equal(t, 0, parsed.Total)
}

func TestRunTokenList_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origTenantID := tokenTenantID
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenTenantID = origTenantID
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenTenantID = ""
	tokenJSONOutput = false

	err := runTokenList(tokenListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list tokens")
}

func TestRunTokenGet_TextOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	output := captureStdout(t, func() {
		err := runTokenGet(tokenGetCmd, []string{"abc123testtoken"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "Token: abc123testtoken")
	assert.Contains(t, output, "Tenant ID:")
	assert.Contains(t, output, "test-tenant")
	assert.Contains(t, output, "Controller URL:")
	assert.Contains(t, output, "controller.example.com:4433")
	assert.Contains(t, output, "Status:")

	// Must not be bare JSON
	assert.False(t, json.Valid([]byte(strings.TrimSpace(output))), "text output must not be valid JSON")
}

func TestRunTokenGet_JSONOutput(t *testing.T) {
	server := newTokenServer(t)
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = true

	output := captureStdout(t, func() {
		err := runTokenGet(tokenGetCmd, []string{"abc123testtoken"})
		require.NoError(t, err)
	})

	// Output must be valid JSON parseable as APITokenResponse
	var parsed APITokenResponse
	require.NoError(t, json.Unmarshal([]byte(output), &parsed), "output must be valid JSON")

	assert.Equal(t, "abc123testtoken", parsed.Token)
	assert.Equal(t, "test-tenant", parsed.TenantID)
	assert.Equal(t, "controller.example.com:4433", parsed.ControllerURL)

	// No human-readable text on stdout
	assert.NotContains(t, output, "Token:")
	assert.NotContains(t, output, "Tenant ID:")
}

func TestRunTokenGet_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"token not found"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	err := runTokenGet(tokenGetCmd, []string{"nonexistenttoken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token nonexistenttoken")
}

func TestRunTokenGet_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	origAPIURL := tokenAPIURL
	origTLSInsecure := tokenTLSInsecure
	origJSON := tokenJSONOutput
	t.Cleanup(func() {
		tokenAPIURL = origAPIURL
		tokenTLSInsecure = origTLSInsecure
		tokenJSONOutput = origJSON
	})

	tokenAPIURL = server.URL
	tokenTLSInsecure = true
	tokenJSONOutput = false

	err := runTokenGet(tokenGetCmd, []string{"sometesttoken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get token sometesttoken")
	assert.Contains(t, err.Error(), "internal server error")
}

// generateTestBundleFile writes a real admin bundle with valid mTLS certs to path.
// controllerURL is stored as the bundle's ControllerURL so tests can distinguish bundles.
func generateTestBundleFile(t *testing.T, path, controllerURL string) {
	t.Helper()

	// Generate CA key and self-signed cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Generate client key and cert signed by the CA
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	b := &certbundle.Bundle{
		CertPEM:       string(clientCertPEM),
		KeyPEM:        string(clientKeyPEM),
		CAPEM:         string(caCertPEM),
		ControllerURL: controllerURL,
		AuditSubject:  "admin:test-admin",
	}
	require.NoError(t, certbundle.Write(path, b))
}

func TestGetAPIClient_BundlePrecedence(t *testing.T) {
	tmpDir := t.TempDir()

	bundleFlag := filepath.Join(tmpDir, "flag.bundle.yaml")
	bundleEnvVar := filepath.Join(tmpDir, "env.bundle.yaml")
	bundleUserConfig := filepath.Join(tmpDir, "userconfig", "cfgms", "admin.bundle.yaml")
	bundleSystem := filepath.Join(tmpDir, "system", "admin.bundle.yaml")

	generateTestBundleFile(t, bundleFlag, "https://flag-bundle.local:9443")
	generateTestBundleFile(t, bundleEnvVar, "https://env-bundle.local:9443")
	generateTestBundleFile(t, bundleUserConfig, "https://userconfig-bundle.local:9443")
	generateTestBundleFile(t, bundleSystem, "https://system-bundle.local:9443")

	// Override injectable path functions so tests don't touch real system paths
	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "userconfig"), nil }
	systemBundlePathFn = func() string { return bundleSystem }

	// Save and restore package-level flag vars
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origTokenAPIURL := tokenAPIURL
	t.Cleanup(func() {
		bundlePath = origBundlePath
		noBundle = origNoBundle
		tokenAPIURL = origTokenAPIURL
	})
	noBundle = false
	tokenAPIURL = "" // let bundle supply the URL

	t.Run("explicit --bundle flag beats CFGMS_ADMIN_BUNDLE", func(t *testing.T) {
		t.Setenv("CFGMS_ADMIN_BUNDLE", bundleEnvVar)
		bundlePath = bundleFlag

		client, err := getAPIClient()
		require.NoError(t, err)
		assert.Equal(t, "https://flag-bundle.local:9443", client.baseURL)
	})

	t.Run("CFGMS_ADMIN_BUNDLE beats user config dir", func(t *testing.T) {
		t.Setenv("CFGMS_ADMIN_BUNDLE", bundleEnvVar)
		bundlePath = ""

		client, err := getAPIClient()
		require.NoError(t, err)
		assert.Equal(t, "https://env-bundle.local:9443", client.baseURL)
	})

	t.Run("user config dir beats system path", func(t *testing.T) {
		origEnv, wasSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
		require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
		t.Cleanup(func() {
			if wasSet {
				require.NoError(t, os.Setenv("CFGMS_ADMIN_BUNDLE", origEnv))
			} else {
				require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
			}
		})
		bundlePath = ""

		client, err := getAPIClient()
		require.NoError(t, err)
		assert.Equal(t, "https://userconfig-bundle.local:9443", client.baseURL)
	})

	t.Run("system path used when no higher priority path exists", func(t *testing.T) {
		origEnv, wasSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
		require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
		t.Cleanup(func() {
			if wasSet {
				require.NoError(t, os.Setenv("CFGMS_ADMIN_BUNDLE", origEnv))
			} else {
				require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
			}
		})
		bundlePath = ""
		// Override user config dir to a non-existent path so only system path remains
		userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "no-such-userconfig"), nil }
		t.Cleanup(func() {
			userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "userconfig"), nil }
		})

		client, err := getAPIClient()
		require.NoError(t, err)
		assert.Equal(t, "https://system-bundle.local:9443", client.baseURL)
	})
}

func TestGetAPIClient_NoBundleFlag(t *testing.T) {
	tmpDir := t.TempDir()

	// Create bundles at all candidate paths so they'd be found without --no-bundle
	bundleFlagPath := filepath.Join(tmpDir, "flag.bundle.yaml")
	bundleEnvPath := filepath.Join(tmpDir, "env.bundle.yaml")
	bundleUserConfigPath := filepath.Join(tmpDir, "userconfig", "cfgms", "admin.bundle.yaml")
	bundleSystemPath := filepath.Join(tmpDir, "system", "admin.bundle.yaml")

	generateTestBundleFile(t, bundleFlagPath, "https://flag-bundle.local:9443")
	generateTestBundleFile(t, bundleEnvPath, "https://env-bundle.local:9443")
	generateTestBundleFile(t, bundleUserConfigPath, "https://userconfig-bundle.local:9443")
	generateTestBundleFile(t, bundleSystemPath, "https://system-bundle.local:9443")

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origTokenAPIURL := tokenAPIURL
	origTokenAPIKey := tokenAPIKey
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
		bundlePath = origBundlePath
		noBundle = origNoBundle
		tokenAPIURL = origTokenAPIURL
		tokenAPIKey = origTokenAPIKey
	})

	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "userconfig"), nil }
	systemBundlePathFn = func() string { return bundleSystemPath }
	t.Setenv("CFGMS_ADMIN_BUNDLE", bundleEnvPath)

	bundlePath = bundleFlagPath
	noBundle = true // explicit opt-out
	tokenAPIURL = "https://api-key-controller.local:9080"
	tokenAPIKey = "test-api-key"

	client, err := getAPIClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// Client must use the API key path, not the bundle (no mTLS certificates)
	assert.Equal(t, "https://api-key-controller.local:9080", client.baseURL)
	assert.Equal(t, "test-api-key", client.apiKey)
	transport := client.httpClient.Transport.(*http.Transport)
	assert.Empty(t, transport.TLSClientConfig.Certificates)
}

func TestGetAPIClient_EmptyBundleEnvVar(t *testing.T) {
	tmpDir := t.TempDir()

	// Create bundles at all candidate paths (env var empty should opt out)
	bundleEnvPath := filepath.Join(tmpDir, "env.bundle.yaml")
	bundleUserConfigPath := filepath.Join(tmpDir, "userconfig", "cfgms", "admin.bundle.yaml")
	bundleSystemPath := filepath.Join(tmpDir, "system", "admin.bundle.yaml")

	generateTestBundleFile(t, bundleEnvPath, "https://env-bundle.local:9443")
	generateTestBundleFile(t, bundleUserConfigPath, "https://userconfig-bundle.local:9443")
	generateTestBundleFile(t, bundleSystemPath, "https://system-bundle.local:9443")

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origTokenAPIURL := tokenAPIURL
	origTokenAPIKey := tokenAPIKey
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
		bundlePath = origBundlePath
		noBundle = origNoBundle
		tokenAPIURL = origTokenAPIURL
		tokenAPIKey = origTokenAPIKey
	})

	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "userconfig"), nil }
	systemBundlePathFn = func() string { return bundleSystemPath }

	// CFGMS_ADMIN_BUNDLE="" (explicitly set to empty) opts out of bundle discovery
	t.Setenv("CFGMS_ADMIN_BUNDLE", "")

	bundlePath = ""
	noBundle = false
	tokenAPIURL = "https://api-key-controller.local:9080"
	tokenAPIKey = "test-api-key"

	client, err := getAPIClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// Empty env var is explicit opt-out — must use API key path
	assert.Equal(t, "https://api-key-controller.local:9080", client.baseURL)
	assert.Equal(t, "test-api-key", client.apiKey)
	transport := client.httpClient.Transport.(*http.Transport)
	assert.Empty(t, transport.TLSClientConfig.Certificates)
}

func TestGetAPIClient_BundleAbsent_FallbackToAPIKey(t *testing.T) {
	tmpDir := t.TempDir()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	origBundlePath := bundlePath
	origNoBundle := noBundle
	origTokenAPIURL := tokenAPIURL
	origTokenAPIKey := tokenAPIKey
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
		bundlePath = origBundlePath
		noBundle = origNoBundle
		tokenAPIURL = origTokenAPIURL
		tokenAPIKey = origTokenAPIKey
	})

	// Point all candidates to non-existent paths inside tmpDir
	userConfigDirFn = func() (string, error) { return filepath.Join(tmpDir, "userconfig"), nil }
	systemBundlePathFn = func() string { return filepath.Join(tmpDir, "system", "admin.bundle.yaml") }

	// Ensure env var is not set
	origEnv, wasSet := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
	t.Cleanup(func() {
		if wasSet {
			require.NoError(t, os.Setenv("CFGMS_ADMIN_BUNDLE", origEnv))
		} else {
			require.NoError(t, os.Unsetenv("CFGMS_ADMIN_BUNDLE"))
		}
	})

	bundlePath = ""
	noBundle = false
	tokenAPIURL = "https://fallback-controller.local:9080"
	tokenAPIKey = "fallback-api-key"

	client, err := getAPIClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// No bundle anywhere → must fall through to API key path, no error
	assert.Equal(t, "https://fallback-controller.local:9080", client.baseURL)
	assert.Equal(t, "fallback-api-key", client.apiKey)
	transport := client.httpClient.Transport.(*http.Transport)
	assert.Empty(t, transport.TLSClientConfig.Certificates)
}
