// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCACert creates a valid self-signed CA certificate for testing
func generateTestCACert(t *testing.T) []byte {
	t.Helper()

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

func TestNewAPIClient(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		client, err := NewAPIClient(nil)
		assert.Nil(t, client)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("default config creates client with system CA", func(t *testing.T) {
		cfg := &APIClientConfig{
			BaseURL: "https://example.com",
			APIKey:  "test-key",
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		assert.Equal(t, "https://example.com", client.baseURL)
		assert.Equal(t, "test-key", client.apiKey)
		assert.NotNil(t, client.httpClient)
	})

	t.Run("TLS insecure mode sets InsecureSkipVerify", func(t *testing.T) {
		cfg := &APIClientConfig{
			BaseURL:     "https://example.com",
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.httpClient.Transport.(*http.Transport)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	})

	t.Run("custom CA cert creates proper TLS config", func(t *testing.T) {
		// Generate a valid test CA certificate
		testCACert := generateTestCACert(t)

		cfg := &APIClientConfig{
			BaseURL:    "https://example.com",
			CACertPEM:  testCACert,
			ServerName: "example.com",
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.httpClient.Transport.(*http.Transport)
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
		assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("invalid CA cert returns error", func(t *testing.T) {
		cfg := &APIClientConfig{
			BaseURL:   "https://example.com",
			CACertPEM: []byte("not a valid certificate"),
		}

		client, err := NewAPIClient(cfg)
		assert.Nil(t, client)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create TLS config")
	})

	t.Run("server name is set in TLS config", func(t *testing.T) {
		cfg := &APIClientConfig{
			BaseURL:    "https://example.com",
			ServerName: "custom-server-name",
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.httpClient.Transport.(*http.Transport)
		assert.Equal(t, "custom-server-name", transport.TLSClientConfig.ServerName)
	})

	t.Run("minimum TLS version is 1.2", func(t *testing.T) {
		cfg := &APIClientConfig{
			BaseURL: "https://example.com",
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.httpClient.Transport.(*http.Transport)
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	})
}

func TestAPIClientCreateToken(t *testing.T) {
	t.Run("successful token creation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

			// Parse request body
			var req APITokenCreateRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			assert.Equal(t, "test-tenant", req.TenantID)
			assert.Equal(t, "mqtt://controller:8883", req.ControllerURL)

			// Return created token
			resp := APITokenResponse{
				Token:         "cfgms_reg_test123",
				TenantID:      req.TenantID,
				ControllerURL: req.ControllerURL,
				CreatedAt:     "2025-01-01T00:00:00Z",
				SingleUse:     false,
				Revoked:       false,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			APIKey:      "test-api-key",
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		req := &APITokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller:8883",
		}

		resp, err := client.CreateToken(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "cfgms_reg_test123", resp.Token)
		assert.Equal(t, "test-tenant", resp.TenantID)
	})

	t.Run("handles error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("tenant_id is required"))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		req := &APITokenCreateRequest{
			ControllerURL: "mqtt://controller:8883",
		}

		resp, err := client.CreateToken(context.Background(), req)
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tenant_id is required")
	})
}

func TestAPIClientListTokens(t *testing.T) {
	t.Run("list all tokens", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens", r.URL.Path)

			resp := APITokenListResponse{
				Tokens: []APITokenResponse{
					{Token: "token1", TenantID: "tenant1"},
					{Token: "token2", TenantID: "tenant2"},
				},
				Total: 2,
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.ListTokens(context.Background(), "")
		require.NoError(t, err)

		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Tokens, 2)
	})

	t.Run("list with tenant filter", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "tenant1", r.URL.Query().Get("tenant_id"))

			resp := APITokenListResponse{
				Tokens: []APITokenResponse{
					{Token: "token1", TenantID: "tenant1"},
				},
				Total: 1,
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.ListTokens(context.Background(), "tenant1")
		require.NoError(t, err)

		assert.Equal(t, 1, resp.Total)
	})
}

func TestAPIClientGetToken(t *testing.T) {
	t.Run("get existing token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens/test-token", r.URL.Path)

			resp := APITokenResponse{
				Token:         "test-token",
				TenantID:      "test-tenant",
				ControllerURL: "mqtt://controller:8883",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.GetToken(context.Background(), "test-token")
		require.NoError(t, err)

		assert.Equal(t, "test-token", resp.Token)
	})

	t.Run("get non-existent token returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Token not found"))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.GetToken(context.Background(), "nonexistent")
		assert.Nil(t, resp)
		assert.Error(t, err)
	})
}

func TestAPIClientDeleteToken(t *testing.T) {
	t.Run("delete existing token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens/test-token", r.URL.Path)

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.DeleteToken(context.Background(), "test-token")
		assert.NoError(t, err)
	})

	t.Run("delete non-existent token returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Token not found"))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.DeleteToken(context.Background(), "nonexistent")
		assert.Error(t, err)
	})
}

func TestAPIClientRevokeToken(t *testing.T) {
	t.Run("revoke existing token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens/test-token/revoke", r.URL.Path)

			revokedAt := "2025-01-01T12:00:00Z"
			resp := APITokenResponse{
				Token:     "test-token",
				Revoked:   true,
				RevokedAt: &revokedAt,
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.RevokeToken(context.Background(), "test-token")
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
		assert.NotNil(t, resp.RevokedAt)
	})
}

func TestAPIClientErrorParsing(t *testing.T) {
	t.Run("parses JSON error response with error field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "Invalid request"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.GetToken(context.Background(), "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid request")
	})

	t.Run("parses JSON error response with message field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message": "Something went wrong"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.GetToken(context.Background(), "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Something went wrong")
	})

	t.Run("handles plain text error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal server error"))
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.GetToken(context.Background(), "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Internal server error")
		assert.Contains(t, err.Error(), "500")
	})
}

func TestAPIClientAuthentication(t *testing.T) {
	t.Run("sends Bearer token when API key is set", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer my-secret-key", r.Header.Get("Authorization"))

			resp := APITokenListResponse{Tokens: []APITokenResponse{}, Total: 0}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			APIKey:      "my-secret-key",
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.ListTokens(context.Background(), "")
		require.NoError(t, err)
	})

	t.Run("no Authorization header when API key is empty", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Empty(t, r.Header.Get("Authorization"))

			resp := APITokenListResponse{Tokens: []APITokenResponse{}, Total: 0}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.ListTokens(context.Background(), "")
		require.NoError(t, err)
	})
}

func TestAPIClientRequestHeaders(t *testing.T) {
	t.Run("sets correct content type and accept headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "application/json", r.Header.Get("Accept"))

			w.WriteHeader(http.StatusCreated)
			resp := APITokenResponse{Token: "test"}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{
			BaseURL:     server.URL,
			TLSInsecure: true,
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		req := &APITokenCreateRequest{
			TenantID:      "test",
			ControllerURL: "mqtt://test:8883",
		}

		_, err = client.CreateToken(context.Background(), req)
		require.NoError(t, err)
	})
}
