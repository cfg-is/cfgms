// SPDX-License-Identifier: AGPL-3.0-only
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

	"github.com/cfgis/cfgms/pkg/cert"
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
			assert.Equal(t, "controller:4433", req.ControllerURL)

			// Return created token
			resp := APITokenResponse{
				Token:         "test123",
				TenantID:      req.TenantID,
				ControllerURL: req.ControllerURL,
				CreatedAt:     "2025-01-01T00:00:00Z",
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
			ControllerURL: "controller:4433",
		}

		resp, err := client.CreateToken(context.Background(), req)
		require.NoError(t, err)

		assert.Equal(t, "test123", resp.Token)
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
			ControllerURL: "controller:4433",
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
				ControllerURL: "controller:4433",
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

func TestAPIClientRotateToken(t *testing.T) {
	t.Run("rotate returns new token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/tokens/test-tenant/rotate", r.URL.Path)

			var body APIRotateTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "production", body.Group)

			resp := APITokenResponse{
				Token:         "newtoken123",
				TenantID:      "test-tenant",
				ControllerURL: "controller:4433",
				Group:         "production",
				CreatedAt:     "2025-01-01T00:00:00Z",
				Revoked:       false,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, APIKey: "test-key", TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.RotateToken(context.Background(), "test-tenant", "production")
		require.NoError(t, err)

		assert.Equal(t, "newtoken123", resp.Token)
		assert.Equal(t, "test-tenant", resp.TenantID)
		assert.Equal(t, "production", resp.Group)
	})

	t.Run("no active tokens returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no active tokens found for tenant"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.RotateToken(context.Background(), "empty-tenant", "")
		assert.Nil(t, resp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active tokens found")
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
			ControllerURL: "test:4433",
		}

		_, err = client.CreateToken(context.Background(), req)
		require.NoError(t, err)
	})
}

func TestNewAPIClient_MTLSConfig(t *testing.T) {
	t.Run("client cert and key populate TLS config with certificate", func(t *testing.T) {
		manager, err := cert.NewManager(&cert.ManagerConfig{
			CAConfig: &cert.CAConfig{
				Organization: "Test CA",
				Country:      "US",
				ValidityDays: 365,
			},
			StoragePath: t.TempDir(),
		})
		require.NoError(t, err)

		caCertPEM, err := manager.GetCACertificate()
		require.NoError(t, err)

		clientCert, err := manager.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   "test-admin",
			Organization: "Test Admin",
			ValidityDays: 1,
		})
		require.NoError(t, err)

		cfg := &APIClientConfig{
			BaseURL:       "https://controller.example.com:9443",
			ClientCertPEM: clientCert.CertificatePEM,
			ClientKeyPEM:  clientCert.PrivateKeyPEM,
			CACertPEM:     caCertPEM,
			ServerName:    "controller.example.com",
		}

		client, err := NewAPIClient(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.httpClient.Transport.(*http.Transport)
		assert.NotEmpty(t, transport.TLSClientConfig.Certificates)
		assert.NotNil(t, transport.TLSClientConfig.RootCAs)
		assert.Equal(t, "controller.example.com", transport.TLSClientConfig.ServerName)
	})
}

func TestAPIClientGet(t *testing.T) {
	t.Run("returns response for successful GET", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/api/v1/test", r.URL.Path)
			assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, APIKey: "test-key", TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.Get(context.Background(), "/api/v1/test")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error on connection failure", func(t *testing.T) {
		cfg := &APIClientConfig{BaseURL: "http://127.0.0.1:0", TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		resp, err := client.Get(context.Background(), "/api/v1/test")
		assert.Nil(t, resp)
		assert.Error(t, err)
	})
}

func TestAPIClientApproveAllRegistrations(t *testing.T) {
	t.Run("returns count of approved registrations", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/approve-all", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"approved":3}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		count, err := client.ApproveAllRegistrations(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	t.Run("returns 0 on second call (idempotent)", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			if callCount == 1 {
				_, _ = w.Write([]byte(`{"approved":2}`))
			} else {
				_, _ = w.Write([]byte(`{"approved":0}`))
			}
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		count1, err := client.ApproveAllRegistrations(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 2, count1)

		count2, err := client.ApproveAllRegistrations(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 0, count2)
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"store unavailable"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.ApproveAllRegistrations(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "store unavailable")
	})
}

func TestAPIClientApproveByCIDR(t *testing.T) {
	t.Run("sends CIDR in request body and returns count", func(t *testing.T) {
		var capturedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/approve-by-cidr", r.URL.Path)

			buf := make([]byte, 256)
			n, _ := r.Body.Read(buf)
			capturedBody = string(buf[:n])

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"approved":2}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		count, err := client.ApproveByCIDR(context.Background(), "192.168.1.0/24")
		require.NoError(t, err)
		assert.Equal(t, 2, count)
		assert.Contains(t, capturedBody, "192.168.1.0/24")
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid CIDR"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		_, err = client.ApproveByCIDR(context.Background(), "not-a-cidr")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CIDR")
	})
}

func TestAPIClientAddIPTrust(t *testing.T) {
	t.Run("sends tenant_id, cidr and pre_seeded=true", func(t *testing.T) {
		var capturedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/api/v1/registration/ip-trust", r.URL.Path)

			buf := make([]byte, 256)
			n, _ := r.Body.Read(buf)
			capturedBody = string(buf[:n])

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.AddIPTrust(context.Background(), "acme", "10.0.0.0/8")
		require.NoError(t, err)
		assert.Contains(t, capturedBody, "acme")
		assert.Contains(t, capturedBody, "10.0.0.0/8")
		assert.Contains(t, capturedBody, `"pre_seeded":true`)
	})

	t.Run("API error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"ip-trust store unavailable"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.AddIPTrust(context.Background(), "acme", "10.0.0.0/8")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ip-trust store unavailable")
	})
}

func TestAPIClientRevokeIPTrust(t *testing.T) {
	t.Run("sends DELETE to correct path with encoded CIDR", func(t *testing.T) {
		var capturedMethod, capturedRawPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedRawPath = r.URL.RawPath
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.RevokeIPTrust(context.Background(), "acme", "10.0.0.0/8")
		require.NoError(t, err)
		assert.Equal(t, "DELETE", capturedMethod)
		// The CIDR slash should be percent-encoded to preserve it as a single path segment.
		assert.Contains(t, capturedRawPath, "10.0.0.0%2F8")
		assert.Contains(t, capturedRawPath, "acme")
	})

	t.Run("not found returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"ip trust entry not found"}`))
		}))
		defer server.Close()

		cfg := &APIClientConfig{BaseURL: server.URL, TLSInsecure: true}
		client, err := NewAPIClient(cfg)
		require.NoError(t, err)

		err = client.RevokeIPTrust(context.Background(), "acme", "10.0.0.0/8")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ip trust entry not found")
	})
}
