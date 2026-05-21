// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inMemoryCredentialStore is a simple in-memory implementation of auth.CredentialStore
// for use in tests that don't need OS-level secret storage.
type inMemoryCredentialStore struct {
	mu     sync.RWMutex
	tokens map[string]*auth.AccessToken
}

func newInMemoryCredentialStore() *inMemoryCredentialStore {
	return &inMemoryCredentialStore{tokens: make(map[string]*auth.AccessToken)}
}

func (s *inMemoryCredentialStore) StoreToken(tenantID string, token *auth.AccessToken) error {
	s.mu.Lock()
	s.tokens[tenantID] = token
	s.mu.Unlock()
	return nil
}

func (s *inMemoryCredentialStore) GetToken(tenantID string) (*auth.AccessToken, error) {
	s.mu.RLock()
	t, ok := s.tokens[tenantID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("token not found for %q", tenantID)
	}
	return t, nil
}

func (s *inMemoryCredentialStore) DeleteToken(_ string) error { return nil }
func (s *inMemoryCredentialStore) StoreDelegatedToken(_, _ string, _ *auth.AccessToken) error {
	return nil
}
func (s *inMemoryCredentialStore) GetDelegatedToken(_, _ string) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not implemented")
}
func (s *inMemoryCredentialStore) DeleteDelegatedToken(_, _ string) error { return nil }
func (s *inMemoryCredentialStore) StoreUserContext(_, _ string, _ *auth.UserContext) error {
	return nil
}
func (s *inMemoryCredentialStore) GetUserContext(_, _ string) (*auth.UserContext, error) {
	return nil, fmt.Errorf("not implemented")
}
func (s *inMemoryCredentialStore) DeleteUserContext(_, _ string) error              { return nil }
func (s *inMemoryCredentialStore) StoreConfig(_ string, _ *auth.OAuth2Config) error { return nil }
func (s *inMemoryCredentialStore) GetConfig(_ string) (*auth.OAuth2Config, error) {
	return nil, fmt.Errorf("not implemented")
}
func (s *inMemoryCredentialStore) IsAvailable() bool { return true }

// sha256HexOf returns the lowercase hex SHA-256 of the given string.
func sha256HexOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// signTestRequest signs req in-place using AWS Signature V4 with the supplied credentials.
func signTestRequest(t *testing.T, req *http.Request, accessKey, secretKey, region, service, payloadHash string) {
	t.Helper()
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	}

	signer := awsv4.NewSigner()
	signingTime := time.Now().UTC()
	err := signer.SignHTTP(context.Background(), creds, req, payloadHash, service, region, signingTime)
	require.NoError(t, err, "AWS SDK signing must not fail")
}

// tokenResponse is the JSON structure returned by the test token server.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func TestClientCredentialsGrant_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "real-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			TokenURL:     srv.URL,
		},
		GrantType: "client_credentials",
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	tokenSet, err := client.ClientCredentialsGrant(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, tokenSet)

	assert.Equal(t, "real-token", tokenSet.AccessToken)
	assert.Equal(t, "Bearer", tokenSet.TokenType)
	assert.NotContains(t, tokenSet.AccessToken, "mock")
	assert.True(t, tokenSet.ExpiresAt.After(time.Now().Add(59*time.Minute)), "ExpiresAt should be ~1 hour from now")
}

func TestClientCredentialsGrant_OAuth2Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Error:            "invalid_client",
			ErrorDescription: "bad creds",
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "bad-client-id",
			ClientSecret: "bad-secret",
			TokenURL:     srv.URL,
		},
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	_, err := client.ClientCredentialsGrant(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
}

func TestClientCredentialsGrant_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     srv.URL,
		},
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	_, err := client.ClientCredentialsGrant(context.Background(), config)
	require.Error(t, err)
}

func TestRefreshToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:  "refreshed-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh-token",
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			TokenURL:     srv.URL,
		},
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	tokenSet, err := client.RefreshToken(context.Background(), "old-refresh-token")
	require.NoError(t, err)
	require.NotNil(t, tokenSet)

	assert.Equal(t, "refreshed-access-token", tokenSet.AccessToken)
	assert.Equal(t, "Bearer", tokenSet.TokenType)
	assert.Equal(t, "new-refresh-token", tokenSet.RefreshToken)
	assert.NotContains(t, tokenSet.AccessToken, "new-access-token", "must not return placeholder token")
	assert.True(t, tokenSet.ExpiresAt.After(time.Now().Add(59*time.Minute)))
}

func TestRefreshToken_PreservesOldRefreshTokenWhenServerOmitsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "new-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			// no refresh_token returned
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     srv.URL,
		},
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	tokenSet, err := client.RefreshToken(context.Background(), "original-refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "original-refresh-token", tokenSet.RefreshToken, "should preserve old refresh token when server omits it")
}

func TestRefreshToken_NoConfigReturnsError(t *testing.T) {
	client := NewOAuth2Client(http.DefaultClient, nil)

	_, err := client.RefreshToken(context.Background(), "some-refresh-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

func TestRefreshToken_OAuth2Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Error:            "invalid_grant",
			ErrorDescription: "refresh token expired",
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			TokenURL:     srv.URL,
		},
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	_, err := client.RefreshToken(context.Background(), "expired-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestGenerateJWT_RSA_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: string(privateKeyPEM),
		Algorithm:  "RS256",
		Claims: map[string]interface{}{
			"sub": "test-subject",
			"iss": "test-issuer",
		},
	}

	signed, err := ua.generateJWT(config)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)
	assert.NotEqual(t, "mock-jwt-token", signed)
	assert.True(t, strings.HasPrefix(signed, "ey"), "JWT should start with 'ey'")

	// Verify the signature using the public key
	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		require.True(t, ok, "signing method should be RSA")
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "test-subject", claims["sub"])
	assert.Equal(t, "test-issuer", claims["iss"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["exp"])
}

func TestGenerateJWT_HMAC_Success(t *testing.T) {
	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: "super-secret-hmac-key-at-least-32-bytes-long",
		Algorithm:  "HS256",
		Claims: map[string]interface{}{
			"sub": "hmac-subject",
		},
	}

	signed, err := ua.generateJWT(config)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)
	assert.NotEqual(t, "mock-jwt-token", signed)

	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		require.True(t, ok, "signing method should be HMAC")
		return []byte(config.PrivateKey), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "hmac-subject", claims["sub"])
}

func TestGenerateJWT_DefaultsToRS256WhenAlgorithmEmpty(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: string(privateKeyPEM),
		Algorithm:  "", // empty — should default to RS256
		Claims:     map[string]interface{}{"sub": "test"},
	}

	signed, err := ua.generateJWT(config)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		require.True(t, ok, "default algorithm should be RSA (RS256)")
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestGenerateJWT_EmptyPrivateKeyReturnsError(t *testing.T) {
	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: "",
		Algorithm:  "RS256",
	}

	_, err := ua.generateJWT(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private_key is required")
}

func TestGenerateJWT_ReturnsProvidedTokenDirectly(t *testing.T) {
	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		Token:     "already-signed-jwt-token",
		Algorithm: "RS256",
	}

	signed, err := ua.generateJWT(config)
	require.NoError(t, err)
	assert.Equal(t, "already-signed-jwt-token", signed)
}

func TestGenerateJWT_InvalidRSAKeyReturnsError(t *testing.T) {
	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: "not-a-valid-pem-key",
		Algorithm:  "RS256",
	}

	_, err := ua.generateJWT(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse RSA private key")
}

func TestGenerateJWT_AddsIatAndExpWhenAbsent(t *testing.T) {
	ua := &UniversalAuthenticator{}
	config := &JWTConfig{
		PrivateKey: "hmac-key-long-enough-for-hs256-signing",
		Algorithm:  "HS256",
		Claims:     map[string]interface{}{"sub": "test"},
	}

	before := time.Now()
	signed, err := ua.generateJWT(config)
	require.NoError(t, err)

	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.PrivateKey), nil
	})
	require.NoError(t, err)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	iat, ok := claims["iat"].(float64)
	require.True(t, ok, "iat should be present")
	assert.GreaterOrEqual(t, int64(iat), before.Unix())

	exp, ok := claims["exp"].(float64)
	require.True(t, ok, "exp should be present")
	assert.Greater(t, int64(exp), int64(iat), "exp should be after iat")
}

func TestNoMockTokensInProductionCode(t *testing.T) {
	// This test documents and enforces that no placeholder token strings remain.
	// If these strings appear in test output, the implementation regressed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "real-server-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	config := &ExtendedOAuth2Config{
		OAuth2Config: OAuth2Config{
			ClientID:     "cid",
			ClientSecret: "csecret",
			TokenURL:     srv.URL,
		},
		GrantType: "client_credentials",
	}
	client := NewOAuth2Client(http.DefaultClient, config)

	tokenSet, err := client.ClientCredentialsGrant(context.Background(), config)
	require.NoError(t, err)
	assert.Equal(t, "real-server-token", tokenSet.AccessToken, "ClientCredentialsGrant must return the server-issued token")

	tokenSet2, err := client.RefreshToken(context.Background(), "some-refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "real-server-token", tokenSet2.AccessToken, "RefreshToken must return the server-issued token")

	ua := &UniversalAuthenticator{}
	jwtConfig := &JWTConfig{
		PrivateKey: "hmac-secret-key-long-enough-here",
		Algorithm:  "HS256",
	}
	signed, err := ua.generateJWT(jwtConfig)
	require.NoError(t, err)
	assert.NotEqual(t, "mock-jwt-token", signed, "generateJWT must not return placeholder")
}

// AWS Signature V4 tests

const (
	testAWSAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testAWSSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testAWSRegion    = "us-east-1"
	testAWSService   = "execute-api"
	testAWSProvider  = "test-aws"
)

func setupAWSAuthenticator(t *testing.T) *UniversalAuthenticator {
	t.Helper()
	credStore := newInMemoryCredentialStore()
	ua := NewUniversalAuthenticator(credStore, http.DefaultClient)
	err := ua.Authenticate(context.Background(), testAWSProvider, AuthConfig{
		Method: AuthMethodAWSSignature,
		Config: map[string]interface{}{
			"access_key_id":     testAWSAccessKey,
			"secret_access_key": testAWSSecretKey,
			"region":            testAWSRegion,
			"service":           testAWSService,
		},
	})
	require.NoError(t, err, "Authenticate must store AWS credentials without error")
	return ua
}

func TestAuthenticateAWSSignature_StoresCredentials(t *testing.T) {
	credStore := newInMemoryCredentialStore()
	ua := NewUniversalAuthenticator(credStore, http.DefaultClient)

	err := ua.Authenticate(context.Background(), testAWSProvider, AuthConfig{
		Method: AuthMethodAWSSignature,
		Config: map[string]interface{}{
			"access_key_id":     testAWSAccessKey,
			"secret_access_key": testAWSSecretKey,
			"region":            testAWSRegion,
			"service":           testAWSService,
		},
	})
	require.NoError(t, err)

	// Verify the credentials were stored and are retrievable
	token, err := credStore.GetToken(testAWSProvider + ":secret")
	require.NoError(t, err)

	var stored AWSSignatureConfig
	require.NoError(t, json.Unmarshal([]byte(token.Token), &stored))
	assert.Equal(t, testAWSAccessKey, stored.AccessKeyID)
	assert.Equal(t, testAWSSecretKey, stored.SecretAccessKey)
	assert.Equal(t, testAWSRegion, stored.Region)
	assert.Equal(t, testAWSService, stored.Service)
}

func TestAuthenticateAWSSignature_MissingAccessKeyID(t *testing.T) {
	ua := NewUniversalAuthenticator(newInMemoryCredentialStore(), http.DefaultClient)
	err := ua.Authenticate(context.Background(), testAWSProvider, AuthConfig{
		Method: AuthMethodAWSSignature,
		Config: map[string]interface{}{
			"secret_access_key": testAWSSecretKey,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_key_id")
}

func TestVerifyAWSSignedRequest_ValidSignature(t *testing.T) {
	ua := setupAWSAuthenticator(t)

	payload := "test request body"
	payloadHash := sha256HexOf(payload)

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		"https://example.execute-api.us-east-1.amazonaws.com/test", strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	signTestRequest(t, req, testAWSAccessKey, testAWSSecretKey, testAWSRegion, testAWSService, payloadHash)

	err = ua.VerifyAWSSignedRequest(context.Background(), testAWSProvider, req)
	assert.NoError(t, err, "valid AWS Signature V4 request must be accepted")
}

func TestVerifyAWSSignedRequest_InvalidSignature(t *testing.T) {
	ua := setupAWSAuthenticator(t)

	payload := "test request body"
	payloadHash := sha256HexOf(payload)

	req, err := http.NewRequestWithContext(context.Background(), "POST",
		"https://example.execute-api.us-east-1.amazonaws.com/test", strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	signTestRequest(t, req, testAWSAccessKey, testAWSSecretKey, testAWSRegion, testAWSService, payloadHash)

	// Tamper with the last 8 hex chars of the signature to produce an invalid header.
	origAuth := req.Header.Get("Authorization")
	req.Header.Set("Authorization", origAuth[:len(origAuth)-8]+"00000000")

	err = ua.VerifyAWSSignedRequest(context.Background(), testAWSProvider, req)
	require.Error(t, err, "tampered signature must be rejected")
	assert.ErrorIs(t, err, errUnauthenticated, "error must wrap errUnauthenticated sentinel")
}

func TestVerifyAWSSignedRequest_MalformedAuthorizationHeader(t *testing.T) {
	ua := setupAWSAuthenticator(t)

	req, err := http.NewRequestWithContext(context.Background(), "GET",
		"https://example.com/path", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer not-aws-sig")
	req.Header.Set("X-Amz-Date", "20230101T120000Z")

	err = ua.VerifyAWSSignedRequest(context.Background(), testAWSProvider, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed", "error must describe the malformed header")
	assert.NotErrorIs(t, err, errUnauthenticated, "malformed header is an internal error, not unauthenticated")
}

func TestVerifyAWSSignedRequest_WrongAccessKey(t *testing.T) {
	ua := setupAWSAuthenticator(t)

	payload := ""
	payloadHash := sha256HexOf(payload)

	req, err := http.NewRequestWithContext(context.Background(), "GET",
		"https://example.execute-api.us-east-1.amazonaws.com/resource", nil)
	require.NoError(t, err)

	// Sign with a DIFFERENT access key
	signTestRequest(t, req, "AKIADIFFERENTKEY0001", testAWSSecretKey, testAWSRegion, testAWSService, payloadHash)

	err = ua.VerifyAWSSignedRequest(context.Background(), testAWSProvider, req)
	require.Error(t, err)
	assert.ErrorIs(t, err, errUnauthenticated, "wrong access key must return unauthenticated error")
}
