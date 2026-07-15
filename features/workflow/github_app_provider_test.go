// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// generateTestRSAKeyPEM generates a fresh 2048-bit RSA private key and returns
// its PEM encoding. Intended for tests only.
func generateTestRSAKeyPEM(t *testing.T) (pemBytes []byte, privateKey *rsa.PrivateKey) {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(pk)
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return b, pk
}

// TestGitHubAppJWT_SignAndVerify verifies the JWT signing path without any network calls.
// It generates a test RSA key, signs a JWT via generateGitHubAppJWT, then
// parses and verifies the token — asserting RS256 algorithm, iss claim, and exp claim.
func TestGitHubAppJWT_SignAndVerify(t *testing.T) {
	privPEM, privKey := generateTestRSAKeyPEM(t)
	appID := "42"

	signed, err := generateGitHubAppJWT(appID, string(privPEM))
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	// Parse and verify signature with the corresponding public key.
	claims := jwt.MapClaims{}
	token, err := jwt.NewParser().ParseWithClaims(signed, &claims,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return &privKey.PublicKey, nil
		},
	)
	require.NoError(t, err)
	assert.True(t, token.Valid)

	// Assert RS256 algorithm.
	assert.Equal(t, "RS256", token.Header["alg"])

	// Assert iss claim equals the app ID.
	iss, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, appID, iss)

	// Assert exp claim is in the future and no more than 10 minutes out.
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	now := time.Now()
	assert.True(t, exp.After(now), "exp must be in the future")
	assert.True(t, exp.Before(now.Add(11*time.Minute)), "exp must be at most 10 minutes from now")
}

// TestGitHubAppJWT_InvalidPEM verifies that a malformed private key PEM returns an error.
func TestGitHubAppJWT_InvalidPEM(t *testing.T) {
	_, err := generateGitHubAppJWT("1", "not-valid-pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing RSA private key")
}

// TestGitHubAppProvider_MissingSecret verifies that a missing App secret
// produces a wrapped ErrSecretNotFound without panicking.
func TestGitHubAppProvider_MissingSecret(t *testing.T) {
	store := newEmptyTestSecretStore()
	logger := pkgtesting.NewMockLogger(true)
	provider := NewGitHubAppProvider(store, logger, nil)

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	_, err := provider.ExecuteOperation(context.Background(), config)
	require.Error(t, err)
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound),
		"expected ErrSecretNotFound in error chain, got: %v", err)
}

// TestGitHubAppProvider_NilSecretStore verifies that a zero-value provider (nil secrets)
// returns a clear error rather than panicking.
func TestGitHubAppProvider_NilSecretStore(t *testing.T) {
	provider := &GitHubAppProvider{}

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	_, err := provider.ExecuteOperation(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets store not configured")
}

// TestGitHubAppProvider_ValidateConfig exercises the config validation path.
func TestGitHubAppProvider_ValidateConfig(t *testing.T) {
	p := &GitHubAppProvider{}

	cases := []struct {
		name    string
		config  *APIConfig
		wantErr string
	}{
		{
			name: "valid",
			config: &APIConfig{
				Service:    "runners",
				Operation:  "registration-token",
				Parameters: map[string]interface{}{"owner": "org", "repo": "r"},
			},
		},
		{
			name:    "empty service",
			config:  &APIConfig{},
			wantErr: "service is required",
		},
		{
			name:    "unknown service",
			config:  &APIConfig{Service: "unknown"},
			wantErr: "unsupported service",
		},
		{
			name:    "unknown operation",
			config:  &APIConfig{Service: "runners", Operation: "bad"},
			wantErr: "unsupported operation",
		},
		{
			name: "missing owner",
			config: &APIConfig{
				Service:    "runners",
				Operation:  "registration-token",
				Parameters: map[string]interface{}{"repo": "r"},
			},
			wantErr: "'owner' is required",
		},
		{
			name: "missing repo",
			config: &APIConfig{
				Service:    "runners",
				Operation:  "registration-token",
				Parameters: map[string]interface{}{"owner": "org"},
			},
			wantErr: "'repo' is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.ValidateConfig(tc.config)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestGitHubAppProvider_GetMethods verifies the provider metadata methods.
func TestGitHubAppProvider_GetMethods(t *testing.T) {
	p := &GitHubAppProvider{}

	assert.Equal(t, "github", p.GetName())
	assert.Equal(t, []string{"runners"}, p.GetServices())
	assert.Equal(t, []string{"registration-token"}, p.GetOperations("runners"))
	assert.Nil(t, p.GetOperations("unknown"))
	assert.Contains(t, p.GetAuthenticationMethods(), AuthTypeCustom)
	assert.NoError(t, p.RefreshToken(context.Background(), nil))
}

// TestGitHubAppProvider_RegisteredInBuiltins verifies that "github" is present in
// the default provider registry and that the runners/registration-token operation
// can be validated from a YAML workflow configuration.
func TestGitHubAppProvider_RegisteredInBuiltins(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger, nil)

	provider, err := registry.GetProvider("github")
	require.NoError(t, err, "github provider must be registered in registerBuiltinProviders")
	assert.Equal(t, "github", provider.GetName())

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}
	assert.NoError(t, provider.ValidateConfig(config),
		"runners/registration-token must be a valid operation on the registered provider")
}

// TestGitHubAppProvider_RegistryExecuteWithoutSecrets verifies that calling
// ExecuteOperation through the provider registry on the built-in (nil-secrets)
// github provider returns the expected "secrets store not configured" error
// rather than panicking or producing a nil-pointer dereference.
func TestGitHubAppProvider_RegistryExecuteWithoutSecrets(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger, nil)

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	_, err := registry.ExecuteOperation(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets store not configured")
}

// TestGitHubAppProvider_RegistryWithSecretsStore verifies that the github provider
// resolved from a production-wired registry (with a real secrets store) reaches
// the store and fails on a MISSING secret rather than "secrets store not configured".
// This is the [REQUIRED TEST] from the story-2374 acceptance criteria.
func TestGitHubAppProvider_RegistryWithSecretsStore(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	store := newEmptyTestSecretStore() // real store, no secrets pre-populated
	registry := NewProviderRegistry(logger, store)

	provider, err := registry.GetProvider("github")
	require.NoError(t, err)

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	_, err = provider.ExecuteOperation(context.Background(), config)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "secrets store not configured"),
		"expected failure on missing secret, not 'secrets store not configured'; got: %v", err)
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound),
		"expected ErrSecretNotFound in error chain, got: %v", err)
}

// TestNewEngine_SecretsStoreThreadedToProvider verifies that a secrets store passed
// to NewEngine is threaded through NewProviderRegistry to the github APIProvider.
// The provider must fail on ErrSecretNotFound (secrets store reachable) rather than
// "secrets store not configured" (secrets store nil).
func TestNewEngine_SecretsStoreThreadedToProvider(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	store := newEmptyTestSecretStore()
	engine := NewEngine(nil, logger, store, nil, nil, nil, nil)

	provider, err := engine.providerRegistry.GetProvider("github")
	require.NoError(t, err, "github provider must be registered in the engine's built-in registry")

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	_, err = provider.ExecuteOperation(context.Background(), config)
	require.Error(t, err)
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound),
		"secrets store reached (wired through NewEngine): expected ErrSecretNotFound, got: %v", err)
	assert.False(t, strings.Contains(err.Error(), "secrets store not configured"),
		"secrets store must be wired, not nil: got: %v", err)
}

// TestGitHubAppProvider_ExecuteOperation_E2E exercises the full ExecuteOperation path
// (secret loading → JWT signing → HTTP token exchanges) against httptest stub servers.
// The provider's baseURL field is set to the stub server URL so no real network calls are made.
func TestGitHubAppProvider_ExecuteOperation_E2E(t *testing.T) {
	privPEM, _ := generateTestRSAKeyPEM(t)
	const appID = "99"
	const installID = "1001"
	const fakeInstallToken = "ghs_testInstallToken"
	const fakeRegToken = "FAKETOKEN123"

	// Collect handler-goroutine assertion failures for replay in the test goroutine.
	// Calling t.Errorf from net/http handler goroutines is technically safe (it uses
	// t.Errorf, not t.Fatal), but assertions that reference t after the test has
	// exited are undefined. Capturing errors in a slice and replaying them here is
	// the canonical pattern for httptest handler assertions.
	var handlerMu sync.Mutex
	var handlerErrs []string
	addHandlerErr := func(msg string) {
		handlerMu.Lock()
		defer handlerMu.Unlock()
		handlerErrs = append(handlerErrs, msg)
	}

	// Single stub server handles both GitHub API endpoints.
	stubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/app/installations/" + installID + "/access_tokens":
			if r.Method != http.MethodPost {
				addHandlerErr(fmt.Sprintf("installation endpoint: expected POST, got %q", r.Method))
			}
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				addHandlerErr(fmt.Sprintf("installation-token request must carry a Bearer App JWT, got: %q", authHeader))
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":%q,"expires_at":"2026-12-31T00:00:00Z"}`, fakeInstallToken)
		case "/repos/test-org/test-repo/actions/runners/registration-token":
			if got, want := r.Header.Get("Authorization"), "Bearer "+fakeInstallToken; got != want {
				addHandlerErr(fmt.Sprintf("registration endpoint: expected Authorization %q, got %q", want, got))
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":%q,"expires_at":"2026-12-31T00:00:00Z"}`, fakeRegToken)
		default:
			http.NotFound(w, r)
		}
	}))
	defer stubServer.Close()

	store := newEmptyTestSecretStore()
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubAppID, Value: appID}))
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubInstallationID, Value: installID}))
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubPrivateKeyPEM, Value: string(privPEM)}))

	logger := pkgtesting.NewMockLogger(true)
	provider := NewGitHubAppProvider(store, logger, stubServer.Client())
	provider.baseURL = stubServer.URL // redirect to stub; no real network calls

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": "test-org",
			"repo":  "test-repo",
		},
	}

	resp, err := provider.ExecuteOperation(ctx, config)
	require.NoError(t, err)

	// Replay handler assertions in the test goroutine. By the time
	// ExecuteOperation returns the HTTP response, the handler goroutine has
	// already written to handlerErrs (response write happens-after error capture).
	handlerMu.Lock()
	errs := make([]string, len(handlerErrs))
	copy(errs, handlerErrs)
	handlerMu.Unlock()
	for _, e := range errs {
		t.Errorf("stub handler assertion: %s", e)
	}

	assert.True(t, resp.Success)
	assert.Equal(t, 201, resp.StatusCode)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, fakeRegToken, data["token"])
	assert.NotEmpty(t, data["expires_at"])
}

// TestGitHubAppIntegration runs the full App JWT → installation token → registration token
// exchange against the real GitHub API.
//
// Gated on CFGMS_TEST_GITHUB_APP=true; skipped in make test-complete.
// Required environment variables when enabled:
//
//	GITHUB_APP_ID              — numeric GitHub App ID
//	GITHUB_APP_INSTALLATION_ID — installation ID for the App on the target org/repo
//	GITHUB_APP_PRIVATE_KEY_PEM — PEM-encoded RSA private key
//	GITHUB_OWNER               — org or user name
//	GITHUB_REPO                — repository name
func TestGitHubAppIntegration(t *testing.T) {
	if os.Getenv("CFGMS_TEST_GITHUB_APP") == "" {
		t.Skip("set CFGMS_TEST_GITHUB_APP=true to run GitHub App integration tests")
	}

	appID := os.Getenv("GITHUB_APP_ID")
	installID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	pemRaw := os.Getenv("GITHUB_APP_PRIVATE_KEY_PEM")
	owner := os.Getenv("GITHUB_OWNER")
	repo := os.Getenv("GITHUB_REPO")

	for _, pair := range []struct{ k, v string }{
		{"GITHUB_APP_ID", appID},
		{"GITHUB_APP_INSTALLATION_ID", installID},
		{"GITHUB_APP_PRIVATE_KEY_PEM", pemRaw},
		{"GITHUB_OWNER", owner},
		{"GITHUB_REPO", repo},
	} {
		if pair.v == "" {
			t.Fatalf("CFGMS_TEST_GITHUB_APP is set but %s is empty", pair.k)
		}
	}

	store := newEmptyTestSecretStore()
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubAppID, Value: appID}))
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubInstallationID, Value: installID}))
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: secretKeyGitHubPrivateKeyPEM, Value: pemRaw}))

	logger := pkgtesting.NewMockLogger(true)
	provider := NewGitHubAppProvider(store, logger, nil)

	config := &APIConfig{
		Provider:  "github",
		Service:   "runners",
		Operation: "registration-token",
		Parameters: map[string]interface{}{
			"owner": owner,
			"repo":  repo,
		},
	}

	resp, err := provider.ExecuteOperation(ctx, config)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, 201, resp.StatusCode)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, data["token"], "registration token must be non-empty")
	assert.NotEmpty(t, data["expires_at"])
}

// ---- test helpers ----

// testSecretStore is a minimal thread-safe in-memory SecretStore for unit tests.
type testSecretStore struct {
	mu      sync.RWMutex
	secrets map[string]string
}

func newEmptyTestSecretStore() *testSecretStore {
	return &testSecretStore{secrets: make(map[string]string)}
}

func (s *testSecretStore) StoreSecret(_ context.Context, req *secretsif.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret %q: %w", key, secretsif.ErrSecretNotFound)
	}
	return &secretsif.Secret{Key: key, Value: v}, nil
}

func (s *testSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[key]; !ok {
		return fmt.Errorf("%w: %s", secretsif.ErrSecretNotFound, key)
	}
	delete(s.secrets, key)
	return nil
}

func (s *testSecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}

func (s *testSecretStore) GetSecrets(_ context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*secretsif.Secret)
	for _, k := range keys {
		if v, ok := s.secrets[k]; ok {
			result[k] = &secretsif.Secret{Key: k, Value: v}
		}
	}
	return result, nil
}

func (s *testSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *testSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, errors.New("versioning not supported")
}

func (s *testSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}

func (s *testSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, nil
}

func (s *testSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func (s *testSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *testSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *testSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *testSecretStore) Close() error                                             { return nil }
