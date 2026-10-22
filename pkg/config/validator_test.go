// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	git "github.com/go-git/go-git/v5"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitserver "github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/memory"

	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/sops"
)

// testSecretStore is a simple in-process secret store for validator tests.
// It is a real implementation (not a mock): it stores and returns secrets from a map.
type testSecretStore struct {
	secrets map[string]string
	// bound maps a secret key to the repository URL written into its
	// bound_repository_url metadata. A key absent here has no metadata.
	bound map[string]string
}

// newBoundTestSecretStore returns a store whose every secret is bound to repoURL.
func newBoundTestSecretStore(secrets map[string]string, repoURL string) *testSecretStore {
	b := make(map[string]string, len(secrets))
	for k := range secrets {
		b[k] = NormalizeRepositoryURL(repoURL)
	}
	return &testSecretStore{secrets: secrets, bound: b}
}

func newTestSecretStore(secrets map[string]string) *testSecretStore {
	return &testSecretStore{secrets: secrets}
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsiface.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsiface.ErrSecretNotFound
	}
	sec := &secretsiface.Secret{Key: key, Value: v}
	if u, ok := s.bound[key]; ok {
		sec.Metadata = map[string]string{SecretMetaKeyBoundRepositoryURL: u}
	}
	return sec, nil
}

func (s *testSecretStore) StoreSecret(_ context.Context, _ *secretsiface.SecretRequest) error {
	return nil
}
func (s *testSecretStore) CompareAndSwapSecret(_ context.Context, _ string, _ int, req *secretsiface.SecretRequest) (int, bool, error) {
	if s.secrets == nil {
		s.secrets = make(map[string]string)
	}
	s.secrets[req.Key] = req.Value
	return 1, true, nil
}
func (s *testSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *testSecretStore) ListSecrets(_ context.Context, _ *secretsiface.SecretFilter) ([]*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsiface.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsiface.SecretRequest) error {
	return nil
}
func (s *testSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsiface.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsiface.SecretVersion, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *testSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *testSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *testSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *testSecretStore) Close() error                                             { return nil }

// testRepoURL is the in-memory git server URL used for tests that need a reachable
// remote. It is a hostname-based HTTPS URL so it passes the SSRF guard.
const testRepoURL = "https://test.cfgms.local/repo"

// installTestTransport temporarily replaces the go-git HTTPS protocol handler with
// a server-side transport backed by the provided storage. The MapLoader key must be
// the full endpoint URL string (ep.String()), which is what MapLoader.Load uses.
// Returns a restore function that MUST be deferred. Tests that use this helper must
// NOT call t.Parallel() because it modifies package-level global state.
func installTestTransport(t *testing.T, store *memory.Storage) (restore func()) {
	t.Helper()
	original := gitclient.Protocols["https"]
	loader := gitserver.MapLoader{testRepoURL: store}
	gitclient.InstallProtocol("https", gitserver.NewClient(loader))
	return func() {
		gitclient.InstallProtocol("https", original)
	}
}

// installEmptyTransport installs a transport with no repositories (all lookups fail).
func installEmptyTransport(t *testing.T) (restore func()) {
	t.Helper()
	original := gitclient.Protocols["https"]
	gitclient.InstallProtocol("https", gitserver.NewClient(gitserver.MapLoader{}))
	return func() {
		gitclient.InstallProtocol("https", original)
	}
}

// newInMemoryBareRepo creates an empty in-memory bare git repository.
func newInMemoryBareRepo(t *testing.T) *memory.Storage {
	t.Helper()
	store := memory.NewStorage()
	_, err := git.Init(store, nil) // nil worktree = bare
	require.NoError(t, err)
	return store
}

// TestValidateMountPoint_Reachable verifies that ValidateMountPoint returns nil when
// the remote is reachable, using an in-memory go-git server transport.
// An empty bare repository (no commits) is treated as connectivity success —
// the remote responded, so the mount point is reachable.
func TestValidateMountPoint_Reachable(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	store := newInMemoryBareRepo(t)
	restore := installTestTransport(t, store)
	defer restore()

	v := NewDefaultMountPointValidator()
	info := &ConfigSourceInfo{
		Type: ConfigSourceTypeGit,
		URL:  testRepoURL,
	}
	require.NoError(t, v.ValidateMountPoint(context.Background(), info, nil))
}

// TestValidateMountPoint_Unreachable verifies that ValidateMountPoint returns an error
// when no repository exists at the given URL.
func TestValidateMountPoint_Unreachable(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	restore := installEmptyTransport(t) // no repos registered
	defer restore()

	v := NewDefaultMountPointValidator()
	info := &ConfigSourceInfo{
		Type: ConfigSourceTypeGit,
		URL:  testRepoURL,
	}
	err := v.ValidateMountPoint(context.Background(), info, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mount point connection test failed")
}

// TestValidateMountPoint_CredentialFailure verifies that ValidateMountPoint returns an
// error when the remote rejects authentication, and that the error contains no credential.
func TestValidateMountPoint_CredentialFailure(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	repoURL := fmt.Sprintf("https://localhost:%d/repo", port)

	ss := newBoundTestSecretStore(map[string]string{"mytoken": "super-secret-value"}, repoURL)

	v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
	info := &ConfigSourceInfo{
		Type:          ConfigSourceTypeGit,
		URL:           repoURL,
		CredentialRef: "mytoken",
	}
	err := v.ValidateMountPoint(context.Background(), info, ss)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-value", "error must not leak credential")
}

// TestValidateMountPoint_Timeout verifies that ValidateMountPoint returns an error when
// the caller's context deadline expires before the remote responds.
func TestValidateMountPoint_Timeout(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // block until client disconnects
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	repoURL := fmt.Sprintf("https://localhost:%d/repo", port)

	v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
	info := &ConfigSourceInfo{
		Type: ConfigSourceTypeGit,
		URL:  repoURL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := v.ValidateMountPoint(ctx, info, nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, 5*time.Second, "validator must time out quickly when caller context expires")
	msg := err.Error()
	assert.True(t,
		strings.Contains(msg, "deadline") ||
			strings.Contains(msg, "timeout") ||
			strings.Contains(msg, "context") ||
			strings.Contains(msg, "connection"),
		"expected timeout/context error, got: %v", err)
}

// TestValidateMountPoint_NoCredentialLeakedInError verifies that error messages from
// ValidateMountPoint never contain credential bytes even when the connection fails.
func TestValidateMountPoint_NoCredentialLeakedInError(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	const sensitiveToken = "ultra-sensitive-token-abc123"

	restore := installEmptyTransport(t) // always fails
	defer restore()

	ss := newBoundTestSecretStore(map[string]string{"myref": sensitiveToken}, testRepoURL)

	v := NewDefaultMountPointValidator()
	info := &ConfigSourceInfo{
		Type:          ConfigSourceTypeGit,
		URL:           testRepoURL,
		CredentialRef: "myref",
	}
	err := v.ValidateMountPoint(context.Background(), info, ss)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sensitiveToken,
		"error message must not contain the credential value")
}

// TestValidateMountPoint_RejectsRFC1918AtValidateTime verifies that ValidateMountPoint
// re-runs the SSRF guard and rejects RFC 1918/loopback IP literals independently.
func TestValidateMountPoint_RejectsRFC1918AtValidateTime(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"10.x.x.x", "https://10.0.0.1/repo.git"},
		{"172.16.x.x", "https://172.16.0.1/repo.git"},
		{"192.168.x.x", "https://192.168.1.1/repo.git"},
		{"loopback 127.0.0.1", "https://127.0.0.1/repo.git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewDefaultMountPointValidator()
			info := &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: tc.url}
			err := v.ValidateMountPoint(context.Background(), info, nil)
			require.Error(t, err, "expected SSRF rejection for %s", tc.url)
			assert.True(t,
				strings.Contains(err.Error(), "SSRF") || strings.Contains(err.Error(), "URL validation"),
				"expected SSRF/URL-validation error, got: %v", err)
		})
	}
}

// TestValidateMountPoint_RejectsUserinfoAtValidateTime verifies that ValidateMountPoint
// re-runs the userinfo check and rejects URLs with embedded credentials.
func TestValidateMountPoint_RejectsUserinfoAtValidateTime(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"token-only userinfo", "https://token@github.com/example/repo.git"},
		{"user:pass userinfo", "https://user:pass@github.com/example/repo.git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewDefaultMountPointValidator()
			info := &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: tc.url}
			err := v.ValidateMountPoint(context.Background(), info, nil)
			require.Error(t, err, "expected userinfo rejection for %s", tc.url)
			assert.True(t,
				strings.Contains(err.Error(), "userinfo") || strings.Contains(err.Error(), "URL validation"),
				"expected userinfo/URL-validation error, got: %v", err)
		})
	}
}

// TestValidateMountPoint_NilInfo verifies that a nil ConfigSourceInfo returns no error.
func TestValidateMountPoint_NilInfo(t *testing.T) {
	v := NewDefaultMountPointValidator()
	assert.NoError(t, v.ValidateMountPoint(context.Background(), nil, nil))
}

// TestValidateMountPoint_ControllerSource verifies that non-git sources are a no-op.
func TestValidateMountPoint_ControllerSource(t *testing.T) {
	v := NewDefaultMountPointValidator()
	info := &ConfigSourceInfo{Type: ConfigSourceTypeController}
	assert.NoError(t, v.ValidateMountPoint(context.Background(), info, nil))
}

// TestSanitizeConnectionError verifies that credential bytes are scrubbed from errors.
func TestSanitizeConnectionError(t *testing.T) {
	auth := &githttp.BasicAuth{Username: "git", Password: "mysecretpassword"}
	err := sanitizeConnectionError(fmt.Errorf("auth failed with mysecretpassword"), auth)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "mysecretpassword")
	assert.Contains(t, err.Error(), "[REDACTED]")
}

// bindingTestServer starts a real HTTPS server that records whether any request
// carried an Authorization header and returns its repository URL.
func bindingTestServer(t *testing.T) (repoURL string, sawAuth func() bool) {
	t.Helper()
	var mu sync.Mutex
	seen := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			mu.Lock()
			seen = true
			mu.Unlock()
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("https://localhost:%d/repo", port), func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

// TestValidateMountPoint_CredentialBinding covers the binding check: a credential
// bound to another repository, or to none, is refused before any network call.
func TestValidateMountPoint_CredentialBinding(t *testing.T) {
	t.Cleanup(UseHostResolverForTesting(publicTestResolver()))
	const token = "binding-secret-token-xyz"
	const fix = "cfg tenant config-source set-credential"

	t.Run("bound to another repository is refused with no Authorization header", func(t *testing.T) {
		urlB, sawAuth := bindingTestServer(t)
		ss := newBoundTestSecretStore(map[string]string{"ref": token}, "https://other.cfgms.local/repo")
		v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
		err := v.ValidateMountPoint(context.Background(), &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: urlB, CredentialRef: "ref"}, ss)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fix)
		assert.NotContains(t, err.Error(), token)
		assert.False(t, sawAuth(), "server must receive no Authorization header")
	})

	t.Run("unbound credential is refused", func(t *testing.T) {
		urlB, sawAuth := bindingTestServer(t)
		ss := newTestSecretStore(map[string]string{"ref": token})
		v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
		err := v.ValidateMountPoint(context.Background(), &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: urlB, CredentialRef: "ref"}, ss)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fix)
		assert.NotContains(t, err.Error(), token)
		assert.False(t, sawAuth())
	})

	t.Run("bound credential is sent, also across host case and trailing slash", func(t *testing.T) {
		urlA, sawAuth := bindingTestServer(t)
		ss := newBoundTestSecretStore(map[string]string{"ref": token}, urlA)
		v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
		for _, u := range []string{urlA, strings.Replace(urlA, "localhost", "LOCALHOST", 1), urlA + "/"} {
			err := v.ValidateMountPoint(context.Background(), &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: u, CredentialRef: "ref"}, ss)
			// The server answers 401, so the call fails at the network step, not the binding.
			require.Error(t, err, u)
			assert.NotContains(t, err.Error(), "not bound", u)
		}
		assert.True(t, sawAuth(), "bound credential must reach the matching host")
	})
}

// TestCheckCredentialBinding_RealSopsStore proves a secret written with the binding
// metadata into the real sops store reads back and passes the binding check.
func TestCheckCredentialBinding_RealSopsStore(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, key, 0o600))

	store, err := sops.NewSOPSSecretStore(&sops.SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig:   map[string]interface{}{"root": filepath.Join(dir, "data")},
		KeyFile:         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	const repo = "https://git.cfgms.local/acme/configs"
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsiface.SecretRequest{
		Key:       ConfigSourceCredentialKeyName,
		Value:     "tok",
		Metadata:  map[string]string{SecretMetaKeyBoundRepositoryURL: NormalizeRepositoryURL(repo)},
		TenantID:  "tenant-a",
		CreatedBy: "test",
	}))
	got, err := store.GetSecret(ctx, "tenant-a/"+ConfigSourceCredentialKeyName)
	require.NoError(t, err)
	require.NoError(t, CheckCredentialBinding(got, repo))
	require.NoError(t, CheckCredentialBinding(got, "https://GIT.cfgms.local/acme/configs/"))
	require.Error(t, CheckCredentialBinding(got, "https://evil.cfgms.local/acme/configs"))
}

// TestValidateMountPoint_ResolvedBlockedAddressRejectedBeforeConnect verifies that a
// name resolving to a blocked address fails URL validation with no request sent.
func TestValidateMountPoint_ResolvedBlockedAddressRejectedBeforeConnect(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	repoURL := fmt.Sprintf("https://git.cfgms.local:%d/repo", port)

	v := NewDefaultMountPointValidator(WithInsecureSkipTLS(),
		WithHostResolver(&fakeResolver{addrs: ipAddrs("169.254.169.254")}))
	err := v.ValidateMountPoint(context.Background(), &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: repoURL}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL validation failed")
	assert.NotContains(t, err.Error(), "169.254.169.254")
	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, requests, "no connection may be attempted")
}

func TestValidateMountPoint_RejectsNonCanonicalNumericHosts(t *testing.T) {
	for _, h := range []string{"2130706433", "0177.0.0.1", "0x7f.1", "127.000.000.001"} {
		t.Run(h, func(t *testing.T) {
			v := NewDefaultMountPointValidator(WithHostResolver(&fakeResolver{addrs: ipAddrs("203.0.113.10")}))
			err := v.ValidateMountPoint(context.Background(), &ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: "https://" + h + "/repo"}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "URL validation failed")
		})
	}
}
