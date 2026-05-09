// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
)

// testSecretStore is a simple in-process secret store for validator tests.
// It is a real implementation (not a mock): it stores and returns secrets from a map.
type testSecretStore struct {
	secrets map[string]string
}

func newTestSecretStore(secrets map[string]string) *testSecretStore {
	return &testSecretStore{secrets: secrets}
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsiface.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsiface.ErrSecretNotFound
	}
	return &secretsiface.Secret{Key: key, Value: v}, nil
}

func (s *testSecretStore) StoreSecret(_ context.Context, _ *secretsiface.SecretRequest) error {
	return nil
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	repoURL := fmt.Sprintf("https://localhost:%d/repo", port)

	ss := newTestSecretStore(map[string]string{"mytoken": "super-secret-value"})

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
	const sensitiveToken = "ultra-sensitive-token-abc123"

	restore := installEmptyTransport(t) // always fails
	defer restore()

	ss := newTestSecretStore(map[string]string{"myref": sensitiveToken})

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
