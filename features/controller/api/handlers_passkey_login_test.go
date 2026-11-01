// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #5066: passkey login finish and step-up finish must reload the account after the
// assertion verifies, refuse when the account was disabled or the signing credential was
// revoked in the meantime, and record the sign count with compare-and-swap so a refused
// write never resurrects a removed credential or clears the disabled flag.
//
// The concurrent admin write is a real write to the real secret store, performed from
// inside the store's own ListSecrets call so it lands after the handler's first read of
// the account and before its sign-count write. No component is mocked.
package api

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// racingSecretStore wraps the server's real secret store. After the fireOnList-th
// ListSecrets call returns, it runs hook once (simulating an administrator write racing
// the handler). With casAlwaysLoses it reports every CompareAndSwapSecret as a lost swap.
type racingSecretStore struct {
	secretsif.SecretStore

	mu            sync.Mutex
	fireOnList    int
	hook          func()
	casAlwaysLoss bool
	casCalls      int
}

func (r *racingSecretStore) ListSecrets(ctx context.Context, f *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	metas, err := r.SecretStore.ListSecrets(ctx, f)
	r.mu.Lock()
	var fire func()
	if r.hook != nil {
		r.fireOnList--
		if r.fireOnList == 0 {
			fire, r.hook = r.hook, nil
		}
	}
	r.mu.Unlock()
	if fire != nil {
		fire()
	}
	return metas, err
}

func (r *racingSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expected int, req *secretsif.SecretRequest) (int, bool, error) {
	r.mu.Lock()
	r.casCalls++
	lose := r.casAlwaysLoss
	r.mu.Unlock()
	if lose {
		return 0, false, nil
	}
	return r.SecretStore.CompareAndSwapSecret(ctx, key, expected, req)
}

// installRacingStore swaps the server's secret store for a racing wrapper.
func installRacingStore(t *testing.T, srv *Server) *racingSecretStore {
	t.Helper()
	rs := &racingSecretStore{SecretStore: srv.secretStore}
	srv.secretStore = rs
	return rs
}

// mutateStoredAccount applies mutate to the account as stored and persists it, as an
// administrator's write would.
func mutateStoredAccount(t *testing.T, srv *Server, username string, mutate func(a *account)) {
	t.Helper()
	a, err := srv.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	mutate(a)
	require.NoError(t, srv.persistAccount(context.Background(), a, "test-admin"))
}

func storedAccount(t *testing.T, srv *Server, username string) *account {
	t.Helper()
	a, err := srv.loadAccountFromStore(context.Background(), username, "")
	require.NoError(t, err)
	require.NotNil(t, a)
	return a
}

func TestPasskeyLoginFinish_CredentialRemovedDuringAssertion_Refused(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	// 1st ListSecrets is doPasskeyLogin's own lookup, 2nd is the handler's read.
	rs.fireOnList = 2
	rs.hook = func() {
		mutateStoredAccount(t, srv, username, func(a *account) { a.Credentials = nil })
	}

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies(), "no session may be issued")
	assert.Empty(t, storedAccount(t, srv, username).Credentials, "revoked credential must stay removed")
}

func TestPasskeyLoginFinish_AccountDisabledDuringAssertion_Refused(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	rs.fireOnList = 2
	rs.hook = func() {
		mutateStoredAccount(t, srv, username, func(a *account) { a.Disabled = true })
	}

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "WEBAUTHN_VERIFY_ERROR", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, rec.Result().Cookies(), "no session may be issued")
	assert.True(t, storedAccount(t, srv, username).Disabled, "account must stay disabled")
}

func TestPasskeyLoginFinish_SwapKeepsLosing_RefusedAfterOneRetry(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)
	rs := installRacingStore(t, srv)
	rs.casAlwaysLoss = true

	rec := doPasskeyLogin(t, srv, username, "")

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
	rs.mu.Lock()
	calls := rs.casCalls
	rs.mu.Unlock()
	assert.Equal(t, 2, calls, "one attempt plus exactly one retry")
	creds := storedAccount(t, srv, username).Credentials
	require.Len(t, creds, 1)
	assert.Zero(t, creds[0].SignCount, "nothing may be written")
}

func TestPasskeyLoginFinish_Success_UpdatesCacheVersion(t *testing.T) {
	srv, username := setupPasskeySessionServer(t)

	rec := doPasskeyLogin(t, srv, username, "")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	srv.mu.RLock()
	cached := srv.accounts[username]
	srv.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, storedAccount(t, srv, username).Version, cached.Version)
}
