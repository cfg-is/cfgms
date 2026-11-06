// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newGrantSecretStore opens a real SOPS secret store on the paths in the
// environment; calling it twice yields two independent instances over one store.
func newGrantSecretStore(t *testing.T) secretsif.SecretStore {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.ExternalURL = "https://localhost:8080"
	s, err := NewSecretStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newGrantStores returns two stores over the same durable config and secret storage.
func newGrantStores(t *testing.T) (*AutomationGrantStore, *AutomationGrantStore, string) {
	t.Helper()
	setTestSecretsEnv(t)
	sm := pkgtesting.SetupTestStorage(t)
	a, err := NewAutomationGrantStore(sm.GetConfigStore(), newGrantSecretStore(t))
	require.NoError(t, err)
	b, err := NewAutomationGrantStore(sm.GetConfigStore(), newGrantSecretStore(t))
	require.NoError(t, err)
	return a, b, os.Getenv("CFGMS_SECRETS_REPO_PATH")
}

func TestAutomationGrant_CreateGetAndCredential(t *testing.T) {
	store, _, _ := newGrantStores(t)
	ctx := context.Background()

	grant, cred, err := store.Create(ctx, "msp-a", "deploy", "admin-1", time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(cred, "cfgag_"+grant.ID+"_"))

	got, err := store.Get(ctx, "msp-a", grant.ID)
	require.NoError(t, err)
	assert.Equal(t, "deploy", got.Name)
	assert.Equal(t, "admin-1", got.CreatedBy)
	assert.False(t, got.Revoked())

	byCred, reason, err := store.GetByCredential(ctx, cred)
	require.NoError(t, err)
	assert.Empty(t, reason)
	assert.Equal(t, grant.ID, byCred.ID)
	assert.Equal(t, "msp-a", byCred.TenantID)
}

func TestAutomationGrant_PlaintextNeverPersisted(t *testing.T) {
	store, _, secretsRoot := newGrantStores(t)
	ctx := context.Background()
	_, cred, err := store.Create(ctx, "t1", "n", "u", time.Now().Add(time.Hour))
	require.NoError(t, err)
	// base64url secrets may contain '_', so split off only the id.
	parts := strings.SplitN(strings.TrimPrefix(cred, "cfgag_"), "_", 2)
	id, secret := parts[0], parts[1]

	entries, err := store.configs.ListConfigs(ctx, nil)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, string(e.Data), secret)
	}
	stored, err := store.getSecret(ctx, "t1", id)
	require.NoError(t, err)
	assert.Equal(t, hashAPIKey(secret), stored.Value)

	// Nothing under the secrets root contains the plaintext either.
	require.NoError(t, filepath.Walk(secretsRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(p) // #nosec G304 G122 -- test walks its own TempDir
		require.NoError(t, rerr)
		assert.NotContains(t, string(data), secret, p)
		return nil
	}))
}

func TestAutomationGrant_CreateValidation(t *testing.T) {
	store, _, _ := newGrantStores(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	cases := map[string]struct {
		tenant, name string
		exp          time.Time
	}{
		"empty tenant": {"", "n", future},
		"empty name":   {"t", "  ", future},
		"zero expiry":  {"t", "n", time.Time{}},
		"past expiry":  {"t", "n", time.Now().Add(-time.Minute)},
		"beyond cap":   {"t", "n", time.Now().Add(MaxGrantLifetime + time.Hour)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, cred, err := store.Create(ctx, c.tenant, c.name, "u", c.exp)
			require.ErrorIs(t, err, ErrInvalidGrantRequest)
			assert.Empty(t, cred)
		})
	}
	_, _, err := store.Create(ctx, "t", "n", "u", time.Now().Add(MaxGrantLifetime-time.Minute))
	assert.NoError(t, err, "an expiry just inside the cap is accepted")
}

func TestAutomationGrant_GetByCredentialRefusals(t *testing.T) {
	store, _, _ := newGrantStores(t)
	ctx := context.Background()

	grant, cred, err := store.Create(ctx, "t1", "n", "u", time.Now().Add(time.Hour))
	require.NoError(t, err)

	// Wrong secret on an existing id.
	_, reason, err := store.GetByCredential(ctx, "cfgag_"+grant.ID+"_wrongsecret")
	assert.ErrorIs(t, err, ErrInvalidGrantCredential)
	assert.Equal(t, GrantRejectSecret, reason)

	// Unknown id and malformed input.
	_, reason, err = store.GetByCredential(ctx, "cfgag_deadbeef_whatever")
	assert.ErrorIs(t, err, ErrInvalidGrantCredential)
	assert.Equal(t, GrantRejectUnknown, reason)
	for _, bad := range []string{"", "cfgag_", "cfgag_zz_x", "other_abc_def", "cfgag_abc"} {
		_, _, err = store.GetByCredential(ctx, bad)
		assert.ErrorIs(t, err, ErrInvalidGrantCredential, bad)
	}

	// Expired: advance the store's clock beyond the expiry.
	store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, reason, err = store.GetByCredential(ctx, cred)
	assert.ErrorIs(t, err, ErrInvalidGrantCredential)
	assert.Equal(t, GrantRejectExpired, reason)
	store.now = time.Now

	// Revoked.
	_, err = store.Revoke(ctx, "t1", grant.ID, "admin")
	require.NoError(t, err)
	_, reason, err = store.GetByCredential(ctx, cred)
	assert.ErrorIs(t, err, ErrInvalidGrantCredential)
	assert.Equal(t, GrantRejectRevoked, reason)

	// Every refusal is the same generic error text.
	assert.Equal(t, "invalid automation grant credential", err.Error())
}

// A revoke through one store instance is seen by another on its next call.
func TestAutomationGrant_RevokeVisibleToPeerStore(t *testing.T) {
	a, b, _ := newGrantStores(t)
	ctx := context.Background()

	grant, cred, err := a.Create(ctx, "t1", "n", "u", time.Now().Add(time.Hour))
	require.NoError(t, err)
	_, _, err = b.GetByCredential(ctx, cred)
	require.NoError(t, err)

	_, err = a.Revoke(ctx, "t1", grant.ID, "admin")
	require.NoError(t, err)

	_, _, err = b.GetByCredential(ctx, cred)
	assert.ErrorIs(t, err, ErrInvalidGrantCredential)
	got, err := b.Get(ctx, "t1", grant.ID)
	require.NoError(t, err)
	assert.True(t, got.Revoked())
	assert.Equal(t, "admin", got.RevokedBy)
}

// The subtree comes from real tenant records linked by ParentID (flat IDs, ADR-025
// Amendment 1), resolved by Server.tenantSubtreeIDs; "msp-ab" shares a string
// prefix with "msp-a" but is a sibling and must not be listed.
func TestAutomationGrant_ListSubtree(t *testing.T) {
	srv := setupTestServer(t)
	seedTenantTree(t, srv)
	store, _, _ := newGrantStores(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	for _, tn := range []string{"msp-a", "client-1", "msp-ab", "msp-b"} {
		_, _, err := store.Create(ctx, tn, "g", "u", exp)
		require.NoError(t, err)
	}

	listTenants := func(caller string) []string {
		var subtree []string
		for id := range srv.tenantSubtreeIDs(ctx, caller) {
			subtree = append(subtree, id)
		}
		got, err := store.List(ctx, subtree)
		require.NoError(t, err)
		var tenants []string
		for _, g := range got {
			tenants = append(tenants, g.TenantID)
		}
		return tenants
	}

	assert.ElementsMatch(t, []string{"msp-a", "client-1"}, listTenants("msp-a"))
	assert.ElementsMatch(t, []string{"client-1"}, listTenants("client-1"))
	assert.ElementsMatch(t, []string{"msp-a", "client-1", "msp-ab", "msp-b"}, listTenants(testRootTenantID))

	none, err := store.List(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestAutomationGrant_GetAndRevokeUnknown(t *testing.T) {
	store, _, _ := newGrantStores(t)
	ctx := context.Background()
	_, err := store.Get(ctx, "t1", "nope")
	assert.ErrorIs(t, err, ErrGrantNotFound)
	_, err = store.Revoke(ctx, "t1", "nope", "admin")
	assert.ErrorIs(t, err, ErrGrantNotFound)
	_, err = NewAutomationGrantStore(nil, nil)
	assert.Error(t, err)
}

func TestAutomationGrant_RevokeIsIdempotent(t *testing.T) {
	store, _, _ := newGrantStores(t)
	ctx := context.Background()
	grant, _, err := store.Create(ctx, "t1", "n", "u", time.Now().Add(time.Hour))
	require.NoError(t, err)
	first, err := store.Revoke(ctx, "t1", grant.ID, "admin-1")
	require.NoError(t, err)
	second, err := store.Revoke(ctx, "t1", grant.ID, "admin-2")
	require.NoError(t, err)
	assert.Equal(t, "admin-1", second.RevokedBy)
	assert.True(t, first.RevokedAt.Equal(*second.RevokedAt))
}
