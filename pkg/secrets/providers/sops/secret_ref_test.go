// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// TestSecretRefSplits verifies every reading of a combined reference is offered,
// leftmost separator first (Issue #4574).
func TestSecretRefSplits(t *testing.T) {
	assert.Equal(t, [][2]string{{"a", "b/c"}, {"a/b", "c"}}, secretRefSplits("a/b/c"))
	assert.Equal(t, [][2]string{{"tenant-a", "k1"}}, secretRefSplits("tenant-a/k1"))
	assert.Empty(t, secretRefSplits("no-separator"))
	assert.Empty(t, secretRefSplits("/k1"))
	assert.Empty(t, secretRefSplits("tenant-a/"))
}

// slashNameConfigStore adapts the real flatfile ConfigStore to a backend whose config
// names may contain "/" (as the PostgreSQL backend's may): names are escaped on the
// way in and unescaped on the way out. Everything else is the flatfile store.
type slashNameConfigStore struct {
	cfgconfig.ConfigStore
}

func escapeName(n string) string   { return strings.ReplaceAll(n, "/", "~2F") }
func unescapeName(n string) string { return strings.ReplaceAll(n, "~2F", "/") }

func escapedKey(k *cfgconfig.ConfigKey) *cfgconfig.ConfigKey {
	c := *k
	c.Name = escapeName(k.Name)
	return &c
}

func unescapeEntry(e *cfgconfig.ConfigEntry) *cfgconfig.ConfigEntry {
	if e != nil && e.Key != nil {
		e.Key.Name = unescapeName(e.Key.Name)
	}
	return e
}

func (s *slashNameConfigStore) StoreConfig(ctx context.Context, e *cfgconfig.ConfigEntry) error {
	c := *e
	c.Key = escapedKey(e.Key)
	return s.ConfigStore.StoreConfig(ctx, &c)
}

func (s *slashNameConfigStore) GetConfig(ctx context.Context, k *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	e, err := s.ConfigStore.GetConfig(ctx, escapedKey(k))
	return unescapeEntry(e), err
}

func (s *slashNameConfigStore) DeleteConfig(ctx context.Context, k *cfgconfig.ConfigKey) error {
	return s.ConfigStore.DeleteConfig(ctx, escapedKey(k))
}

func (s *slashNameConfigStore) ListConfigs(ctx context.Context, f *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	out, err := s.ConfigStore.ListConfigs(ctx, f)
	for _, e := range out {
		unescapeEntry(e)
	}
	return out, err
}

func newSlashNameSOPSStore(t *testing.T) *SOPSSecretStore {
	t.Helper()
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))
	store.configStore = &slashNameConfigStore{ConfigStore: store.configStore}
	return store
}

// TestSlashKey_TopLevelTenant_StillResolves is the regression guard for keys that
// contain "/" (the m365 credential layout): under a top-level tenant the leftmost
// reading — the historical split — still finds them (Issue #4574).
func TestSlashKey_TopLevelTenant_StillResolves(t *testing.T) {
	store := newSlashNameSOPSStore(t)
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{
		Key: "m365/tid-1/token", Value: "tok", TenantID: "acme",
	}))

	got, err := store.GetSecret(ctx, "acme/m365/tid-1/token")
	require.NoError(t, err)
	assert.Equal(t, "tok", got.Value)
	assert.Equal(t, "acme", got.TenantID)

	require.NoError(t, store.DeleteSecret(ctx, "acme/m365/tid-1/token"))
	_, err = store.GetSecret(ctx, "acme/m365/tid-1/token")
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound), "got %v", err)
}

// TestSlashKey_NestedTenant_GetAndDelete verifies a "/"-containing key under a nested
// tenant resolves: the reference is ambiguous as a string and is resolved against
// the store (Issue #4574).
func TestSlashKey_NestedTenant_GetAndDelete(t *testing.T) {
	store := newSlashNameSOPSStore(t)
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{
		Key: "m365/tid-1/delegated/user-1", Value: "tok", TenantID: "msp-a/client-1",
	}))

	const ref = "msp-a/client-1/m365/tid-1/delegated/user-1"
	got, err := store.GetSecret(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "tok", got.Value)
	assert.Equal(t, "msp-a/client-1", got.TenantID)

	require.NoError(t, store.DeleteSecret(ctx, ref))
	_, err = store.GetSecret(ctx, ref)
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound), "got %v", err)
	assert.True(t, errors.Is(store.DeleteSecret(ctx, ref), secretsif.ErrSecretNotFound))
}

// TestTenantSecretAccessor_ExplicitTenant verifies the tenant-explicit path reads and
// deletes without any reference resolution, and reports a miss as ErrSecretNotFound.
func TestTenantSecretAccessor_ExplicitTenant(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))
	ctx := context.Background()
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: "k1", Value: "v1", TenantID: "msp-a/client-1"}))

	got, err := store.GetTenantSecret(ctx, "msp-a/client-1", "k1")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)

	require.NoError(t, store.DeleteTenantSecret(ctx, "msp-a/client-1", "k1"))
	_, err = store.GetTenantSecret(ctx, "msp-a/client-1", "k1")
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound), "got %v", err)
}

// TestNestedTenantSecret_GetAndDelete verifies a secret in a nested tenant can be read
// and deleted by its "<tenant>/<key>" reference (Issue #4574).
func TestNestedTenantSecret_GetAndDelete(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))
	ctx := context.Background()

	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{
		Key: "k1", Value: "v1", TenantID: "msp-a/client-1",
	}))

	got, err := store.GetSecret(ctx, "msp-a/client-1/k1")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
	assert.Equal(t, "msp-a/client-1", got.TenantID)

	require.NoError(t, store.DeleteSecret(ctx, "msp-a/client-1/k1"))
	_, err = store.GetSecret(ctx, "msp-a/client-1/k1")
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound), "got %v", err)
}

// TestListSecrets_SkipsUndecryptableRecord verifies one record this store cannot
// decrypt (written under a different key) is skipped by a listing rather than failing
// it, while a direct read of that record still fails (Issue #4574).
func TestListSecrets_SkipsUndecryptableRecord(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	store := newTestSOPSStore(t, dataRoot, writeTestKey(t, t.TempDir()))
	foreign := newTestSOPSStore(t, dataRoot, writeTestKey(t, t.TempDir()))
	ctx := context.Background()

	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: "mine", Value: "v", TenantID: "tenant-a"}))
	require.NoError(t, foreign.StoreSecret(ctx, &secretsif.SecretRequest{Key: "foreign", Value: "v", TenantID: "tenant-a"}))

	list, err := store.ListSecrets(ctx, &secretsif.SecretFilter{TenantID: "tenant-a"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "mine", list[0].Key)

	_, err = store.GetSecret(ctx, "tenant-a/foreign")
	assert.Error(t, err, "a direct read must still fail closed")
}

// TestListSecrets_KeyPrefixFiltersByName verifies a KeyPrefix listing, filtered by
// record name before any decrypt, returns only the matching record across tenants.
func TestListSecrets_KeyPrefixFiltersByName(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	store := newTestSOPSStore(t, dataRoot, writeTestKey(t, t.TempDir()))
	ctx := context.Background()

	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: "abc123", Value: "v", TenantID: "tenant-a"}))
	require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{Key: "zzz999", Value: "v", TenantID: "tenant-b"}))

	list, err := store.ListSecrets(ctx, &secretsif.SecretFilter{KeyPrefix: "abc"})
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "abc123", list[0].Key)
	assert.Equal(t, "tenant-a", list[0].TenantID)
}

// TestFlatfileBackend_RejectsSlashInSecretName pins the assumption resolveSecretRef's
// leftmost-first order relies on: the flatfile backend refuses a "/" in a secret
// name, so a record named "b/<k>" under tenant "a" can never shadow tenant "a/b"'s
// "<k>" there.
func TestFlatfileBackend_RejectsSlashInSecretName(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))
	err := store.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key: "child/k1", Value: "v", TenantID: "tenant-a",
	})
	require.Error(t, err, "flatfile must reject a secret name containing '/'")
}
