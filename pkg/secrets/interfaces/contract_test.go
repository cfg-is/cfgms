// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Contract test for SecretStore.CompareAndSwapSecret (Issue #3775 / ADR-031 Decision
// 1). Runs the same semantics against every provider that can be exercised without
// external infrastructure: sops (flatfile, temp dir), steward (encrypted local
// files, temp dir), and oskeychain (real platform backend, skipped when this host
// offers none). OpenBao — the one ClusterCapable provider, and the only one with a
// genuine server-side check-and-set — requires a running OpenBao instance and is
// covered by the equivalent contract in
// pkg/secrets/providers/openbao/cas_test.go, gated by the existing
// "//go:build integration" convention store_test.go established for that provider.
package interfaces_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/oskeychain"
	"github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
)

// casProviderCase names one SecretStore provider to run the shared contract
// against. newStore returns a fresh, isolated store or an empty skip reason;
// when skip is non-empty the case is skipped rather than failed — matching the
// justified-skip convention this codebase already uses for infrastructure this
// specific host may not offer (e.g. steward's /etc/machine-id requirement,
// oskeychain's platform-backend requirement).
type casProviderCase struct {
	name       string
	newStore   func(t *testing.T) (secretsif.SecretStore, string /* skip reason */)
	newKeyPair func(t *testing.T) (key string, tenantID string)

	// honoursExpiry records whether this provider implements secret expiry at all.
	// The contract's "an expired secret does not exist" rule only has content for
	// providers that can produce an expired record; oskeychain has no notion of
	// expiry anywhere (StoreSecret ignores SecretRequest.TTL and no read path ever
	// refuses a record as expired), so the rule is vacuous there and the expiry
	// case is not run against it rather than asserted falsely.
	honoursExpiry bool
}

func newTestSecretsKeyFile(t *testing.T, dir string) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	return keyPath
}

func casProviderCases() []casProviderCase {
	return []casProviderCase{
		{
			name: "sops",
			newStore: func(t *testing.T) (secretsif.SecretStore, string) {
				base := t.TempDir()
				p := &sops.SOPSProvider{}
				store, err := p.CreateSecretStore(map[string]interface{}{
					"storage_provider": "flatfile",
					"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
					"cache_enabled":    false,
					"key_file":         newTestSecretsKeyFile(t, base),
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = store.Close() })
				return store, ""
			},
			newKeyPair: func(t *testing.T) (string, string) {
				return "cas-key", "tenant-a"
			},
			honoursExpiry: true,
		},
		{
			name: "steward",
			newStore: func(t *testing.T) (secretsif.SecretStore, string) {
				if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
					return nil, "skipping: /etc/machine-id not available (required for platform key derivation on Linux)"
				}
				p := &steward.StewardProvider{}
				store, err := p.CreateSecretStore(map[string]interface{}{
					"secrets_dir": t.TempDir(),
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = store.Close() })
				return store, ""
			},
			newKeyPair: func(t *testing.T) (string, string) {
				return "cas-key", "tenant-1"
			},
			honoursExpiry: true,
		},
		{
			name: "oskeychain",
			newStore: func(t *testing.T) (secretsif.SecretStore, string) {
				p := &oskeychain.Provider{}
				ok, _ := p.Available()
				if !ok {
					return nil, "no usable OS keychain backend on this host"
				}
				store, err := p.CreateSecretStore(nil)
				require.NoError(t, err)
				return store, ""
			},
			newKeyPair: func(t *testing.T) (string, string) {
				return "cfgms/session/contract-" + randContractHex(t, 8), ""
			},
			honoursExpiry: false,
		},
	}
}

func randContractHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

// storeKey builds the GetSecret-style lookup key for a (tenantID, key) pair —
// "tenantID/key" for providers that split tenant from key at the store boundary
// (sops), or just key for providers that do not (steward, oskeychain).
func storeKey(tenantID, key string) string {
	if tenantID == "" {
		return key
	}
	return tenantID + "/" + key
}

// TestCompareAndSwapSecret_Contract is the [REQUIRED TEST]: create-if-absent,
// version-mismatch rejection, and version chaining, run identically against
// every provider case above.
func TestCompareAndSwapSecret_Contract(t *testing.T) {
	for _, tc := range casProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			store, skip := tc.newStore(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()
			key, tenantID := tc.newKeyPair(t)
			lookupKey := storeKey(tenantID, key)

			// expectedVersion 0 against an absent key succeeds and returns version 1.
			v1, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
				Key: key, Value: "v1", TenantID: tenantID, CreatedBy: "test",
			})
			require.NoError(t, err)
			require.True(t, ok, "create-if-absent must succeed against a key that has never been written")
			assert.Equal(t, 1, v1)

			got, err := store.GetSecret(ctx, lookupKey)
			require.NoError(t, err)
			assert.Equal(t, "v1", got.Value)

			// A second create-if-absent against the now-existing key must lose — this
			// is the exact shape of two concurrent writers racing the same transition.
			_, ok, err = store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
				Key: key, Value: "attacker-value", TenantID: tenantID, CreatedBy: "test",
			})
			require.NoError(t, err, "a lost race must be ok=false with a nil error, never an error")
			assert.False(t, ok)

			got, err = store.GetSecret(ctx, lookupKey)
			require.NoError(t, err)
			assert.Equal(t, "v1", got.Value, "the losing write must never be observed")

			// The version returned by a successful CAS is exactly what the next CAS
			// must present.
			v2, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, v1, &secretsif.SecretRequest{
				Key: key, Value: "v2", TenantID: tenantID, CreatedBy: "test",
			})
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, 2, v2)

			got, err = store.GetSecret(ctx, lookupKey)
			require.NoError(t, err)
			assert.Equal(t, "v2", got.Value)
		})
	}
}

// TestCompareAndSwapSecret_Contract_ConcurrentRace proves exactly one of N
// concurrent create-if-absent CAS calls against the same key succeeds, for
// every provider case above.
func TestCompareAndSwapSecret_Contract_ConcurrentRace(t *testing.T) {
	for _, tc := range casProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			store, skip := tc.newStore(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()
			key, tenantID := tc.newKeyPair(t)
			lookupKey := storeKey(tenantID, key)

			const attempts = 8
			var wg sync.WaitGroup
			var successes int64
			wg.Add(attempts)
			for i := 0; i < attempts; i++ {
				go func() {
					defer wg.Done()
					_, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
						Key: key, Value: "value", TenantID: tenantID, CreatedBy: "test",
					})
					require.NoError(t, err)
					if ok {
						atomic.AddInt64(&successes, 1)
					}
				}()
			}
			wg.Wait()

			assert.Equal(t, int64(1), successes,
				"exactly one of N concurrent create-if-absent CAS calls for the same key must succeed")
		})
	}
}

// TestCompareAndSwapSecret_Contract_ExpiredSecretIsAbsent is the shared proof of the
// contract's expiry rule: a record past its ExpiresAt must be treated by
// CompareAndSwapSecret exactly as an absent one, so a create-if-absent takes it over.
//
// This is what makes a TTL-bounded claim recoverable. Every read path already refuses
// an expired record and no provider sweeps them, so a provider that let an expired
// record keep blocking expectedVersion 0 would strand its key permanently the moment
// a claiming process died before releasing — the credential-renewal claim (#3724)
// turning every later renewal of that serial into a 409 forever.
//
// The takeover must remain a compare-and-set: the version returned continues the
// record's own sequence rather than restarting at 1, so the crashed holder's stale
// version cannot win afterwards.
func TestCompareAndSwapSecret_Contract_ExpiredSecretIsAbsent(t *testing.T) {
	for _, tc := range casProviderCases() {
		if !tc.honoursExpiry {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			store, skip := tc.newStore(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()
			key, tenantID := tc.newKeyPair(t)
			lookupKey := storeKey(tenantID, key)

			v1, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
				Key: key, Value: "claim", TenantID: tenantID, CreatedBy: "crashed-holder",
				TTL: 20 * time.Millisecond,
			})
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, 1, v1)

			require.Eventually(t, func() bool {
				_, err := store.GetSecret(ctx, lookupKey)
				return err != nil
			}, time.Second, 5*time.Millisecond, "the record must become unreadable once its TTL elapses")

			v2, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
				Key: key, Value: "taken-over", TenantID: tenantID, CreatedBy: "retrier",
			})
			require.NoError(t, err)
			require.True(t, ok, "create-if-absent must take over an expired record, never be blocked by it")
			assert.Equal(t, 2, v2, "the takeover continues the record's version sequence")

			got, err := store.GetSecret(ctx, lookupKey)
			require.NoError(t, err)
			assert.Equal(t, "taken-over", got.Value)

			_, ok, err = store.CompareAndSwapSecret(ctx, lookupKey, v1, &secretsif.SecretRequest{
				Key: key, Value: "stale", TenantID: tenantID, CreatedBy: "crashed-holder",
			})
			require.NoError(t, err)
			assert.False(t, ok, "the crashed holder's stale version must not win after the takeover")
		})
	}
}

// TestCompareAndSwapSecret_Contract_ExpiredSecretRejectsNonZeroVersion is the other
// half of the expiry rule: an expired record must also fail a non-zero
// expectedVersion, not only yield to a create-if-absent.
//
// No reader can obtain a version for an expired record — every read path refuses it
// — so a caller presenting one is holding a version from before the expiry and is by
// definition stale. Accepting it would make "expired" mean absent for one caller and
// present for another against the very same record.
func TestCompareAndSwapSecret_Contract_ExpiredSecretRejectsNonZeroVersion(t *testing.T) {
	for _, tc := range casProviderCases() {
		if !tc.honoursExpiry {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			store, skip := tc.newStore(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()
			key, tenantID := tc.newKeyPair(t)
			lookupKey := storeKey(tenantID, key)

			v1, ok, err := store.CompareAndSwapSecret(ctx, lookupKey, 0, &secretsif.SecretRequest{
				Key: key, Value: "claim", TenantID: tenantID, CreatedBy: "holder",
				TTL: 20 * time.Millisecond,
			})
			require.NoError(t, err)
			require.True(t, ok)

			require.Eventually(t, func() bool {
				_, err := store.GetSecret(ctx, lookupKey)
				return err != nil
			}, time.Second, 5*time.Millisecond)

			_, ok, err = store.CompareAndSwapSecret(ctx, lookupKey, v1, &secretsif.SecretRequest{
				Key: key, Value: "stale-update", TenantID: tenantID, CreatedBy: "holder",
			})
			require.NoError(t, err, "a lost race must be ok=false with a nil error")
			assert.False(t, ok, "a non-zero expected version must not match an expired record")
		})
	}
}
