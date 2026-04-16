// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	sopspkg "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/stretchr/testify/require"
)

// errUnknownKey is a sentinel returned by mockLeasedStore for unknown lease IDs and keys,
// allowing error-path tests to verify the interface propagates errors correctly.
var errUnknownKey = errors.New("unknown key or lease ID")

// mockLeasedStore is a minimal in-process implementation of both SecretStore and LeasedSecret
// used exclusively to verify the type-assertion dispatch pattern and interface mechanics.
//
// No real vault-class LeasedSecret provider exists in the codebase yet (OpenBao, AWS Secrets
// Manager, and Azure Key Vault are planned — see pkg/secrets/interfaces/README.md). Until one
// is available, this concrete type is the only way to exercise the LeasedSecret interface
// surface; it is not replacing a real CFGMS component. The non-implementation tests below
// (SOPS, steward) use real providers.
type mockLeasedStore struct {
	noopSecretStore
	leases map[string]*interfaces.Lease
}

func newMockLeasedStore() *mockLeasedStore {
	return &mockLeasedStore{
		leases: make(map[string]*interfaces.Lease),
	}
}

func (m *mockLeasedStore) LeaseSecret(_ context.Context, key string, req *interfaces.LeaseRequest) (*interfaces.Secret, *interfaces.Lease, error) {
	if key == "" {
		return nil, nil, errUnknownKey
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = time.Hour // provider default
	}
	lease := &interfaces.Lease{
		ID:        "lease-" + key,
		TTL:       ttl,
		Renewable: req.Renewable,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}
	m.leases[lease.ID] = lease
	return &interfaces.Secret{Key: key}, lease, nil
}

func (m *mockLeasedStore) RenewLease(_ context.Context, leaseID string, increment time.Duration) (*interfaces.Lease, error) {
	lease, ok := m.leases[leaseID]
	if !ok {
		return nil, errUnknownKey
	}
	lease.TTL = increment
	lease.ExpiresAt = time.Now().Add(increment)
	return lease, nil
}

func (m *mockLeasedStore) RevokeLease(_ context.Context, leaseID string) error {
	if _, ok := m.leases[leaseID]; !ok {
		return errUnknownKey
	}
	delete(m.leases, leaseID)
	return nil
}

// noopSecretStore is a no-operation base that satisfies interfaces.SecretStore so that
// mockLeasedStore can embed it. Its methods return zero values; they are never called
// directly in the tests below — only the LeasedSecret methods are under test.
type noopSecretStore struct{}

func (n *noopSecretStore) StoreSecret(_ context.Context, _ *interfaces.SecretRequest) error {
	return nil
}
func (n *noopSecretStore) GetSecret(_ context.Context, _ string) (*interfaces.Secret, error) {
	return nil, nil
}
func (n *noopSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (n *noopSecretStore) ListSecrets(_ context.Context, _ *interfaces.SecretFilter) ([]*interfaces.SecretMetadata, error) {
	return nil, nil
}
func (n *noopSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*interfaces.Secret, error) {
	return nil, nil
}
func (n *noopSecretStore) StoreSecrets(_ context.Context, _ map[string]*interfaces.SecretRequest) error {
	return nil
}
func (n *noopSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*interfaces.Secret, error) {
	return nil, nil
}
func (n *noopSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*interfaces.SecretVersion, error) {
	return nil, nil
}
func (n *noopSecretStore) GetSecretMetadata(_ context.Context, _ string) (*interfaces.SecretMetadata, error) {
	return nil, nil
}
func (n *noopSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (n *noopSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (n *noopSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (n *noopSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (n *noopSecretStore) Close() error                                             { return nil }

// TestLeasedSecret_TypeAssertionPattern verifies that the type-assertion guard pattern
// works correctly for vault-class stores, and that the three LeasedSecret methods are
// callable through the interface — including their error paths.
func TestLeasedSecret_TypeAssertionPattern(t *testing.T) {
	var store interfaces.SecretStore = newMockLeasedStore()

	ls, ok := store.(interfaces.LeasedSecret)
	require.True(t, ok, "mockLeasedStore must satisfy interfaces.LeasedSecret")
	require.NotNil(t, ls)

	ctx := context.Background()

	t.Run("happy path: lease, renew, revoke", func(t *testing.T) {
		secret, lease, err := ls.LeaseSecret(ctx, "db/creds", &interfaces.LeaseRequest{
			TTL:       time.Hour,
			Renewable: true,
		})
		require.NoError(t, err)
		require.NotNil(t, secret)
		require.Equal(t, "db/creds", secret.Key)
		require.NotNil(t, lease)
		require.Equal(t, "lease-db/creds", lease.ID)
		require.Equal(t, time.Hour, lease.TTL)
		require.True(t, lease.Renewable)
		require.False(t, lease.ExpiresAt.IsZero())

		renewed, err := ls.RenewLease(ctx, lease.ID, 30*time.Minute)
		require.NoError(t, err)
		require.NotNil(t, renewed)
		require.Equal(t, 30*time.Minute, renewed.TTL)

		err = ls.RevokeLease(ctx, lease.ID)
		require.NoError(t, err)
	})

	t.Run("error path: LeaseSecret with empty key", func(t *testing.T) {
		_, _, err := ls.LeaseSecret(ctx, "", &interfaces.LeaseRequest{TTL: time.Hour})
		require.Error(t, err, "LeaseSecret must propagate error for empty key")
		require.ErrorIs(t, err, errUnknownKey)
	})

	t.Run("error path: RenewLease with unknown lease ID", func(t *testing.T) {
		_, err := ls.RenewLease(ctx, "nonexistent-lease-id", time.Hour)
		require.Error(t, err, "RenewLease must propagate error for unknown lease ID")
		require.ErrorIs(t, err, errUnknownKey)
	})

	t.Run("error path: RevokeLease with unknown lease ID", func(t *testing.T) {
		err := ls.RevokeLease(ctx, "nonexistent-lease-id")
		require.Error(t, err, "RevokeLease must propagate error for unknown lease ID")
		require.ErrorIs(t, err, errUnknownKey)
	})

	t.Run("default TTL applied when zero", func(t *testing.T) {
		_, lease, err := ls.LeaseSecret(ctx, "iam/role", &interfaces.LeaseRequest{
			TTL:       0, // zero means use provider default
			Renewable: false,
		})
		require.NoError(t, err)
		require.Greater(t, lease.TTL, time.Duration(0), "provider must apply a non-zero default TTL")
	})
}

// TestSOPSStore_DoesNotImplementLeasedSecret verifies that the static-secret SOPS provider
// does not satisfy the LeasedSecret mixin.
func TestSOPSStore_DoesNotImplementLeasedSecret(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := sopspkg.NewSOPSSecretStore(&sopspkg.SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig: map[string]interface{}{
			"root": tmpDir,
		},
		CacheEnabled: false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	var secretStore interfaces.SecretStore = store
	_, ok := secretStore.(interfaces.LeasedSecret)
	require.False(t, ok, "SOPSSecretStore must NOT implement interfaces.LeasedSecret (static-secret provider)")
}

// TestStewardStore_DoesNotImplementLeasedSecret verifies that the static-secret steward provider
// does not satisfy the LeasedSecret mixin.
func TestStewardStore_DoesNotImplementLeasedSecret(t *testing.T) {
	// The steward provider requires /etc/machine-id for platform key derivation on Linux.
	// Skip when it is absent or unreadable (e.g., minimal containers without systemd).
	if _, err := os.Stat("/etc/machine-id"); err != nil {
		t.Skip("skipping: /etc/machine-id not available or not readable (required for steward platform key derivation)")
	}

	tmpDir := t.TempDir()

	provider := &steward.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": tmpDir,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, ok := store.(interfaces.LeasedSecret)
	require.False(t, ok, "StewardSecretStore must NOT implement interfaces.LeasedSecret (static-secret provider)")
}

// TestLease_JSONRoundTrip verifies Lease serialises and deserialises correctly.
func TestLease_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	original := interfaces.Lease{
		ID:        "vault-lease-abc123",
		TTL:       2 * time.Hour,
		Renewable: true,
		IssuedAt:  now,
		ExpiresAt: now.Add(2 * time.Hour),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded interfaces.Lease
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Equal(t, original.ID, decoded.ID)
	require.Equal(t, original.TTL, decoded.TTL)
	require.Equal(t, original.Renewable, decoded.Renewable)
	require.True(t, original.IssuedAt.Equal(decoded.IssuedAt), "IssuedAt mismatch")
	require.True(t, original.ExpiresAt.Equal(decoded.ExpiresAt), "ExpiresAt mismatch")
}

// TestLeaseRequest_JSONRoundTrip verifies LeaseRequest serialises and deserialises correctly.
func TestLeaseRequest_JSONRoundTrip(t *testing.T) {
	t.Run("with parameters", func(t *testing.T) {
		original := interfaces.LeaseRequest{
			TTL:       30 * time.Minute,
			Renewable: true,
			Parameters: map[string]any{
				"role":       "read-only",
				"ttl_max":    "1h",
				"max_leases": float64(5), // JSON numbers unmarshal as float64
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded interfaces.LeaseRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.Equal(t, original.TTL, decoded.TTL)
		require.Equal(t, original.Renewable, decoded.Renewable)
		require.Equal(t, "read-only", decoded.Parameters["role"])
		require.Equal(t, "1h", decoded.Parameters["ttl_max"])
		require.Equal(t, float64(5), decoded.Parameters["max_leases"])
	})

	t.Run("zero value", func(t *testing.T) {
		original := interfaces.LeaseRequest{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded interfaces.LeaseRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.Equal(t, time.Duration(0), decoded.TTL)
		require.False(t, decoded.Renewable)
		require.Nil(t, decoded.Parameters)
	})
}

// TestSecretMetadata_Policy_JSONRoundTrip verifies the Policy field added to SecretMetadata
// serialises correctly with and without a value.
func TestSecretMetadata_Policy_JSONRoundTrip(t *testing.T) {
	t.Run("without policy", func(t *testing.T) {
		m := interfaces.SecretMetadata{
			Key:     "api/key",
			Version: 1,
		}
		data, err := json.Marshal(m)
		require.NoError(t, err)

		// policy field must be absent when nil (omitempty)
		require.NotContains(t, string(data), "policy")

		var decoded interfaces.SecretMetadata
		require.NoError(t, json.Unmarshal(data, &decoded))
		require.Nil(t, decoded.Policy)
	})

	t.Run("with policy", func(t *testing.T) {
		m := interfaces.SecretMetadata{
			Key:     "api/key",
			Version: 2,
			Policy: map[string]any{
				"ttl":        "24h",
				"max_leases": float64(10), // JSON numbers unmarshal as float64
				"bound_ips":  []any{"10.0.0.0/8"},
			},
		}
		data, err := json.Marshal(m)
		require.NoError(t, err)
		require.Contains(t, string(data), "policy")

		var decoded interfaces.SecretMetadata
		require.NoError(t, json.Unmarshal(data, &decoded))
		require.NotNil(t, decoded.Policy)
		require.Equal(t, "24h", decoded.Policy["ttl"])
		require.Equal(t, float64(10), decoded.Policy["max_leases"])
		require.NotEmpty(t, decoded.Policy["bound_ips"])
	})
}
