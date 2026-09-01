// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// These tests exercise the storage provider registry and the storage-manager
// factories against the real OSS providers (flat-file and SQLite). They live in
// the external interfaces_test package because pkg/storage/providers/* imports
// pkg/storage/interfaces — an in-package test cannot import a real provider
// without forming an import cycle. Registry internals are reached through the
// RegistrySnapshot / RegistryReplace helpers in export_test.go.
package interfaces_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// withEmptyRegistry empties the global provider registry for the duration of the
// test and restores the original contents on cleanup.
func withEmptyRegistry(t *testing.T) {
	t.Helper()
	original := interfaces.RegistrySnapshot()
	interfaces.RegistryReplace(nil)
	t.Cleanup(func() { interfaces.RegistryReplace(original) })
}

// ossConfigs returns per-test provider configurations: a flat-file root and a
// SQLite database file, both under t.TempDir().
func ossConfigs(t *testing.T) (flatfileCfg, sqliteCfg map[string]interface{}) {
	t.Helper()
	return map[string]interface{}{"root": t.TempDir()},
		map[string]interface{}{"path": filepath.Join(t.TempDir(), "test.db")}
}

// Test provider registration
func TestRegisterStorageProvider(t *testing.T) {
	withEmptyRegistry(t)

	provider := newFlatFileProvider()
	interfaces.RegisterStorageProvider(provider)

	// Verify registration
	names := interfaces.GetRegisteredProviderNames()
	if len(names) != 1 || names[0] != "flatfile" {
		t.Errorf("Expected provider 'flatfile' to be registered, got: %v", names)
	}

	// Test getting the provider
	retrieved, err := interfaces.GetStorageProvider("flatfile")
	if err != nil {
		t.Errorf("Failed to get registered provider: %v", err)
	}

	if retrieved.Name() != "flatfile" {
		t.Errorf("Expected provider name 'flatfile', got: %s", retrieved.Name())
	}
}

func TestRegisterStorageProviderWithValidation(t *testing.T) {
	withEmptyRegistry(t)

	_, sqliteCfg := ossConfigs(t)

	err := interfaces.RegisterStorageProviderWithValidation(newSQLiteProvider(), sqliteCfg)
	if err != nil {
		t.Errorf("Failed to register provider with validation: %v", err)
	}

	// Verify registration
	names := interfaces.GetRegisteredProviderNames()
	if len(names) != 1 || names[0] != "sqlite" {
		t.Errorf("Expected provider 'sqlite' to be registered, got: %v", names)
	}
}

// closeCountingProvider wraps a real StorageProvider and counts how many of
// the stores it creates are later closed. It delegates every Create*Store
// call to the wrapped real provider (so sqlite performs real I/O) and only
// instruments the returned store's Close method — it fakes nothing about
// store behavior.
type closeCountingProvider struct {
	interfaces.StorageProvider
	closes int
}

func (p *closeCountingProvider) CreateClientTenantStore(config map[string]interface{}) (business.ClientTenantStore, error) {
	store, err := p.StorageProvider.CreateClientTenantStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingClientTenantStore{ClientTenantStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateAuditStore(config map[string]interface{}) (business.AuditStore, error) {
	store, err := p.StorageProvider.CreateAuditStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingAuditStore{AuditStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateRBACStore(config map[string]interface{}) (business.RBACStore, error) {
	store, err := p.StorageProvider.CreateRBACStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingRBACStore{RBACStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateTenantStore(config map[string]interface{}) (business.TenantStore, error) {
	store, err := p.StorageProvider.CreateTenantStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingTenantStore{TenantStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateRegistrationTokenStore(config map[string]interface{}) (business.RegistrationTokenStore, error) {
	store, err := p.StorageProvider.CreateRegistrationTokenStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingRegistrationTokenStore{RegistrationTokenStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateStewardStore(config map[string]interface{}) (business.StewardStore, error) {
	store, err := p.StorageProvider.CreateStewardStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingStewardStore{StewardStore: store, p: p}, nil
}

func (p *closeCountingProvider) CreateTriggerStore(config map[string]interface{}) (business.TriggerStore, error) {
	store, err := p.StorageProvider.CreateTriggerStore(config)
	if err != nil {
		return store, err
	}
	return closeCountingTriggerStore{TriggerStore: store, p: p}, nil
}

type closeCountingClientTenantStore struct {
	business.ClientTenantStore
	p *closeCountingProvider
}

func (s closeCountingClientTenantStore) Close() error {
	s.p.closes++
	return s.ClientTenantStore.Close()
}

type closeCountingAuditStore struct {
	business.AuditStore
	p *closeCountingProvider
}

func (s closeCountingAuditStore) Close() error {
	s.p.closes++
	return s.AuditStore.Close()
}

type closeCountingRBACStore struct {
	business.RBACStore
	p *closeCountingProvider
}

func (s closeCountingRBACStore) Close() error {
	s.p.closes++
	return s.RBACStore.Close()
}

type closeCountingTenantStore struct {
	business.TenantStore
	p *closeCountingProvider
}

func (s closeCountingTenantStore) Close() error {
	s.p.closes++
	return s.TenantStore.Close()
}

type closeCountingRegistrationTokenStore struct {
	business.RegistrationTokenStore
	p *closeCountingProvider
}

func (s closeCountingRegistrationTokenStore) Close() error {
	s.p.closes++
	return s.RegistrationTokenStore.Close()
}

type closeCountingStewardStore struct {
	business.StewardStore
	p *closeCountingProvider
}

func (s closeCountingStewardStore) Close() error {
	s.p.closes++
	return s.StewardStore.Close()
}

type closeCountingTriggerStore struct {
	business.TriggerStore
	p *closeCountingProvider
}

func (s closeCountingTriggerStore) Close() error {
	s.p.closes++
	return s.TriggerStore.Close()
}

// TestRegisterStorageProviderWithValidation_ClosesValidationStores guards
// against the Windows-only CI failure diagnosed against PR #3254: validation
// creates seven stores (ClientTenantStore, AuditStore, RBACStore, TenantStore,
// RegistrationTokenStore, StewardStore, TriggerStore) purely to prove
// Create*Store succeeds, then discarded them without closing. On Linux a
// leaked *sql.DB handle is invisible because the OS allows unlinking an open
// file; on Windows the leaked handle keeps the file locked, so a caller's
// later cleanup (t.TempDir() in this suite) fails with "the process cannot
// access the file because it is being used by another process." Real sqlite
// I/O runs through the wrapped provider; only Close() is instrumented.
func TestRegisterStorageProviderWithValidation_ClosesValidationStores(t *testing.T) {
	withEmptyRegistry(t)

	_, sqliteCfg := ossConfigs(t)
	provider := &closeCountingProvider{StorageProvider: newSQLiteProvider()}

	require.NoError(t, interfaces.RegisterStorageProviderWithValidation(provider, sqliteCfg))

	assert.Equal(t, 7, provider.closes, "RegisterStorageProviderWithValidation must close every validation store it creates")
}

// TestValidateProvider verifies that the real OSS providers satisfy the
// registration rules and that a nil provider is rejected.
func TestValidateProvider(t *testing.T) {
	providers := map[string]interfaces.StorageProvider{
		"flatfile": newFlatFileProvider(),
		"sqlite":   newSQLiteProvider(),
	}
	for name, provider := range providers {
		t.Run(name+" is valid", func(t *testing.T) {
			require.NoError(t, interfaces.ValidateProvider(provider))
		})
	}

	t.Run("nil provider is rejected", func(t *testing.T) {
		require.Error(t, interfaces.ValidateProvider(nil))
	})
}

// TestValidateProviderMetadata covers the registration rules a provider's
// declared metadata must satisfy. The rules are evaluated as data, so no
// implementation of StorageProvider is needed to reach the rejection paths.
func TestValidateProviderMetadata(t *testing.T) {
	validCaps := interfaces.ProviderCapabilities{
		MaxBatchSize:          100,
		MaxConfigSize:         1024 * 1024,
		MaxAuditRetentionDays: 365,
	}

	tests := []struct {
		name         string
		providerName string
		description  string
		version      string
		capabilities interfaces.ProviderCapabilities
		expectError  bool
	}{
		{
			name:         "valid metadata",
			providerName: "test",
			description:  "test provider",
			version:      "1.0.0",
			capabilities: validCaps,
			expectError:  false,
		},
		{
			name:         "empty name",
			providerName: "",
			description:  "test",
			version:      "1.0.0",
			capabilities: validCaps,
			expectError:  true,
		},
		{
			name:         "empty description",
			providerName: "test",
			description:  "",
			version:      "1.0.0",
			capabilities: validCaps,
			expectError:  true,
		},
		{
			name:         "empty version",
			providerName: "test",
			description:  "test",
			version:      "",
			capabilities: validCaps,
			expectError:  true,
		},
		{
			name:         "negative batch size",
			providerName: "test",
			description:  "test",
			version:      "1.0.0",
			capabilities: interfaces.ProviderCapabilities{MaxBatchSize: -1},
			expectError:  true,
		},
		{
			name:         "negative config size",
			providerName: "test",
			description:  "test",
			version:      "1.0.0",
			capabilities: interfaces.ProviderCapabilities{MaxConfigSize: -1},
			expectError:  true,
		},
		{
			name:         "negative audit retention",
			providerName: "test",
			description:  "test",
			version:      "1.0.0",
			capabilities: interfaces.ProviderCapabilities{MaxAuditRetentionDays: -1},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := interfaces.ValidateProviderMetadata(tt.providerName, tt.description, tt.version, tt.capabilities)
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error, got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestCreateAllStoresFromConfig(t *testing.T) {
	t.Run("sqlite provider supplies the business-data tier", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegisterStorageProvider(newSQLiteProvider())

		_, sqliteCfg := ossConfigs(t)
		manager, err := interfaces.CreateAllStoresFromConfig("sqlite", sqliteCfg)
		if err != nil {
			t.Fatalf("Failed to create storage manager: %v", err)
		}
		t.Cleanup(func() { _ = manager.Close() })

		if manager.GetProviderName() != "sqlite" {
			t.Errorf("Expected provider name 'sqlite', got: %s", manager.GetProviderName())
		}

		ctStore := manager.GetClientTenantStore()
		if ctStore == nil {
			t.Fatal("ClientTenantStore should not be nil")
		}
		// Round-trip: store a tenant and verify retrieval returns the same value.
		want := &business.ClientTenant{ID: "rt-tenant-1", TenantID: "rt-tenant-1", TenantName: "Round Trip Tenant"}
		if err := ctStore.StoreClientTenant(want); err != nil {
			t.Fatalf("StoreClientTenant failed: %v", err)
		}
		got, err := ctStore.GetClientTenant("rt-tenant-1")
		if err != nil {
			t.Fatalf("GetClientTenant failed: %v", err)
		}
		if got.ID != want.ID || got.TenantName != want.TenantName {
			t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
		}

		if manager.GetAuditStore() == nil {
			t.Errorf("AuditStore should not be nil")
		}
		if manager.GetRBACStore() == nil {
			t.Errorf("RBACStore should not be nil")
		}
		// SQLite does not serve config data (ADR-003) — it reports ErrNotSupported,
		// which the factory tolerates by leaving the slot nil.
		if manager.GetConfigStore() != nil {
			t.Errorf("ConfigStore should be nil for the SQLite provider")
		}

		// Issue #3755: single-provider mode must wire the durable nonce store from
		// the named provider. A nil store here means every registration-refresh
		// challenge/complete request answers 503 in this deployment shape.
		nonceStore := manager.GetNonceStore()
		if nonceStore == nil {
			t.Fatal("NonceStore should not be nil for the SQLite provider")
		}
		ctx := context.Background()
		const nonceKey = "refresh-nonce:all-stores"
		if err := nonceStore.PutNonce(ctx, nonceKey, []byte("challenge"), time.Minute); err != nil {
			t.Fatalf("PutNonce failed: %v", err)
		}
		entry, found, err := nonceStore.GetAndConsumeNonce(ctx, nonceKey)
		if err != nil {
			t.Fatalf("GetAndConsumeNonce failed: %v", err)
		}
		if !found || string(entry) != "challenge" {
			t.Fatalf("nonce round-trip mismatch: found=%v entry=%q", found, entry)
		}
	})

	t.Run("unregistered provider name returns an error", func(t *testing.T) {
		withEmptyRegistry(t)

		_, err := interfaces.CreateAllStoresFromConfig("nonexistent", nil)
		if err == nil {
			t.Fatal("expected an error for an unregistered provider name")
		}
	})
}

func TestConfigKeyString(t *testing.T) {
	tests := []struct {
		name     string
		key      *cfgconfig.ConfigKey
		expected string
	}{
		{
			name: "with scope",
			key: &cfgconfig.ConfigKey{
				TenantID:  "tenant1",
				Namespace: "templates",
				Name:      "firewall",
				Scope:     "device1",
			},
			expected: "tenant1/templates/firewall@device1",
		},
		{
			name: "without scope",
			key: &cfgconfig.ConfigKey{
				TenantID:  "tenant1",
				Namespace: "certificates",
				Name:      "root-ca",
			},
			expected: "tenant1/certificates/root-ca",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestListProvidersV2(t *testing.T) {
	withEmptyRegistry(t)

	provider := newFlatFileProvider()
	interfaces.RegisterStorageProvider(provider)

	providers := interfaces.ListProvidersV2()
	if len(providers) != 1 {
		t.Fatalf("Expected 1 provider, got %d", len(providers))
	}

	if providers[0].Name != "flatfile" {
		t.Errorf("Expected provider name 'flatfile', got: %s", providers[0].Name)
	}

	if providers[0].Version != provider.GetVersion() {
		t.Errorf("Expected version %q, got: %s", provider.GetVersion(), providers[0].Version)
	}

	if !providers[0].Available {
		t.Errorf("Expected the flat-file provider to report as available")
	}

	if providers[0].Capabilities != provider.GetCapabilities() {
		t.Errorf("Expected reported capabilities to match the provider's own: got %+v, want %+v",
			providers[0].Capabilities, provider.GetCapabilities())
	}
}

func TestNewStorageManagerFromStores(t *testing.T) {
	t.Run("composite provider name and nil provider", func(t *testing.T) {
		flatfileCfg, sqliteCfg := ossConfigs(t)
		ff, sq := newFlatFileProvider(), newSQLiteProvider()

		configStore, err := ff.CreateConfigStore(flatfileCfg)
		require.NoError(t, err)
		auditStore, err := ff.CreateAuditStore(flatfileCfg)
		require.NoError(t, err)
		rbacStore, err := sq.CreateRBACStore(sqliteCfg)
		require.NoError(t, err)
		tenantStore, err := sq.CreateTenantStore(sqliteCfg)
		require.NoError(t, err)
		clientTenantStore, err := sq.CreateClientTenantStore(sqliteCfg)
		require.NoError(t, err)
		registrationTokenStore, err := sq.CreateRegistrationTokenStore(sqliteCfg)
		require.NoError(t, err)

		sm := interfaces.NewStorageManagerFromStores(
			configStore, auditStore, rbacStore,
			tenantStore, clientTenantStore, registrationTokenStore,
			nil, nil, nil, nil, nil,
		)
		t.Cleanup(func() { _ = sm.Close() })

		if sm.GetProviderName() != "composite" {
			t.Errorf("expected providerName %q, got %q", "composite", sm.GetProviderName())
		}
		if sm.GetProvider() != nil {
			t.Errorf("expected nil provider for composite manager, got non-nil")
		}
	})

	t.Run("GetCapabilities returns zero value without panic", func(t *testing.T) {
		sm := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		caps := sm.GetCapabilities()
		// Zero value - no field should be set
		if caps.SupportsTransactions || caps.SupportsVersioning || caps.MaxBatchSize != 0 {
			t.Errorf("expected zero-value ProviderCapabilities, got %+v", caps)
		}
	})

	t.Run("GetVersion returns composite without panic", func(t *testing.T) {
		sm := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetVersion() != "composite" {
			t.Errorf("expected version %q, got %q", "composite", sm.GetVersion())
		}
	})

	t.Run("GetProvider returns nil without panic", func(t *testing.T) {
		sm := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if sm.GetProvider() != nil {
			t.Errorf("expected nil from GetProvider on composite manager")
		}
	})

	t.Run("all store parameters accepted and retrievable", func(t *testing.T) {
		flatfileCfg, sqliteCfg := ossConfigs(t)
		ff, sq := newFlatFileProvider(), newSQLiteProvider()

		configStore, err := ff.CreateConfigStore(flatfileCfg)
		require.NoError(t, err)
		auditStore, err := ff.CreateAuditStore(flatfileCfg)
		require.NoError(t, err)
		rbacStore, err := sq.CreateRBACStore(sqliteCfg)
		require.NoError(t, err)
		tenantStore, err := sq.CreateTenantStore(sqliteCfg)
		require.NoError(t, err)
		clientTenantStore, err := sq.CreateClientTenantStore(sqliteCfg)
		require.NoError(t, err)
		registrationTokenStore, err := sq.CreateRegistrationTokenStore(sqliteCfg)
		require.NoError(t, err)
		pushStore, err := sq.CreatePushStore(sqliteCfg)
		require.NoError(t, err)

		sm := interfaces.NewStorageManagerFromStores(
			configStore, auditStore, rbacStore,
			tenantStore, clientTenantStore, registrationTokenStore,
			nil, nil, nil, nil, pushStore,
		)
		t.Cleanup(func() { _ = sm.Close() })

		if sm.GetConfigStore() != configStore {
			t.Errorf("ConfigStore mismatch")
		}
		if sm.GetAuditStore() != auditStore {
			t.Errorf("AuditStore mismatch")
		}
		if sm.GetRBACStore() != rbacStore {
			t.Errorf("RBACStore mismatch")
		}
		if sm.GetTenantStore() != tenantStore {
			t.Errorf("TenantStore mismatch")
		}
		if sm.GetClientTenantStore() != clientTenantStore {
			t.Errorf("ClientTenantStore mismatch")
		}
		if sm.GetRegistrationTokenStore() != registrationTokenStore {
			t.Errorf("RegistrationTokenStore mismatch")
		}
		if sm.GetSessionStore() != nil {
			t.Errorf("SessionStore should be nil")
		}
		if sm.GetStewardStore() != nil {
			t.Errorf("StewardStore should be nil")
		}
		if sm.GetCommandStore() != nil {
			t.Errorf("CommandStore should be nil")
		}
		if sm.GetTriggerStore() != nil {
			t.Errorf("TriggerStore should be nil")
		}
		if sm.GetPushStore() != pushStore {
			t.Errorf("PushStore mismatch")
		}
	})

	t.Run("nil values allowed for all stores", func(t *testing.T) {
		sm := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		// Should not panic
		if sm.GetConfigStore() != nil {
			t.Errorf("expected nil ConfigStore")
		}
		if sm.GetAuditStore() != nil {
			t.Errorf("expected nil AuditStore")
		}
	})
}

func TestCreateOSSStorageManager(t *testing.T) {
	t.Run("error when flatfile provider not registered", func(t *testing.T) {
		withEmptyRegistry(t)

		_, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		if err == nil {
			t.Fatal("expected error when flatfile provider not registered")
		}
	})

	t.Run("error when sqlite provider not registered", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegistryReplace(map[string]interfaces.StorageProvider{
			"flatfile": newFlatFileProvider(),
		})

		_, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		if err == nil {
			t.Fatal("expected error when sqlite provider not registered")
		}
	})

	t.Run("creates composite manager backed by the real OSS providers", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegistryReplace(map[string]interfaces.StorageProvider{
			"flatfile": newFlatFileProvider(),
			"sqlite":   newSQLiteProvider(),
		})

		sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Cleanup(func() { _ = sm.Close() })

		if sm.GetProviderName() != "composite" {
			t.Errorf("expected providerName %q, got %q", "composite", sm.GetProviderName())
		}
		if sm.GetProvider() != nil {
			t.Errorf("expected nil provider")
		}

		// Config/Audit/Steward/IPTrust come from flatfile
		if sm.GetConfigStore() == nil {
			t.Errorf("ConfigStore should not be nil")
		}
		if sm.GetAuditStore() == nil {
			t.Errorf("AuditStore should not be nil")
		}
		if sm.GetStewardStore() == nil {
			t.Errorf("StewardStore should not be nil")
		}
		if sm.GetIPTrustStore() == nil {
			t.Errorf("IPTrustStore should not be nil — flatfile provider supplies it")
		}

		// Business stores come from sqlite
		if sm.GetRBACStore() == nil {
			t.Errorf("RBACStore should not be nil")
		}
		if sm.GetTenantStore() == nil {
			t.Errorf("TenantStore should not be nil")
		}
		if sm.GetClientTenantStore() == nil {
			t.Errorf("ClientTenantStore should not be nil")
		}
		if sm.GetRegistrationTokenStore() == nil {
			t.Errorf("RegistrationTokenStore should not be nil")
		}
		if sm.GetTriggerStore() == nil {
			t.Errorf("TriggerStore should not be nil — the SQLite provider supplies it")
		}
		if sm.GetPendingRefreshStore() == nil {
			t.Errorf("PendingRefreshStore should not be nil — the SQLite bundle supplies it")
		}
		if sm.GetRefreshPolicyStore() == nil {
			t.Errorf("RefreshPolicyStore should not be nil — the SQLite bundle supplies it")
		}

		// The composed manager must be usable end to end: write and read a steward
		// record through the flat-file store the factory wired up.
		ctx := context.Background()
		record := &business.StewardRecord{ID: "oss-steward-1", TenantID: "tenant-1", Status: business.StewardStatusRegistered}
		require.NoError(t, sm.GetStewardStore().RegisterSteward(ctx, record))
		got, err := sm.GetStewardStore().GetSteward(ctx, "oss-steward-1")
		require.NoError(t, err)
		assert.Equal(t, "tenant-1", got.TenantID)
	})
}

// TestCreateOSSStorageManager_StoreCreationErrors verifies that store-creation
// failures propagate out of the factory instead of yielding a half-built
// manager. Both failures are genuine provider errors: the flat-file provider
// rejects a root that is not a directory, and the SQLite provider cannot open a
// database file in a directory that does not exist.
func TestCreateOSSStorageManager_StoreCreationErrors(t *testing.T) {
	t.Run("flatfile store creation failure propagates", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegistryReplace(map[string]interfaces.StorageProvider{
			"flatfile": newFlatFileProvider(),
			"sqlite":   newSQLiteProvider(),
		})

		// A regular file cannot serve as the flat-file root.
		notADir := filepath.Join(t.TempDir(), "root-is-a-file")
		require.NoError(t, os.WriteFile(notADir, []byte("not a directory"), 0600))

		_, err := interfaces.CreateOSSStorageManager(notADir, filepath.Join(t.TempDir(), "test.db"))
		require.Error(t, err, "a flat-file root that is not a directory must fail the factory")
	})

	t.Run("sqlite store creation failure propagates", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegistryReplace(map[string]interfaces.StorageProvider{
			"flatfile": newFlatFileProvider(),
			"sqlite":   newSQLiteProvider(),
		})

		// The parent directory does not exist, so the database cannot be opened.
		missingDir := filepath.Join(t.TempDir(), "no-such-dir", "test.db")

		_, err := interfaces.CreateOSSStorageManager(t.TempDir(), missingDir)
		require.Error(t, err, "an unopenable SQLite path must fail the factory")
	})
}

func TestUnregisterStorageProvider(t *testing.T) {
	withEmptyRegistry(t)

	interfaces.RegisterStorageProvider(newFlatFileProvider())

	// Verify it's registered
	names := interfaces.GetRegisteredProviderNames()
	if len(names) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(names))
	}

	// Unregister it
	success := interfaces.UnregisterStorageProvider("flatfile")
	if !success {
		t.Errorf("Failed to unregister provider")
	}

	// Verify it's gone
	names = interfaces.GetRegisteredProviderNames()
	if len(names) != 0 {
		t.Errorf("Expected 0 providers after unregistration, got %d", len(names))
	}

	// Try to unregister non-existent provider
	success = interfaces.UnregisterStorageProvider("nonexistent")
	if success {
		t.Errorf("Should not succeed unregistering non-existent provider")
	}
}

// TestRegisterStorageProvider_routesThroughInjectedLogger verifies the registry
// emits its messages through the injected logger rather than a package-global
// default. Registering the same provider name twice is the registry's
// overwrite path, which logs a warning — captured here by the real
// logging.CapturingLogger.
func TestRegisterStorageProvider_routesThroughInjectedLogger(t *testing.T) {
	withEmptyRegistry(t)

	capturing := logging.NewCapturingLogger()
	interfaces.SetStorageLogger(capturing)
	t.Cleanup(func() { interfaces.SetStorageLogger(logging.NewNoopLogger()) })

	provider := newFlatFileProvider()
	interfaces.RegisterStorageProvider(provider)
	interfaces.RegisterStorageProvider(provider) // second registration overwrites

	require.NotEmpty(t, capturing.WarnMessages,
		"expected the overwrite warning to reach the injected logger")
	assert.Contains(t, capturing.WarnMessages[0], "Overwriting existing storage provider 'flatfile'")
}
