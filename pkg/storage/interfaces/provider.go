// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the global storage provider system for CFGMS.
// Store contracts are organised under sub-packages (business, config, blob,
// secrets, timeseries); this package now owns only the provider registry and
// composite StorageManager wiring.
package interfaces

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

var (
	registryLoggerMu sync.RWMutex
	registryLogger   logging.Logger = logging.NewNoopLogger()
)

// SetStorageLogger sets the logger used by the storage provider registry for registration messages.
// Safe to call concurrently with RegisterStorageProvider.
func SetStorageLogger(l logging.Logger) {
	registryLoggerMu.Lock()
	defer registryLoggerMu.Unlock()
	registryLogger = l
}

func getRegistryLogger() logging.Logger {
	registryLoggerMu.RLock()
	defer registryLoggerMu.RUnlock()
	return registryLogger
}

// BusinessStoreBundle groups all business-data stores that a single-connection
// provider can return from one shared database handle. Used by BusinessStoreOpener.
type BusinessStoreBundle struct {
	RBAC                business.RBACStore
	Tenant              business.TenantStore
	ClientTenant        business.ClientTenantStore
	RegistrationToken   business.RegistrationTokenStore
	Session             business.SessionStore
	Command             business.CommandStore
	Trigger             business.TriggerStore
	Push                business.PushStore
	PendingRegistration business.PendingRegistrationStore
	IPTrust             business.IPTrustStore
	PendingRefresh      business.PendingRefreshStore  // Issue #2098: registration-refresh approval queue
	RefreshPolicy       business.RefreshPolicyStore   // Issue #2098: per-tenant refresh policy
	AssurancePolicy     business.AssurancePolicyStore // Issue #2845: per-tenant assurance-policy overrides
	TenantCrossing      business.TenantCrossingStore  // ADR-025 Decision 2: tenant-crossing grants and break-glass
}

// BusinessStoreOpener is an optional StorageProvider extension. A provider that
// implements it can open all seven business stores from one shared database
// connection, preventing WAL read-lock slot exhaustion on Windows when each
// store would otherwise open its own connection to the same file.
type BusinessStoreOpener interface {
	OpenBusinessStores(path string) (*BusinessStoreBundle, error)
}

// RefreshStoreCreator is an optional StorageProvider extension for backends that
// support the per-tenant refresh policy and pending-refresh approval queue (Issue #2329).
// Backends that do not implement this interface leave those stores nil in the manager.
type RefreshStoreCreator interface {
	CreateRefreshPolicyStore(config map[string]interface{}) (business.RefreshPolicyStore, error)
	CreatePendingRefreshStore(config map[string]interface{}) (business.PendingRefreshStore, error)
}

// AssuranceStoreCreator is an optional StorageProvider extension for backends that
// support per-tenant assurance-policy overrides (Issue #2845, ADR-021).
// Backends that do not implement this interface leave the store nil in the manager.
type AssuranceStoreCreator interface {
	CreateAssurancePolicyStore(config map[string]interface{}) (business.AssurancePolicyStore, error)
}

// TenantCrossingStoreCreator is an optional StorageProvider extension for backends that
// support ADR-025 Decision 2's tenant-crossing grant and break-glass records.
// Backends that do not implement this interface leave the store nil in the manager.
type TenantCrossingStoreCreator interface {
	CreateTenantCrossingStore(config map[string]interface{}) (business.TenantCrossingStore, error)
}

// StorageProvider defines the interface that all storage backends must implement.
// Providers now return sub-package types from pkg/storage/interfaces/{business,config}.
type StorageProvider interface {
	// Identification
	Name() string
	Description() string
	Available() (bool, error) // Check dependencies, connectivity, etc.

	// Storage interface creation - providers return sub-package types.
	CreateClientTenantStore(config map[string]interface{}) (business.ClientTenantStore, error)
	CreateConfigStore(config map[string]interface{}) (cfgconfig.ConfigStore, error)
	CreateAuditStore(config map[string]interface{}) (business.AuditStore, error)
	CreateRBACStore(config map[string]interface{}) (business.RBACStore, error)
	CreateTenantStore(config map[string]interface{}) (business.TenantStore, error)
	CreateRegistrationTokenStore(config map[string]interface{}) (business.RegistrationTokenStore, error)
	CreateSessionStore(config map[string]interface{}) (business.SessionStore, error)
	CreateStewardStore(config map[string]interface{}) (business.StewardStore, error)
	CreateCommandStore(config map[string]interface{}) (business.CommandStore, error)
	CreateTriggerStore(config map[string]interface{}) (business.TriggerStore, error)
	CreatePushStore(config map[string]interface{}) (business.PushStore, error)
	CreatePendingRegistrationStore(config map[string]interface{}) (business.PendingRegistrationStore, error)
	CreateIPTrustStore(config map[string]interface{}) (business.IPTrustStore, error)

	// Provider capabilities and metadata
	GetCapabilities() ProviderCapabilities
	GetVersion() string

	// ClusterCapable returns true if this provider can serve as shared state
	// across multiple CFGMS controller nodes in cluster mode.
	ClusterCapable() bool
}

// Global provider registry (Salt-style auto-registration)
var (
	globalRegistry = &providerRegistry{
		providers: make(map[string]StorageProvider),
	}
)

type providerRegistry struct {
	providers map[string]StorageProvider
	mutex     sync.RWMutex
}

// RegisterStorageProvider registers a storage provider (called from provider init() functions).
// This function includes validation to ensure providers implement all required interfaces.
func RegisterStorageProvider(provider StorageProvider) {
	if err := ValidateProvider(provider); err != nil {
		// Log the error but don't panic - allows system to start with other providers
		getRegistryLogger().Warn(fmt.Sprintf("Failed to register storage provider '%s': %v", provider.Name(), err))
		return
	}

	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	if existing, exists := globalRegistry.providers[provider.Name()]; exists {
		getRegistryLogger().Warn(fmt.Sprintf("Overwriting existing storage provider '%s' (version %s) with version %s",
			provider.Name(), existing.GetVersion(), provider.GetVersion()))
	}

	globalRegistry.providers[provider.Name()] = provider
	getRegistryLogger().Info(fmt.Sprintf("Registered storage provider: %s v%s", provider.Name(), provider.GetVersion()),
		"description", provider.Description())
}

// ValidateProviderMetadata applies the registration rules to a provider's
// declared metadata. It is separated from ValidateProvider so the rules can be
// evaluated (and exercised) against provider metadata as plain data, without an
// implementation of the StorageProvider interface.
func ValidateProviderMetadata(name, description, version string, capabilities ProviderCapabilities) error {
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	if description == "" {
		return fmt.Errorf("provider description cannot be empty")
	}

	if version == "" {
		return fmt.Errorf("provider version cannot be empty")
	}

	if capabilities.MaxBatchSize < 0 {
		return fmt.Errorf("provider MaxBatchSize cannot be negative")
	}

	if capabilities.MaxConfigSize < 0 {
		return fmt.Errorf("provider MaxConfigSize cannot be negative")
	}

	if capabilities.MaxAuditRetentionDays < 0 {
		return fmt.Errorf("provider MaxAuditRetentionDays cannot be negative")
	}

	return nil
}

// ValidateProvider ensures a provider implements all required interfaces correctly.
func ValidateProvider(provider StorageProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}

	if err := ValidateProviderMetadata(
		provider.Name(),
		provider.Description(),
		provider.GetVersion(),
		provider.GetCapabilities(),
	); err != nil {
		return err
	}

	if available, err := provider.Available(); !available && err != nil {
		getRegistryLogger().Info(fmt.Sprintf("Note: Provider '%s' reports as unavailable: %v", provider.Name(), err))
	}

	return nil
}

// validateStoreCreation creates a store purely to prove that create(testConfig)
// succeeds, then closes it immediately — the store is never returned to a
// caller. Left open, each of these holds its own backing handle (e.g. a
// sqlite *sql.DB); on Windows an unclosed handle keeps the underlying file
// locked, which fails a later cleanup (e.g. t.TempDir()) with "the process
// cannot access the file because it is being used by another process" even
// though nothing was ever using the store (Issue #2944, PR #3254 CI failure).
func validateStoreCreation[T io.Closer](name string, testConfig map[string]interface{}, create func(map[string]interface{}) (T, error)) error {
	store, err := create(testConfig)
	if err != nil {
		if errors.Is(err, business.ErrNotSupported) {
			return nil
		}
		return fmt.Errorf("failed to create %s: %w", name, err)
	}
	if err := store.Close(); err != nil {
		getRegistryLogger().Warn(fmt.Sprintf("failed to close validation %s: %v", name, err))
	}
	return nil
}

// RegisterStorageProviderWithValidation registers a provider with full validation.
// This is an enhanced version that tests interface creation with a test config.
func RegisterStorageProviderWithValidation(provider StorageProvider, testConfig map[string]interface{}) error {
	if err := ValidateProvider(provider); err != nil {
		return fmt.Errorf("provider validation failed: %w", err)
	}

	if available, _ := provider.Available(); available {
		if err := validateStoreCreation("ClientTenantStore", testConfig, provider.CreateClientTenantStore); err != nil {
			return err
		}

		if _, err := provider.CreateConfigStore(testConfig); err != nil && !errors.Is(err, business.ErrNotSupported) {
			return fmt.Errorf("failed to create ConfigStore: %w", err)
		}

		if err := validateStoreCreation("AuditStore", testConfig, provider.CreateAuditStore); err != nil {
			return err
		}

		if err := validateStoreCreation("RBACStore", testConfig, provider.CreateRBACStore); err != nil {
			return err
		}

		if err := validateStoreCreation("TenantStore", testConfig, provider.CreateTenantStore); err != nil {
			return err
		}

		if err := validateStoreCreation("RegistrationTokenStore", testConfig, provider.CreateRegistrationTokenStore); err != nil {
			return err
		}

		if err := validateStoreCreation("StewardStore", testConfig, provider.CreateStewardStore); err != nil {
			return err
		}

		if err := validateStoreCreation("TriggerStore", testConfig, provider.CreateTriggerStore); err != nil {
			return err
		}
	}

	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	globalRegistry.providers[provider.Name()] = provider
	getRegistryLogger().Info(fmt.Sprintf("Successfully registered and validated storage provider: %s v%s",
		provider.Name(), provider.GetVersion()))

	return nil
}

// GetRegisteredProviderNames returns a list of all registered provider names.
func GetRegisteredProviderNames() []string {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	names := make([]string, 0, len(globalRegistry.providers))
	for name := range globalRegistry.providers {
		names = append(names, name)
	}

	return names
}

// UnregisterStorageProvider removes a provider from the registry (primarily for testing).
func UnregisterStorageProvider(name string) bool {
	globalRegistry.mutex.Lock()
	defer globalRegistry.mutex.Unlock()

	if _, exists := globalRegistry.providers[name]; exists {
		delete(globalRegistry.providers, name)
		return true
	}

	return false
}

// GetStorageProvider retrieves a registered provider by name.
func GetStorageProvider(name string) (StorageProvider, error) {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	provider, exists := globalRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("storage provider '%s' not found", name)
	}

	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("storage provider '%s' not available: %v", name, err)
	}

	return provider, nil
}

// GetAvailableProviders returns all providers that are currently available.
func GetAvailableProviders() map[string]StorageProvider {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	available := make(map[string]StorageProvider)
	for name, provider := range globalRegistry.providers {
		if ok, err := provider.Available(); ok && err == nil {
			available[name] = provider
		}
	}

	return available
}

// ListProviders returns information about all registered providers.
func ListProviders() []ProviderInfo {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	var providers []ProviderInfo
	for name, provider := range globalRegistry.providers {
		available, err := provider.Available()

		info := ProviderInfo{
			Name:        name,
			Description: provider.Description(),
			Available:   available,
		}

		if err != nil {
			info.UnavailableReason = err.Error()
		}

		providers = append(providers, info)
	}

	return providers
}

// ProviderInfo provides information about a storage provider.
type ProviderInfo struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ProviderCapabilities describes what features a storage provider supports.
type ProviderCapabilities struct {
	SupportsTransactions   bool `json:"supports_transactions"`     // ACID transaction support
	SupportsVersioning     bool `json:"supports_versioning"`       // Configuration versioning
	SupportsFullTextSearch bool `json:"supports_full_text_search"` // Full-text search in audit logs
	SupportsEncryption     bool `json:"supports_encryption"`       // At-rest encryption
	SupportsCompression    bool `json:"supports_compression"`      // Data compression
	SupportsReplication    bool `json:"supports_replication"`      // Data replication/HA
	SupportsSharding       bool `json:"supports_sharding"`         // Horizontal partitioning
	MaxBatchSize           int  `json:"max_batch_size"`            // Maximum batch operation size
	MaxConfigSize          int  `json:"max_config_size"`           // Maximum single config size
	MaxAuditRetentionDays  int  `json:"max_audit_retention_days"`  // Maximum audit retention period
}

// ProviderInfoV2 is an enhanced ProviderInfo that includes capabilities.
type ProviderInfoV2 struct {
	ProviderInfo
	Capabilities ProviderCapabilities `json:"capabilities"`
	Version      string               `json:"version"`
}

// CreateClientTenantStoreFromConfig creates a ClientTenantStore from configuration.
func CreateClientTenantStoreFromConfig(providerName string, config map[string]interface{}) (business.ClientTenantStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateClientTenantStore(config)
}

// CreateConfigStoreFromConfig creates a ConfigStore from configuration.
func CreateConfigStoreFromConfig(providerName string, config map[string]interface{}) (cfgconfig.ConfigStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateConfigStore(config)
}

// CreateAuditStoreFromConfig creates an AuditStore from configuration.
func CreateAuditStoreFromConfig(providerName string, config map[string]interface{}) (business.AuditStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateAuditStore(config)
}

// CreateRBACStoreFromConfig creates an RBACStore from configuration.
func CreateRBACStoreFromConfig(providerName string, config map[string]interface{}) (business.RBACStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateRBACStore(config)
}

// CreateTenantStoreFromConfig creates a TenantStore from configuration.
func CreateTenantStoreFromConfig(providerName string, config map[string]interface{}) (business.TenantStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateTenantStore(config)
}

// CreateRegistrationTokenStoreFromConfig creates a RegistrationTokenStore from configuration.
func CreateRegistrationTokenStoreFromConfig(providerName string, config map[string]interface{}) (business.RegistrationTokenStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateRegistrationTokenStore(config)
}

// CreateSessionStoreFromConfig creates a SessionStore from configuration.
func CreateSessionStoreFromConfig(providerName string, config map[string]interface{}) (business.SessionStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateSessionStore(config)
}

// CreateStewardStoreFromConfig creates a StewardStore from configuration.
func CreateStewardStoreFromConfig(providerName string, config map[string]interface{}) (business.StewardStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}

	return provider.CreateStewardStore(config)
}

// CreateCommandStoreFromConfig creates a CommandStore from configuration.
func CreateCommandStoreFromConfig(providerName string, config map[string]interface{}) (business.CommandStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}
	return provider.CreateCommandStore(config)
}

// CreateTriggerStoreFromConfig creates a TriggerStore from configuration.
func CreateTriggerStoreFromConfig(providerName string, config map[string]interface{}) (business.TriggerStore, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("storage provider '%s' not available: %w", providerName, err)
	}
	return provider.CreateTriggerStore(config)
}

// Deprecated: CreateAllStoresFromConfig creates all storage interfaces from a single configuration.
// Use CreateOSSStorageManager for new deployments. This function is retained for backward
// compatibility with the database provider in single-backend mode.
func CreateAllStoresFromConfig(providerName string, config map[string]interface{}) (*StorageManager, error) {
	provider, err := GetStorageProvider(providerName)
	if err != nil {
		available := GetAvailableProviders()
		var availableNames []string
		for name := range available {
			availableNames = append(availableNames, name)
		}
		return nil, fmt.Errorf("storage provider '%s' not available. Available providers: %v. Error: %w", providerName, availableNames, err)
	}

	clientTenantStore, err := provider.CreateClientTenantStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create client tenant store: %w", err)
	}

	configStore, err := provider.CreateConfigStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}

	auditStore, err := provider.CreateAuditStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create audit store: %w", err)
	}

	rbacStore, err := provider.CreateRBACStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create RBAC store: %w", err)
	}

	tenantStore, err := provider.CreateTenantStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create tenant store: %w", err)
	}

	registrationTokenStore, err := provider.CreateRegistrationTokenStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create registration token store: %w", err)
	}

	sessionStore, err := provider.CreateSessionStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}

	stewardStore, err := provider.CreateStewardStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create steward store: %w", err)
	}

	commandStore, err := provider.CreateCommandStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create command store: %w", err)
	}

	triggerStore, err := provider.CreateTriggerStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create trigger store: %w", err)
	}

	pushStore, err := provider.CreatePushStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create push store: %w", err)
	}

	ipTrustStore, err := provider.CreateIPTrustStore(config)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create IP trust store: %w", err)
	}

	return &StorageManager{
		providerName:           providerName,
		provider:               provider,
		clientTenantStore:      clientTenantStore,
		configStore:            configStore,
		auditStore:             auditStore,
		rbacStore:              rbacStore,
		tenantStore:            tenantStore,
		registrationTokenStore: registrationTokenStore,
		sessionStore:           sessionStore,
		stewardStore:           stewardStore,
		commandStore:           commandStore,
		triggerStore:           triggerStore,
		pushStore:              pushStore,
		ipTrustStore:           ipTrustStore,
	}, nil
}

// StorageManager provides unified access to all storage interfaces.
type StorageManager struct {
	providerName             string
	provider                 StorageProvider
	clientTenantStore        business.ClientTenantStore
	configStore              cfgconfig.ConfigStore
	auditStore               business.AuditStore
	rbacStore                business.RBACStore
	tenantStore              business.TenantStore
	registrationTokenStore   business.RegistrationTokenStore
	sessionStore             business.SessionStore
	stewardStore             business.StewardStore
	commandStore             business.CommandStore
	triggerStore             business.TriggerStore
	pushStore                business.PushStore
	pendingRegistrationStore business.PendingRegistrationStore
	ipTrustStore             business.IPTrustStore
	pendingRefreshStore      business.PendingRefreshStore  // Issue #2098: registration-refresh approval queue
	refreshPolicyStore       business.RefreshPolicyStore   // Issue #2098: per-tenant refresh policy
	assurancePolicyStore     business.AssurancePolicyStore // Issue #2845: per-tenant assurance-policy overrides
	tenantCrossingStore      business.TenantCrossingStore  // ADR-025 Decision 2: tenant-crossing grants and break-glass
}

// GetProviderName returns the name of the storage provider.
func (sm *StorageManager) GetProviderName() string {
	return sm.providerName
}

// GetProvider returns the underlying storage provider.
func (sm *StorageManager) GetProvider() StorageProvider {
	return sm.provider
}

// GetClientTenantStore returns the client tenant storage interface.
func (sm *StorageManager) GetClientTenantStore() business.ClientTenantStore {
	return sm.clientTenantStore
}

// GetConfigStore returns the configuration storage interface.
func (sm *StorageManager) GetConfigStore() cfgconfig.ConfigStore {
	return sm.configStore
}

// GetAuditStore returns the audit storage interface.
func (sm *StorageManager) GetAuditStore() business.AuditStore {
	return sm.auditStore
}

// GetRBACStore returns the RBAC storage interface.
func (sm *StorageManager) GetRBACStore() business.RBACStore {
	return sm.rbacStore
}

// GetTenantStore returns the tenant storage interface.
func (sm *StorageManager) GetTenantStore() business.TenantStore {
	return sm.tenantStore
}

// GetRegistrationTokenStore returns the registration token storage interface.
func (sm *StorageManager) GetRegistrationTokenStore() business.RegistrationTokenStore {
	return sm.registrationTokenStore
}

// GetSessionStore returns the session storage interface (nil if not supported by provider).
func (sm *StorageManager) GetSessionStore() business.SessionStore {
	return sm.sessionStore
}

// GetStewardStore returns the steward fleet registry interface (nil if not supported by provider).
func (sm *StorageManager) GetStewardStore() business.StewardStore {
	return sm.stewardStore
}

// GetCommandStore returns the command dispatch state interface (nil if not supported by provider).
func (sm *StorageManager) GetCommandStore() business.CommandStore {
	return sm.commandStore
}

// GetTriggerStore returns the workflow trigger storage interface (nil if not yet wired; Story J wires this).
func (sm *StorageManager) GetTriggerStore() business.TriggerStore {
	return sm.triggerStore
}

// GetPushStore returns the push-state storage interface (nil if not supported by provider).
func (sm *StorageManager) GetPushStore() business.PushStore {
	return sm.pushStore
}

// GetPendingRegistrationStore returns the pending registration storage interface (Issue #1599).
// Returns nil if not supported by the current storage provider.
func (sm *StorageManager) GetPendingRegistrationStore() business.PendingRegistrationStore {
	return sm.pendingRegistrationStore
}

// SetPendingRegistrationStore wires the pending registration store after construction.
// Used by CreateOSSStorageManager when the SQLite bundle path is taken.
func (sm *StorageManager) SetPendingRegistrationStore(s business.PendingRegistrationStore) {
	sm.pendingRegistrationStore = s
}

// GetIPTrustStore returns the IP-trust storage interface (Issue #1694).
// Returns nil when the current storage provider does not support IP-trust storage
// (e.g. the OSS composite flatfile+SQLite backend). Only the database provider
// supplies a non-nil value.
func (sm *StorageManager) GetIPTrustStore() business.IPTrustStore {
	return sm.ipTrustStore
}

// SetIPTrustStore wires the IP-trust store after construction.
func (sm *StorageManager) SetIPTrustStore(s business.IPTrustStore) {
	sm.ipTrustStore = s
}

// GetPendingRefreshStore returns the pending-refresh approval queue (Issue #2098).
// Returns nil when not yet wired; callers must nil-check before use.
func (sm *StorageManager) GetPendingRefreshStore() business.PendingRefreshStore {
	return sm.pendingRefreshStore
}

// SetPendingRefreshStore wires the pending-refresh store after construction.
func (sm *StorageManager) SetPendingRefreshStore(s business.PendingRefreshStore) {
	sm.pendingRefreshStore = s
}

// GetRefreshPolicyStore returns the per-tenant refresh policy store (Issue #2098).
// Returns nil when not yet wired; callers must nil-check before use.
func (sm *StorageManager) GetRefreshPolicyStore() business.RefreshPolicyStore {
	return sm.refreshPolicyStore
}

// SetRefreshPolicyStore wires the per-tenant refresh policy store after construction.
func (sm *StorageManager) SetRefreshPolicyStore(s business.RefreshPolicyStore) {
	sm.refreshPolicyStore = s
}

// GetAssurancePolicyStore returns the per-tenant assurance-policy override store (Issue #2845).
// Returns nil when not yet wired; callers must nil-check before use.
func (sm *StorageManager) GetAssurancePolicyStore() business.AssurancePolicyStore {
	return sm.assurancePolicyStore
}

// SetAssurancePolicyStore wires the per-tenant assurance-policy store after construction.
func (sm *StorageManager) SetAssurancePolicyStore(s business.AssurancePolicyStore) {
	sm.assurancePolicyStore = s
}

// GetTenantCrossingStore returns the ADR-025 Decision 2 tenant-crossing grant/break-glass
// store. Returns nil when not yet wired; callers must nil-check before use.
func (sm *StorageManager) GetTenantCrossingStore() business.TenantCrossingStore {
	return sm.tenantCrossingStore
}

// SetTenantCrossingStore wires the tenant-crossing store after construction.
func (sm *StorageManager) SetTenantCrossingStore(s business.TenantCrossingStore) {
	sm.tenantCrossingStore = s
}

// GetCapabilities returns the provider's capabilities.
// Returns a zero-value ProviderCapabilities when the manager has no backing provider
// (e.g. a composite manager created with NewStorageManagerFromStores).
func (sm *StorageManager) GetCapabilities() ProviderCapabilities {
	if sm.provider == nil {
		return ProviderCapabilities{}
	}
	return sm.provider.GetCapabilities()
}

// GetVersion returns the provider's version.
// Returns "composite" when the manager has no backing provider.
func (sm *StorageManager) GetVersion() string {
	if sm.provider == nil {
		return sm.providerName
	}
	return sm.provider.GetVersion()
}

// Close releases resources held by every non-nil backing store. It returns
// the first error encountered but attempts to close every store regardless,
// so a single failure does not leak the remaining handles.
//
// Not every store interface declares Close (e.g. ConfigStore) but concrete
// implementations often do, so each slot is checked with a type assertion.
//
// SQLite-backed stores in particular must be closed before temp-directory
// cleanup on Windows; without this hook, `t.TempDir()` RemoveAll fails with
// "file in use by another process" when tests exit.
func (sm *StorageManager) Close() error {
	slots := []interface{}{
		sm.clientTenantStore,
		sm.configStore,
		sm.auditStore,
		sm.rbacStore,
		sm.tenantStore,
		sm.registrationTokenStore,
		sm.sessionStore,
		sm.stewardStore,
		sm.commandStore,
		sm.triggerStore,
		sm.pushStore,
		sm.pendingRegistrationStore,
		sm.ipTrustStore,
		sm.refreshPolicyStore,
		sm.pendingRefreshStore,
		sm.assurancePolicyStore,
		sm.tenantCrossingStore,
	}
	var firstErr error
	for _, s := range slots {
		if s == nil {
			continue
		}
		closer, ok := s.(interface{ Close() error })
		if !ok {
			continue
		}
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ListProvidersV2 returns enhanced information about all registered providers.
func ListProvidersV2() []ProviderInfoV2 {
	globalRegistry.mutex.RLock()
	defer globalRegistry.mutex.RUnlock()

	var providers []ProviderInfoV2
	for name, provider := range globalRegistry.providers {
		available, err := provider.Available()

		info := ProviderInfoV2{
			ProviderInfo: ProviderInfo{
				Name:        name,
				Description: provider.Description(),
				Available:   available,
			},
			Capabilities: provider.GetCapabilities(),
			Version:      provider.GetVersion(),
		}

		if err != nil {
			info.UnavailableReason = err.Error()
		}

		providers = append(providers, info)
	}

	return providers
}

// CreateHybridStorageManagerFromConfig creates hybrid storage manager from configuration.
// This is the recommended entry point for production deployments with mixed storage needs.
func CreateHybridStorageManagerFromConfig(config HybridStorageConfig) (*HybridStorageManager, error) {
	return CreateHybridStorageFromConfig(config)
}

// NewStorageManagerFromStores composes a StorageManager from individually-provided store
// implementations.  The caller is responsible for providing the stores it needs; any
// parameter may be nil.  The resulting manager has providerName "composite" and a nil
// provider field — callers must not rely on GetProvider() returning a non-nil value, and
// GetCapabilities() returns a zero-value ProviderCapabilities{} for composite managers.
//
// The parameter order no longer includes a runtime store (retired per ADR-003).
// Callers that previously passed a runtimeStore should pass the remaining stores directly.
func NewStorageManagerFromStores(
	configStore cfgconfig.ConfigStore,
	auditStore business.AuditStore,
	rbacStore business.RBACStore,
	tenantStore business.TenantStore,
	clientTenantStore business.ClientTenantStore,
	registrationTokenStore business.RegistrationTokenStore,
	sessionStore business.SessionStore,
	stewardStore business.StewardStore,
	commandStore business.CommandStore,
	triggerStore business.TriggerStore,
	pushStore business.PushStore,
) *StorageManager {
	return &StorageManager{
		providerName:           "composite",
		provider:               nil,
		configStore:            configStore,
		auditStore:             auditStore,
		rbacStore:              rbacStore,
		tenantStore:            tenantStore,
		clientTenantStore:      clientTenantStore,
		registrationTokenStore: registrationTokenStore,
		sessionStore:           sessionStore,
		stewardStore:           stewardStore,
		commandStore:           commandStore,
		triggerStore:           triggerStore,
		pushStore:              pushStore,
	}
}

// CreateClusterStorageManager composes the cluster storage tier from the database provider
// (Postgres-backed business stores) using pgConnStr as the libpq connection string.
//
// sessionHMACKey is required to create the session store: config["session_hmac_key"] backs
// DatabaseSessionStore's bearer-token hashing (pkg/storage/providers/database/session_store.go),
// which fails closed rather than falling back to an insecure default when the key is empty.
// Source it from storage.cluster.session_hmac_key or CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY.
//
// s3Config documents the S3-compatible blob store configuration required for cluster
// installer artifact storage. The blob store itself is NOT created here — callers are
// responsible for initialising it separately (e.g. via blob.CreateBlobStoreFromConfig("s3", s3Config)).
// Passing nil is accepted but means the caller must configure S3 via CFGMS_S3_INSTALLER_BUCKET.
//
// The "database" provider must be registered before calling this function via a blank-import
// in the calling binary's main.go or in a providers_test.go file for tests.
//
// Used by initialization.go (--init) and server.go (startup) when ha.mode == cluster.
func CreateClusterStorageManager(pgConnStr, sessionHMACKey string, _ map[string]interface{}) (*StorageManager, error) {
	if pgConnStr == "" {
		return nil, fmt.Errorf("cluster storage requires a Postgres connection string (storage.cluster.postgres_dsn or CFGMS_STORAGE_CLUSTER_POSTGRES_DSN)")
	}

	dbCfg := map[string]interface{}{"dsn": pgConnStr, "session_hmac_key": sessionHMACKey}

	provider, err := GetStorageProvider("database")
	if err != nil {
		return nil, fmt.Errorf("database provider not registered for cluster storage (blank-import database provider in calling binary or test providers_test.go): %w", err)
	}

	clientTenantStore, err := provider.CreateClientTenantStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create client tenant store: %w", err)
	}
	configStore, err := provider.CreateConfigStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create config store: %w", err)
	}
	auditStore, err := provider.CreateAuditStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create audit store: %w", err)
	}
	rbacStore, err := provider.CreateRBACStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create RBAC store: %w", err)
	}
	tenantStore, err := provider.CreateTenantStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create tenant store: %w", err)
	}
	registrationTokenStore, err := provider.CreateRegistrationTokenStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create registration token store: %w", err)
	}
	sessionStore, err := provider.CreateSessionStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create session store: %w", err)
	}
	stewardStore, err := provider.CreateStewardStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster storage: failed to create steward store: %w", err)
	}
	commandStore, err := provider.CreateCommandStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create command store: %w", err)
	}
	triggerStore, err := provider.CreateTriggerStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create trigger store: %w", err)
	}
	pushStore, err := provider.CreatePushStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create push store: %w", err)
	}
	ipTrustStore, err := provider.CreateIPTrustStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create IP trust store: %w", err)
	}
	pendingRegStore, err := provider.CreatePendingRegistrationStore(dbCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("cluster storage: failed to create pending registration store: %w", err)
	}

	sm := &StorageManager{
		providerName:           "database",
		provider:               provider,
		clientTenantStore:      clientTenantStore,
		configStore:            configStore,
		auditStore:             auditStore,
		rbacStore:              rbacStore,
		tenantStore:            tenantStore,
		registrationTokenStore: registrationTokenStore,
		sessionStore:           sessionStore,
		stewardStore:           stewardStore,
		commandStore:           commandStore,
		triggerStore:           triggerStore,
		pushStore:              pushStore,
		ipTrustStore:           ipTrustStore,
	}
	if pendingRegStore != nil {
		sm.SetPendingRegistrationStore(pendingRegStore)
	}
	// Wire refresh stores if the provider implements the optional RefreshStoreCreator extension.
	if rsc, ok := provider.(RefreshStoreCreator); ok {
		refreshPolicyStore, err := rsc.CreateRefreshPolicyStore(dbCfg)
		if err != nil && !errors.Is(err, business.ErrNotSupported) {
			return nil, fmt.Errorf("cluster storage: failed to create refresh policy store: %w", err)
		}
		if refreshPolicyStore != nil {
			sm.SetRefreshPolicyStore(refreshPolicyStore)
		}
		pendingRefreshStore, err := rsc.CreatePendingRefreshStore(dbCfg)
		if err != nil && !errors.Is(err, business.ErrNotSupported) {
			return nil, fmt.Errorf("cluster storage: failed to create pending refresh store: %w", err)
		}
		if pendingRefreshStore != nil {
			sm.SetPendingRefreshStore(pendingRefreshStore)
		}
	}
	// Wire assurance policy store if the provider implements AssuranceStoreCreator (Issue #2845).
	if asc, ok := provider.(AssuranceStoreCreator); ok {
		assurancePolicyStore, err := asc.CreateAssurancePolicyStore(dbCfg)
		if err != nil && !errors.Is(err, business.ErrNotSupported) {
			return nil, fmt.Errorf("cluster storage: failed to create assurance policy store: %w", err)
		}
		if assurancePolicyStore != nil {
			sm.SetAssurancePolicyStore(assurancePolicyStore)
		}
	}
	// Wire tenant crossing store if the provider implements TenantCrossingStoreCreator (ADR-025).
	if tcc, ok := provider.(TenantCrossingStoreCreator); ok {
		tenantCrossingStore, err := tcc.CreateTenantCrossingStore(dbCfg)
		if err != nil && !errors.Is(err, business.ErrNotSupported) {
			return nil, fmt.Errorf("cluster storage: failed to create tenant crossing store: %w", err)
		}
		if tenantCrossingStore != nil {
			sm.SetTenantCrossingStore(tenantCrossingStore)
		}
	}
	return sm, nil
}

// CreateOSSStorageManager composes the OSS storage tier from a flatfile provider (for
// config/audit/steward stores) and a SQLite provider (for business-data stores), following
// the ADR-003 store-to-provider mapping.
//
// flatfileRoot is the directory root for the flat-file provider.
// sqliteConnStr is the SQLite DSN passed to the SQLite provider.  Use a file path such as
// "/var/lib/cfgms/cfgms.db" in production.  In tests use t.TempDir()+"/test.db" for
// per-test isolation — do NOT pass ":memory:", because parallel tests sharing
// "file::memory:?cache=shared" collide on schema migrations.
//
// Both the "flatfile" and "sqlite" providers must be registered (via blank imports of their
// respective packages) before calling this function.
func CreateOSSStorageManager(flatfileRoot, sqliteConnStr string) (*StorageManager, error) {
	flatfileCfg := map[string]interface{}{"root": flatfileRoot}
	sqliteCfg := map[string]interface{}{"path": sqliteConnStr}

	ffProvider, err := GetStorageProvider("flatfile")
	if err != nil {
		return nil, fmt.Errorf("flatfile provider not registered: %w", err)
	}
	sqProvider, err := GetStorageProvider("sqlite")
	if err != nil {
		return nil, fmt.Errorf("sqlite provider not registered: %w", err)
	}

	configStore, err := ffProvider.CreateConfigStore(flatfileCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store (flatfile): %w", err)
	}
	auditStore, err := ffProvider.CreateAuditStore(flatfileCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit store (flatfile): %w", err)
	}
	stewardStore, err := ffProvider.CreateStewardStore(flatfileCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create steward store (flatfile): %w", err)
	}
	ipTrustStore, err := ffProvider.CreateIPTrustStore(flatfileCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ip trust store (flatfile): %w", err)
	}

	// Prefer single-connection bundle when the provider supports it.
	// This opens the SQLite database exactly once and shares the *sql.DB across
	// all seven business stores, preventing WAL read-lock slot exhaustion that
	// causes test hangs on Windows when each store opens its own connection.
	if opener, ok := sqProvider.(BusinessStoreOpener); ok {
		bundle, err := opener.OpenBusinessStores(sqliteConnStr)
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite business stores: %w", err)
		}
		sm := NewStorageManagerFromStores(
			configStore, auditStore,
			bundle.RBAC, bundle.Tenant, bundle.ClientTenant,
			bundle.RegistrationToken, bundle.Session,
			stewardStore, bundle.Command, bundle.Trigger, bundle.Push,
		)
		sm.SetPendingRegistrationStore(bundle.PendingRegistration)
		sm.SetIPTrustStore(ipTrustStore)
		sm.SetPendingRefreshStore(bundle.PendingRefresh)
		sm.SetRefreshPolicyStore(bundle.RefreshPolicy)
		sm.SetAssurancePolicyStore(bundle.AssurancePolicy)
		sm.SetTenantCrossingStore(bundle.TenantCrossing)
		return sm, nil
	}

	rbacStore, err := sqProvider.CreateRBACStore(sqliteCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC store (sqlite): %w", err)
	}
	tenantStore, err := sqProvider.CreateTenantStore(sqliteCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant store (sqlite): %w", err)
	}
	clientTenantStore, err := sqProvider.CreateClientTenantStore(sqliteCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create client tenant store (sqlite): %w", err)
	}
	registrationTokenStore, err := sqProvider.CreateRegistrationTokenStore(sqliteCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token store (sqlite): %w", err)
	}
	sessionStore, err := sqProvider.CreateSessionStore(sqliteCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create session store (sqlite): %w", err)
	}
	commandStore, err := sqProvider.CreateCommandStore(sqliteCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create command store (sqlite): %w", err)
	}
	triggerStore, err := sqProvider.CreateTriggerStore(sqliteCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create trigger store (sqlite): %w", err)
	}
	pushStore, err := sqProvider.CreatePushStore(sqliteCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create push store (sqlite): %w", err)
	}
	pendingRegStore, err := sqProvider.CreatePendingRegistrationStore(sqliteCfg)
	if err != nil && !errors.Is(err, business.ErrNotSupported) {
		return nil, fmt.Errorf("failed to create pending registration store (sqlite): %w", err)
	}

	sm := NewStorageManagerFromStores(
		configStore, auditStore, rbacStore,
		tenantStore, clientTenantStore, registrationTokenStore,
		sessionStore, stewardStore, commandStore, triggerStore, pushStore,
	)
	sm.SetPendingRegistrationStore(pendingRegStore)
	sm.SetIPTrustStore(ipTrustStore)
	// PendingRefreshStore and RefreshPolicyStore are only available via BusinessStoreBundle
	// (OpenBusinessStores). The non-bundle fallback path leaves them nil — acceptable since
	// this path is only taken when the provider does not implement BusinessStoreOpener,
	// which in practice means unit tests that do not exercise the refresh flow.
	return sm, nil
}
