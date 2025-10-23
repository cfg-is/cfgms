// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package session provides factory functions for creating session managers
package session

import (
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// NewSessionManagerWithGlobalStorage creates a session manager using the global storage manager
// Epic 6 Compliant: Blindly uses the global storage provider without any provider-specific logic
func NewSessionManagerWithGlobalStorage(storageManager *interfaces.StorageManager, config *Config, logger logging.Logger) (SessionManager, error) {
	if storageManager == nil {
		return nil, fmt.Errorf("global storage manager is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Epic 6 Compliance: Blindly use the global storage provider
	// The session manager has NO knowledge of which provider it is using
	globalRuntimeStore := storageManager.GetRuntimeStore()

	// Create shared cache for ephemeral sessions (always needed for performance)
	// Epic 6 Compliance: No external memory provider dependency
	cacheConfig := cache.CacheConfig{
		Name:            "session-ephemeral",
		MaxSessions:     10000,           // Large limit for production use
		MaxRuntimeItems: 5000,            // Reasonable limit for runtime state
		DefaultTTL:      2 * time.Hour,   // Default session timeout
		CleanupInterval: 5 * time.Minute, // Regular cleanup
	}
	ephemeralStore := cache.NewRuntimeCache(cacheConfig)

	// Use default config if none provided
	if config == nil {
		config = DefaultConfig()
	}

	// Epic 6: Use global provider for persistent sessions, memory for ephemeral
	// If global provider doesn't support runtime storage, CreateRuntimeStore will fail
	// and the system configuration is invalid (user must fix config)
	return NewUnifiedSessionManager(ephemeralStore, globalRuntimeStore, config, logger)
}

// NewSessionManagerWithStorage creates a unified session manager with the specified storage backends
// DEPRECATED: Use NewSessionManagerWithGlobalStorage for Epic 6 compliance
func NewSessionManagerWithStorage(config *SessionManagerConfig, logger logging.Logger) (SessionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("session manager config is required")
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Create ephemeral store (required)
	ephemeralStore, err := interfaces.CreateRuntimeStoreFromConfig(
		config.EphemeralProviderName,
		config.StorageConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral store: %w", err)
	}

	// Create persistent store (optional)
	var persistentStore interfaces.RuntimeStore
	if config.PersistentProviderName != "" {
		persistentStore, err = interfaces.CreateRuntimeStoreFromConfig(
			config.PersistentProviderName,
			config.StorageConfig,
		)
		if err != nil {
			logger.Warn("Failed to create persistent store, continuing with ephemeral only",
				"provider", config.PersistentProviderName,
				"error", err)
		}
	}

	// Use default config if none provided
	sessionConfig := config.SessionConfig
	if sessionConfig == nil {
		sessionConfig = DefaultConfig()
	}

	return NewUnifiedSessionManager(ephemeralStore, persistentStore, sessionConfig, logger)
}

// NewEphemeralSessionManager creates a session manager with only ephemeral storage
// DEPRECATED: Memory provider has been eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage instead.
func NewEphemeralSessionManager(config *Config, logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("NewEphemeralSessionManager is deprecated: memory provider eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage with global storage manager instead")
}

// NewProductionSessionManager creates a session manager suitable for production with both storage types
// DEPRECATED: Memory provider has been eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage instead.
func NewProductionSessionManager(databaseConfig map[string]interface{}, config *Config, logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("NewProductionSessionManager is deprecated: memory provider eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage with global storage manager instead")
}

// NewHybridSessionManager creates a session manager with custom storage backend configuration
// Allows full control over which providers to use for ephemeral vs persistent storage
func NewHybridSessionManager(
	ephemeralProvider string,
	persistentProvider string,
	storageConfig map[string]interface{},
	config *Config,
	logger logging.Logger,
) (SessionManager, error) {

	sessionManagerConfig := &SessionManagerConfig{
		EphemeralProviderName:  ephemeralProvider,
		PersistentProviderName: persistentProvider,
		StorageConfig:          storageConfig,
		SessionConfig:          config,
	}

	return NewSessionManagerWithStorage(sessionManagerConfig, logger)
}

// SessionManagerBuilder provides a fluent interface for building session managers
type SessionManagerBuilder struct {
	ephemeralProvider  string
	persistentProvider string
	storageConfig      map[string]interface{}
	sessionConfig      *Config
	logger             logging.Logger
}

// NewSessionManagerBuilder creates a new session manager builder
func NewSessionManagerBuilder() *SessionManagerBuilder {
	return &SessionManagerBuilder{
		storageConfig: make(map[string]interface{}),
	}
}

// WithEphemeralProvider sets the ephemeral storage provider
func (b *SessionManagerBuilder) WithEphemeralProvider(provider string) *SessionManagerBuilder {
	b.ephemeralProvider = provider
	return b
}

// WithPersistentProvider sets the persistent storage provider
func (b *SessionManagerBuilder) WithPersistentProvider(provider string) *SessionManagerBuilder {
	b.persistentProvider = provider
	return b
}

// WithStorageConfig sets the storage configuration
func (b *SessionManagerBuilder) WithStorageConfig(config map[string]interface{}) *SessionManagerBuilder {
	b.storageConfig = config
	return b
}

// WithSessionConfig sets the session configuration
func (b *SessionManagerBuilder) WithSessionConfig(config *Config) *SessionManagerBuilder {
	b.sessionConfig = config
	return b
}

// WithLogger sets the logger
func (b *SessionManagerBuilder) WithLogger(logger logging.Logger) *SessionManagerBuilder {
	b.logger = logger
	return b
}

// Build creates the session manager
func (b *SessionManagerBuilder) Build() (SessionManager, error) {
	if b.ephemeralProvider == "" {
		return nil, fmt.Errorf("ephemeral provider is required: memory provider eliminated in Epic 6, use WithEphemeralProvider() to specify provider")
	}

	if b.logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	sessionManagerConfig := &SessionManagerConfig{
		EphemeralProviderName:  b.ephemeralProvider,
		PersistentProviderName: b.persistentProvider,
		StorageConfig:          b.storageConfig,
		SessionConfig:          b.sessionConfig,
	}

	return NewSessionManagerWithStorage(sessionManagerConfig, b.logger)
}

// Example usage functions - Epic 6 Compliant

// ExampleControllerIntegration shows how to integrate session management with controller
// This is the correct Epic 6 pattern - use the global storage manager
func ExampleControllerIntegration(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Epic 6 Compliant: Use global storage manager (same as RBAC, Audit, Config)
	config := DefaultConfig()
	config.MaxSessions = 10000
	config.DefaultSessionTimeout = 1 * time.Hour

	return NewSessionManagerWithGlobalStorage(storageManager, config, logger)
}

// ExampleDevelopmentSetup shows development setup using global storage (Epic 6 compliant)
func ExampleDevelopmentSetup(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Development: Uses whatever storage provider is configured globally
	// Epic 6: Memory provider eliminated - use git/database for development
	// All storage providers support both ephemeral and persistent sessions
	return NewSessionManagerWithGlobalStorage(storageManager, DefaultConfig(), logger)
}

// ExampleProductionSetup shows production setup using global storage (Epic 6 compliant)
func ExampleProductionSetup(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Production: Uses global storage provider (typically database)
	config := DefaultConfig()
	config.MaxSessions = 50000                   // High limit for production
	config.DefaultSessionTimeout = 2 * time.Hour // Longer sessions
	config.CleanupInterval = 1 * time.Minute     // Frequent cleanup

	// Epic 6 Compliance: Uses same provider as RBAC/Audit/Config
	return NewSessionManagerWithGlobalStorage(storageManager, config, logger)
}

// Legacy examples (DEPRECATED - not Epic 6 compliant)

// ExampleCustomSetup shows how to set up session management with custom providers
// DEPRECATED: Use ExampleControllerIntegration for Epic 6 compliance
func ExampleCustomSetup(logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("ExampleCustomSetup is deprecated: memory provider eliminated in Epic 6. Use ExampleControllerIntegration with global storage manager instead")
}
