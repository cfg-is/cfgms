// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package flatfile implements a flat-file storage provider for CFGMS.
//
// # Overview
//
// The flat-file provider stores configuration and audit data as files under a
// configured root directory. It is the OSS default for config storage (ADR-003).
//
// # Backup Responsibility
//
// The flat-file provider does NOT manage version history or replication. Backup
// is the operator's responsibility. Use filesystem snapshots, rsync, restic, or
// an equivalent tool to protect the root directory. A built-in helper is planned
// for sub-story B (cfg backup CLI).
//
// # File Layout
//
//	Config storage: <root>/<tenantID>/configs/<namespace>/<name>.<format>
//	Audit storage:  <root>/<tenantID>/audit/<YYYY-MM-DD>.jsonl
//
// # Limitations
//
//   - No automatic version history (use git-sync if you want PR-based change management)
//   - No replication (use PostgreSQL if you need HA)
//   - Single-writer only (not safe for multiple controllers sharing the same root)
//   - Atomic writes use temp-file + rename (crash-safe on Linux; Windows rename
//     across volumes may fail — keep root on a single filesystem)
//
// # Supported Stores
//
// This provider implements ConfigStore and AuditStore. All other store factory
// methods (CreateRuntimeStore, CreateRBACStore, CreateTenantStore,
// CreateRegistrationTokenStore, CreateClientTenantStore) return ErrNotSupported,
// as these belong to the business-data tier (SQLite, sub-story C).
package flatfile

import (
	"errors"
	"fmt"
	"os"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// ErrNotSupported is returned by store factory methods that are not implemented
// by the flat-file provider. These stores belong to the business-data tier.
var ErrNotSupported = errors.New("flatfile: operation not supported by flat-file provider")

// ErrImmutable is returned when attempting to mutate immutable data, such as
// adding an audit entry with a timestamp that falls before the configured
// retention period cutoff.
var ErrImmutable = errors.New("flatfile: data is immutable and cannot be modified")

// FlatFileProvider implements StorageProvider using the local filesystem.
// It is automatically registered on import via init().
type FlatFileProvider struct{}

// Name returns the provider name used for registration and configuration.
func (p *FlatFileProvider) Name() string {
	return "flatfile"
}

// Description returns a human-readable description of the provider.
func (p *FlatFileProvider) Description() string {
	return "Flat-file storage provider for OSS config and audit data; operator is responsible for backups"
}

// GetVersion returns the provider version.
func (p *FlatFileProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider capabilities.
// SupportsVersioning is false: flat-file does not auto-commit history.
func (p *FlatFileProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:   false,
		SupportsVersioning:     false, // flat-file does not auto-commit history
		SupportsFullTextSearch: false,
		SupportsEncryption:     false,
		SupportsCompression:    false,
		SupportsReplication:    false,
		SupportsSharding:       false,
		MaxBatchSize:           100,
		MaxConfigSize:          10 * 1024 * 1024, // 10MB per config
		MaxAuditRetentionDays:  3650,             // 10 years; operator manages disk
	}
}

// Available returns true if the flat-file provider can operate on this system.
// The flat-file provider only requires the OS filesystem and is always available.
func (p *FlatFileProvider) Available() (bool, error) {
	return true, nil
}

// getRootFromConfig extracts and validates the root directory from provider configuration.
func getRootFromConfig(config map[string]interface{}) (string, error) {
	root, ok := config["root"].(string)
	if !ok || root == "" {
		return "", fmt.Errorf("flatfile: 'root' directory is required in provider configuration")
	}

	// Ensure the root exists and is accessible
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			// Root does not exist yet; Create* methods will create it.
			return root, nil
		}
		return "", fmt.Errorf("flatfile: cannot stat root directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("flatfile: root path is not a directory")
	}
	return root, nil
}

// CreateConfigStore creates a flat-file-based configuration store.
// Config map must contain "root" (string): the root directory for config files.
func (p *FlatFileProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	root, err := getRootFromConfig(config)
	if err != nil {
		return nil, err
	}
	store, err := NewFlatFileConfigStore(root)
	if err != nil {
		return nil, fmt.Errorf("flatfile: failed to create config store: %w", err)
	}
	return store, nil
}

// CreateAuditStore creates a flat-file-based audit store.
// Config map must contain "root" (string). Optional: "max_retention_days" (int, default 90).
func (p *FlatFileProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	root, err := getRootFromConfig(config)
	if err != nil {
		return nil, err
	}
	maxRetentionDays := 90
	if days, ok := config["max_retention_days"].(int); ok && days > 0 {
		maxRetentionDays = days
	}
	store, err := NewFlatFileAuditStore(root, maxRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("flatfile: failed to create audit store: %w", err)
	}
	return store, nil
}

// CreateClientTenantStore returns ErrNotSupported.
// Client tenant data belongs in the business-data tier (SQLite / PostgreSQL).
func (p *FlatFileProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	return nil, ErrNotSupported
}

// CreateRBACStore returns ErrNotSupported.
// RBAC data belongs in the business-data tier.
func (p *FlatFileProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	return nil, ErrNotSupported
}

// CreateRuntimeStore returns ErrNotSupported.
// Runtime state belongs in the business-data tier.
func (p *FlatFileProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	return nil, ErrNotSupported
}

// CreateTenantStore returns ErrNotSupported.
// Tenant data belongs in the business-data tier.
func (p *FlatFileProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	return nil, ErrNotSupported
}

// CreateRegistrationTokenStore returns ErrNotSupported.
// Registration token data belongs in the business-data tier.
func (p *FlatFileProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	return nil, ErrNotSupported
}

// CreateSessionStore is not supported by the flatfile provider.
// Use the SQLite provider for durable session storage.
func (p *FlatFileProvider) CreateSessionStore(config map[string]interface{}) (interfaces.SessionStore, error) {
	return nil, ErrNotSupported
}

// CreateStewardStore creates a flat-file-based StewardStore.
// Config map must contain "root" (string): the root directory.
// Steward records are stored as JSON files under <root>/stewards/.
func (p *FlatFileProvider) CreateStewardStore(config map[string]interface{}) (interfaces.StewardStore, error) {
	root, err := getRootFromConfig(config)
	if err != nil {
		return nil, err
	}
	store, err := NewFlatFileStewardStore(root)
	if err != nil {
		return nil, fmt.Errorf("flatfile: failed to create steward store: %w", err)
	}
	return store, nil
}

// init auto-registers the flat-file provider so that a blank import is sufficient.
func init() {
	interfaces.RegisterStorageProvider(&FlatFileProvider{})
}
