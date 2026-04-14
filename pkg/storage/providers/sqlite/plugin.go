// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements the SQLite storage provider for CFGMS business data.
//
// This is the default OSS backend for the business-data tier (ADR-003).
// It requires CGo because it uses github.com/mattn/go-sqlite3.
// Cross-compile targets that disable CGo should use the modernc.org/sqlite driver instead;
// see docs/architecture/storage-architecture.md for guidance.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver (requires CGo)

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Compile-time assertion that SQLiteProvider satisfies StorageProvider.
var _ interfaces.StorageProvider = (*SQLiteProvider)(nil)

// SQLiteProvider implements the StorageProvider interface using SQLite for persistence.
// It is the default OSS backend for all business-data stores.
type SQLiteProvider struct {
	// basePath is an optional directory used by Available() to verify writability.
	// The registered provider (from init()) leaves basePath empty, which means
	// Available() always returns true (the SQLite library is present).
	basePath string
}

// NewSQLiteProvider creates a provider that checks the given directory for writability.
func NewSQLiteProvider(basePath string) *SQLiteProvider {
	return &SQLiteProvider{basePath: basePath}
}

// Name returns the provider name used for registration and lookup.
func (p *SQLiteProvider) Name() string { return "sqlite" }

// Description returns a human-readable description of the provider.
func (p *SQLiteProvider) Description() string {
	return "SQLite business-data provider — OSS default for tenants, RBAC, audit, sessions, and registration tokens"
}

// GetVersion returns the provider version.
func (p *SQLiteProvider) GetVersion() string { return "1.0.0" }

// GetCapabilities describes what this provider supports.
func (p *SQLiteProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:   true,
		SupportsVersioning:     false,
		SupportsFullTextSearch: false,
		SupportsEncryption:     false,
		SupportsCompression:    false,
		SupportsReplication:    false,
		SupportsSharding:       false,
		MaxBatchSize:           500,
		MaxConfigSize:          10 * 1024 * 1024, // 10 MB
		MaxAuditRetentionDays:  3650,              // 10 years
	}
}

// Available reports whether the SQLite library is usable and, when basePath is set,
// whether that directory exists and is writable.
//
// For in-memory paths (":memory:" or paths containing "mode=memory") it always returns true.
// For a non-existent path it returns false.
func (p *SQLiteProvider) Available() (bool, error) {
	if p.basePath == "" {
		return true, nil // library is available; no specific path to verify
	}

	// In-memory databases are always available
	if p.basePath == ":memory:" || strings.Contains(p.basePath, "mode=memory") {
		return true, nil
	}

	dir := p.basePath
	if ext := filepath.Ext(p.basePath); ext != "" {
		// basePath looks like a file path — check its parent directory
		dir = filepath.Dir(p.basePath)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return false, fmt.Errorf("sqlite: directory %s does not exist or is not accessible: %w", dir, err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("sqlite: %s is not a directory", dir)
	}

	// Probe write access with a temporary marker file
	probe := filepath.Join(dir, ".cfgms_sqlite_probe")
	f, err := os.Create(probe)
	if err != nil {
		return false, fmt.Errorf("sqlite: directory %s is not writable: %w", dir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)

	return true, nil
}

// openDB opens (or creates) a SQLite database at path and enables WAL mode and foreign keys.
func openDB(path string) (*sql.DB, error) {
	// mattn/go-sqlite3 accepts DSN parameters via the path.
	// Append shared-cache for in-memory so multiple connections in tests share state.
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared&_journal_mode=WAL&_foreign_keys=on"
	} else if !strings.HasPrefix(path, "file:") {
		dsn = fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on", path)
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: failed to ping %s: %w", path, err)
	}
	return db, nil
}

// getPath extracts the SQLite file path from the config map.
func getPath(config map[string]interface{}) string {
	if v, ok := config["path"].(string); ok && v != "" {
		return v
	}
	return ":memory:"
}

// nowUTC returns the current time in UTC (facilitates testing overrides if needed).
func nowUTC() time.Time { return time.Now().UTC() }

// openAndInit opens a SQLite DB at the given path, applies WAL pragma, and runs schema DDL.
func openAndInit(path string) (*sql.DB, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := initializeSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: schema initialisation failed: %w", err)
	}
	return db, nil
}

// ---- Factory methods --------------------------------------------------------

// CreateTenantStore returns a SQLite-backed TenantStore.
func (p *SQLiteProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteTenantStore{db: db}, nil
}

// CreateClientTenantStore returns a SQLite-backed ClientTenantStore with M365 extension columns.
func (p *SQLiteProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteClientTenantStore{db: db}, nil
}

// CreateAuditStore returns a SQLite-backed AuditStore (append-only).
func (p *SQLiteProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteAuditStore{db: db}, nil
}

// CreateRBACStore returns a SQLite-backed RBACStore.
func (p *SQLiteProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteRBACStore{db: db}, nil
}

// CreateRegistrationTokenStore returns a SQLite-backed RegistrationTokenStore.
func (p *SQLiteProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteRegistrationTokenStore{db: db}, nil
}

// CreateSessionStore returns a SQLite-backed SessionStore (durable Persistent=true sessions only).
func (p *SQLiteProvider) CreateSessionStore(config map[string]interface{}) (interfaces.SessionStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteSessionStore{db: db}, nil
}

// CreateConfigStore is not implemented by the SQLite provider.
// Config data uses the flat-file provider (OSS) or PostgreSQL (commercial).
func (p *SQLiteProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	return nil, interfaces.ErrNotSupported
}

// CreateRuntimeStore is not implemented by the SQLite provider.
// Durable session state is provided by CreateSessionStore; ephemeral state belongs in pkg/cache.
func (p *SQLiteProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	return nil, interfaces.ErrNotSupported
}

// init auto-registers the SQLite provider so it is available after a blank import.
func init() {
	interfaces.RegisterStorageProvider(&SQLiteProvider{})
}
