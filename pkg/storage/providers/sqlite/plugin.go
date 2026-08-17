// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements the SQLite storage provider for CFGMS business data.
//
// This is the default OSS backend for the business-data tier (ADR-003).
// It uses modernc.org/sqlite, a pure-Go port of SQLite, which builds with
// CGO_ENABLED=0 and cross-compiles cleanly to all steward platforms.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver (CGO-free)

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Compile-time assertions that SQLiteProvider satisfies the required interfaces.
var (
	_ interfaces.StorageProvider     = (*SQLiteProvider)(nil)
	_ interfaces.BusinessStoreOpener = (*SQLiteProvider)(nil)
)

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
		MaxAuditRetentionDays:  3650,             // 10 years
	}
}

// ClusterCapable returns true if this provider can serve as shared state across
// multiple CFGMS controller nodes in cluster mode.
func (p *SQLiteProvider) ClusterCapable() bool { return false }

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
	// #nosec G304 -- dir is the validated administrator-configured SQLite
	// storage directory and probe is a fixed temporary filename beneath it.
	f, err := os.Create(probe)
	if err != nil {
		return false, fmt.Errorf("sqlite: directory %s is not writable: %w", dir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)

	return true, nil
}

// openDB opens (or creates) a SQLite database at path and enables WAL mode and foreign keys.
//
// Pragmas are passed via DSN _pragma=name(value) tokens rather than db.Exec
// because database/sql maintains a connection pool — db.Exec runs on one
// pool connection and the pragma never propagates to siblings. Under
// concurrent load (TestSQLite_TwoStoreInstances_ConcurrentWrites_NoCorruption
// hit this on Windows CI) a sibling connection without busy_timeout would
// return SQLITE_BUSY immediately on lock contention, defeating the 5s
// retry budget. modernc.org/sqlite applies _pragma= tokens at every
// connection open via its ConnectionHook, so every pool connection ends
// up with the pragmas applied.
//
// Pragma order in the DSN matters: busy_timeout MUST appear before
// journal_mode=WAL because the journal-mode change itself can hit BUSY
// under contention, and SQLite only honors busy_timeout once it's set.
// On a fresh DB this is irrelevant; on a contended one it's the
// difference between "WAL set up correctly" and "second opener crashes
// at openAndInit" (the Linux CI failure mode in
// TestSQLite_TwoProcesses_ConcurrentWrites_NoCorruption).
func openDB(path string) (*sql.DB, error) {
	// busy_timeout 15s (was 5s): TestSQLite_TwoProcesses_ConcurrentWrites
	// occasionally failed on Windows CI runners with SQLITE_BUSY mid-loop
	// (e.g. iter 25 of 500). The 5s budget was sometimes exhausted by a
	// single contended commit on CI's I/O. 15s is still small relative to
	// real-world controller batch commits and gives Windows CI's I/O
	// variance enough headroom without hiding genuine deadlocks (those
	// would still surface after 15s).
	// File-backed databases use WAL for genuine multi-connection concurrency.
	const filePragmas = "_pragma=busy_timeout(15000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	// In-memory databases are pinned to a single connection (see below), so
	// neither WAL nor shared-cache buys anything: one connection can never
	// contend with itself. Shared-cache in-memory is actively harmful — it
	// routes every statement through the pure-Go driver's process-global
	// shared-cache lock manager, whose lock-ordering can wedge a CREATE
	// TABLE/INDEX in VDBE exec indefinitely when many parallel tests are
	// initialising their own memory schemas at once. busy_timeout does not
	// cover that wait, so the transaction never completes and the test binary
	// hangs to its timeout (Issue #2967: schema.go initialiseSchema hang seen
	// in features/controller/api). A private, single-connection memory DB with
	// the default rollback journal removes the shared-cache lock manager from
	// the picture entirely while preserving per-pool isolation and data sharing
	// across all stores that hold the same *sql.DB.
	const memPragmas = "_pragma=busy_timeout(15000)&_pragma=foreign_keys(on)"

	inMemory := path == ":memory:" || strings.Contains(path, "mode=memory")

	var dsn string
	switch {
	case inMemory:
		// Collapse every in-memory request (":memory:" or a named
		// "file:...?mode=memory[&cache=shared]" DSN) to a private, unnamed
		// memory DB. The single pinned connection means each pool owns exactly
		// one private database that lives for the pool's lifetime; the caller's
		// name only ever served to distinguish shared caches, which no longer
		// exist here, so dropping it is safe and isolation becomes automatic.
		dsn = "file::memory:?" + memPragmas
	case strings.HasPrefix(path, "file:"):
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		dsn = path + sep + filePragmas
	default:
		dsn = "file:" + path + "?" + filePragmas
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to open %s: %w", path, err)
	}

	// A private in-memory database exists only while at least one connection to
	// it remains open: SQLite frees the database the instant the connection pool
	// drops to zero live handles. Under a parallel test suite the default
	// multi-connection pool churns and closes idle connections under memory
	// pressure, tearing the database down mid-run — after which the next query
	// hits a freed handle and the driver nil-dereferences. Pin such databases to
	// a single, never-expiring connection so the backing store lives for the
	// pool's entire lifetime, and so all stores sharing the *sql.DB see one
	// consistent database. File-backed databases keep the default pool (WAL
	// gives real concurrency).
	if inMemory {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)
		db.SetConnMaxIdleTime(0)
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

// isMemoryPath reports whether path denotes an in-memory SQLite database.
// In-memory databases are only ever created by tests (production always uses a
// file). They are always empty at open, so the full schema-DDL/back-fill pass
// can be replaced by the deserialize fast-path in openAndInit.
func isMemoryPath(path string) bool {
	return path == ":memory:" || strings.Contains(path, "mode=memory")
}

// schemaTemplate holds a serialized page image of a freshly-initialised database,
// built exactly once per process. Running the full schema DDL (~15 CREATE TABLEs
// plus indexes and three back-fill probes) costs ~176ms per open under the race
// detector; a single large test package (features/controller/api) opens ~900
// in-memory databases, which alone pushed the suite past the 5-minute test-fast
// budget and produced the timeout captured in initializeSchema. Deserializing a
// prebuilt page image is a memcpy (~15ms under -race) and yields a byte-identical
// schema because the template is itself produced by initializeSchema.
var (
	schemaTemplateOnce sync.Once
	schemaTemplateData []byte
	schemaTemplateErr  error
)

// serializer/deserializer are the modernc.org/sqlite driver-connection capabilities
// used by the in-memory fast-path. They are defined here (not imported) so the
// provider does not take a compile-time dependency on driver internals: if a future
// driver lacks them, the type assertions fail and openAndInit falls back to the
// full DDL path.
type serializer interface{ Serialize() ([]byte, error) }
type deserializer interface{ Deserialize([]byte) error }

// buildSchemaTemplate initialises a throwaway private in-memory database with the
// full DDL path and returns its serialized page image.
func buildSchemaTemplate() ([]byte, error) {
	// Private cache (no cache=shared) and a fixed name: this database is used only
	// to produce the template and is closed immediately, so it must not collide
	// with, or be visible to, any test database.
	db, err := openDB("file:cfgms-schema-template?mode=memory")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := initializeSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("sqlite: building schema template: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	var data []byte
	rawErr := conn.Raw(func(dc any) error {
		s, ok := dc.(serializer)
		if !ok {
			return fmt.Errorf("sqlite: driver connection does not support Serialize")
		}
		b, err := s.Serialize()
		if err != nil {
			return err
		}
		data = b
		return nil
	})
	if rawErr != nil {
		return nil, rawErr
	}
	return data, nil
}

// applySchemaTemplate installs the process-wide schema template into an empty
// in-memory database. It returns an error (leaving the DB untouched) when the
// template is unavailable or the driver lacks Deserialize, so the caller can fall
// back to the full DDL path. If the database is already initialised (another
// handle to the same shared-cache database ran first) it is a no-op, mirroring
// the CREATE TABLE IF NOT EXISTS idempotency of initializeSchema — deserialize
// replaces the whole database, so it must never run over existing data.
func applySchemaTemplate(ctx context.Context, db *sql.DB) error {
	schemaTemplateOnce.Do(func() {
		schemaTemplateData, schemaTemplateErr = buildSchemaTemplate()
	})
	if schemaTemplateErr != nil {
		return schemaTemplateErr
	}

	already, err := tableExists(ctx, db, "schema_version")
	if err != nil {
		return err
	}
	if already {
		return nil
	}

	// Deserialize must run on the same connection that later queries use. In-memory
	// databases are pinned to a single pool connection (openDB sets MaxOpenConns(1)),
	// so checking the connection out here and returning it makes the installed schema
	// visible to every store that shares this *sql.DB.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	return conn.Raw(func(dc any) error {
		d, ok := dc.(deserializer)
		if !ok {
			return fmt.Errorf("sqlite: driver connection does not support Deserialize")
		}
		return d.Deserialize(schemaTemplateData)
	})
}

// openAndInit opens a SQLite DB at the given path, applies WAL pragma, and runs schema DDL.
// In-memory databases (tests only) take the deserialize fast-path; a failure there
// falls through to the full DDL path so correctness never depends on the optimisation.
func openAndInit(path string) (*sql.DB, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if isMemoryPath(path) {
		if err := applySchemaTemplate(ctx, db); err == nil {
			return db, nil
		}
		// Fall through to the full DDL path on any fast-path failure.
	}
	if err := initializeSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: schema initialisation failed: %w", err)
	}
	return db, nil
}

// ---- Factory methods --------------------------------------------------------

// CreateTenantStore returns a SQLite-backed TenantStore.
func (p *SQLiteProvider) CreateTenantStore(config map[string]interface{}) (business.TenantStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteTenantStore{db: db}, nil
}

// CreateClientTenantStore returns a SQLite-backed ClientTenantStore with M365 extension columns.
func (p *SQLiteProvider) CreateClientTenantStore(config map[string]interface{}) (business.ClientTenantStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteClientTenantStore{db: db}, nil
}

// CreateAuditStore returns a SQLite-backed AuditStore (append-only).
func (p *SQLiteProvider) CreateAuditStore(config map[string]interface{}) (business.AuditStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteAuditStore{db: db}, nil
}

// CreateRBACStore returns a SQLite-backed RBACStore.
func (p *SQLiteProvider) CreateRBACStore(config map[string]interface{}) (business.RBACStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteRBACStore{db: db}, nil
}

// CreateRegistrationTokenStore returns a SQLite-backed RegistrationTokenStore.
func (p *SQLiteProvider) CreateRegistrationTokenStore(config map[string]interface{}) (business.RegistrationTokenStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteRegistrationTokenStore{db: db}, nil
}

// CreateSessionStore returns a SQLite-backed SessionStore (durable Persistent=true sessions only).
func (p *SQLiteProvider) CreateSessionStore(config map[string]interface{}) (business.SessionStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteSessionStore{db: db}, nil
}

// CreateConfigStore is not supported by the SQLite provider.
// Config data uses the flat-file provider (OSS) or PostgreSQL (commercial).
func (p *SQLiteProvider) CreateConfigStore(config map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return nil, business.ErrNotSupported
}

// CreateStewardStore returns a SQLite-backed StewardStore for fleet registry persistence.
func (p *SQLiteProvider) CreateStewardStore(config map[string]interface{}) (business.StewardStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteStewardStore{db: db}, nil
}

// CreateCommandStore returns a SQLite-backed CommandStore for durable command dispatch state.
func (p *SQLiteProvider) CreateCommandStore(config map[string]interface{}) (business.CommandStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteCommandStore{db: db}, nil
}

// CreateTriggerStore returns a SQLite-backed TriggerStore for durable workflow trigger persistence.
func (p *SQLiteProvider) CreateTriggerStore(config map[string]interface{}) (business.TriggerStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteTriggerStore{db: db}, nil
}

// CreatePushStore returns a SQLite-backed PushStore for durable push-state persistence.
func (p *SQLiteProvider) CreatePushStore(config map[string]interface{}) (business.PushStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLitePushStore{db: db}, nil
}

// CreatePendingRegistrationStore returns a SQLite-backed PendingRegistrationStore (Issue #1599).
func (p *SQLiteProvider) CreatePendingRegistrationStore(config map[string]interface{}) (business.PendingRegistrationStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLitePendingRegistrationStore{db: db}, nil
}

// CreateSessionTokenStore returns a SQLite-backed session.Store for pkg/session.Manager
// (Issue #2736). This store is distinct from CreateSessionStore (business.SessionStore):
// it uses token-hash keys and enables sessions to survive controller restarts and to
// validate across cluster nodes that share the same SQLite file.
func (p *SQLiteProvider) CreateSessionTokenStore(config map[string]interface{}) (*SQLiteSessionTokenStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteSessionTokenStore{db: db}, nil
}

// CreateIPTrustStore is not yet supported by the SQLite provider.
// IP trust storage is implemented by the database (PostgreSQL) provider (Issue #1691).
func (p *SQLiteProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return nil, business.ErrNotSupported
}

// CreateAlertStore is not supported by the SQLite provider.
// Alert storage is implemented by the database (PostgreSQL) and flatfile providers (Issue #3266).
func (p *SQLiteProvider) CreateAlertStore(_ map[string]interface{}) (business.AlertStore, error) {
	return nil, business.ErrNotSupported
}

// OpenBusinessStores implements interfaces.BusinessStoreOpener.
// It opens the SQLite database at path exactly once, runs schema initialisation,
// and returns all seven business stores sharing the same *sql.DB connection pool.
// This prevents WAL read-lock slot exhaustion on Windows CI where opening seven
// separate *sql.DB connections to the same file causes lock contention.
// database/sql.DB.Close is idempotent, so StorageManager.Close safely calls it
// on every store without error even though they share the underlying handle.
func (p *SQLiteProvider) OpenBusinessStores(path string) (*interfaces.BusinessStoreBundle, error) {
	db, err := openAndInit(path)
	if err != nil {
		return nil, err
	}
	return &interfaces.BusinessStoreBundle{
		RBAC:                &SQLiteRBACStore{db: db},
		Tenant:              &SQLiteTenantStore{db: db},
		ClientTenant:        &SQLiteClientTenantStore{db: db},
		RegistrationToken:   &SQLiteRegistrationTokenStore{db: db},
		Session:             &SQLiteSessionStore{db: db},
		Command:             &SQLiteCommandStore{db: db},
		Trigger:             &SQLiteTriggerStore{db: db},
		Push:                &SQLitePushStore{db: db},
		PendingRegistration: &SQLitePendingRegistrationStore{db: db},
		PendingRefresh:      &SQLitePendingRefreshStore{db: db},
		RefreshPolicy:       &SQLiteRefreshPolicyStore{db: db},
		AssurancePolicy:     &SQLiteAssurancePolicyStore{db: db},
		TenantCrossing:      &SQLiteTenantCrossingStore{db: db},
	}, nil
}

// CreateTenantCrossingStore returns a SQLite-backed TenantCrossingStore
// (ADR-025 Decision 2). Implements interfaces.TenantCrossingStoreCreator.
func (p *SQLiteProvider) CreateTenantCrossingStore(config map[string]interface{}) (business.TenantCrossingStore, error) {
	db, err := openAndInit(getPath(config))
	if err != nil {
		return nil, err
	}
	return &SQLiteTenantCrossingStore{db: db}, nil
}

// init auto-registers the SQLite provider so it is available after a blank import.
func init() {
	interfaces.RegisterStorageProvider(&SQLiteProvider{})
}
