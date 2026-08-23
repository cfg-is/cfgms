// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// --- in-memory PendingRegistrationStore for testing ---

type memPendingStore struct {
	mu      sync.RWMutex
	entries map[string]*business.PendingRegistrationEntry

	// error injection for testing error paths
	expireErr error
}

func newMemPendingStore() *memPendingStore {
	return &memPendingStore{entries: make(map[string]*business.PendingRegistrationEntry)}
}

func (s *memPendingStore) AddPending(_ context.Context, entry *business.PendingRegistrationEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *entry
	s.entries[entry.PendingID] = &cp
	return nil
}

func (s *memPendingStore) GetPendingByID(_ context.Context, pendingID string) (*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return nil, business.ErrPendingRegistrationNotFound
	}
	cp := *e
	return &cp, nil
}

func (s *memPendingStore) GetPendingByToken(_ context.Context, tokenStr string) (*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.TokenStr == tokenStr {
			cp := *e
			return &cp, nil
		}
	}
	return nil, business.ErrPendingRegistrationNotFound
}

func (s *memPendingStore) UpdateStatus(_ context.Context, pendingID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return business.ErrPendingRegistrationNotFound
	}
	e.Status = status
	return nil
}

func (s *memPendingStore) ListPending(_ context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.PendingRegistrationEntry
	for _, e := range s.entries {
		if tenantID == "" || e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *memPendingStore) ListAll(_ context.Context, tenantID string) ([]*business.PendingRegistrationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.PendingRegistrationEntry
	for _, e := range s.entries {
		if tenantID == "" || e.TenantID == tenantID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ExpireStale marks entries whose ExpiresAt is at or before cutoff and whose
// status is "pending" as "expired".
func (s *memPendingStore) ExpireStale(_ context.Context, cutoff time.Time) (int, error) {
	if s.expireErr != nil {
		return 0, s.expireErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, e := range s.entries {
		if e.Status == business.PendingRegistrationStatusPending && !e.ExpiresAt.After(cutoff) {
			e.Status = business.PendingRegistrationStatusExpired
			count++
		}
	}
	return count, nil
}

var _ business.PendingRegistrationStore = (*memPendingStore)(nil)

// getStatus returns the status for the given pendingID (test helper).
func (s *memPendingStore) getStatus(pendingID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[pendingID]
	if !ok {
		return ""
	}
	return e.Status
}

// --- helpers ---

// newPendingEntry creates a pending entry where ExpiresAt = RegisteredAt so that
// ExpireStale(ctx, now.Add(-timeout)) considers the entry stale when
// RegisteredAt < now-timeout.
func newPendingEntry(id string, registeredAt time.Time) *business.PendingRegistrationEntry {
	return &business.PendingRegistrationEntry{
		PendingID:    id,
		StewardID:    "steward-" + id,
		TenantID:     "tenant-1",
		TokenStr:     "tok-" + id,
		SourceIP:     "10.0.0.1",
		RegisteredAt: registeredAt,
		ExpiresAt:    registeredAt, // expiry is registration time; job sweeps with now-timeout cutoff
		Status:       business.PendingRegistrationStatusPending,
	}
}

// TestPendingExpiry_StaleEntryExpired verifies that an entry registered 6 days
// ago is marked expired and an entry registered 1 day ago is left untouched.
func TestPendingExpiry_StaleEntryExpired(t *testing.T) {
	store := newMemPendingStore()
	ctx := context.Background()

	now := time.Now()
	stale := newPendingEntry("p-stale", now.Add(-6*24*time.Hour))
	fresh := newPendingEntry("p-fresh", now.Add(-1*24*time.Hour))

	require.NoError(t, store.AddPending(ctx, stale))
	require.NoError(t, store.AddPending(ctx, fresh))

	timeout := 5 * 24 * time.Hour

	job := registration.NewPendingExpiryJob(registration.PendingExpiryConfig{
		Store:         store,
		Timeout:       timeout,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})

	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, job.Start(ctx2))
	<-ctx2.Done()

	assert.Equal(t, business.PendingRegistrationStatusExpired, store.getStatus("p-stale"),
		"entry registered 6 days ago must be expired")
	assert.Equal(t, business.PendingRegistrationStatusPending, store.getStatus("p-fresh"),
		"entry registered 1 day ago must remain pending")
}

// TestPendingExpiry_ExpireStaleError verifies the job logs the error and
// continues running when ExpireStale returns an error rather than panicking.
func TestPendingExpiry_ExpireStaleError(t *testing.T) {
	store := newMemPendingStore()
	store.expireErr = errPendingTest("injected ExpireStale error")

	job := registration.NewPendingExpiryJob(registration.PendingExpiryConfig{
		Store:         store,
		Timeout:       5 * 24 * time.Hour,
		CheckInterval: 10 * time.Millisecond,
		Logger:        logging.NewNoopLogger(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// Job must not panic when ExpireStale always errors.
	require.NoError(t, job.Start(ctx))
	<-ctx.Done()
}

type errPendingTest string

func (e errPendingTest) Error() string { return string(e) }

// --- PendingExpiryJob: store requirements (#3491) ---

// buildPendingExpiryPostgresDSN constructs a Postgres DSN from the same env
// vars used by the cluster storage tests.
func buildPendingExpiryPostgresDSN() string {
	pw := testutil.GetTestDBPassword()
	port := 5432
	if p := os.Getenv("CFGMS_TEST_DB_PORT"); p != "" {
		if pi, err := strconv.Atoi(p); err == nil {
			port = pi
		}
	}
	dbName := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_NAME"); v != "" {
		dbName = v
	}
	dbUser := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_USER"); v != "" {
		dbUser = v
	}
	return fmt.Sprintf("host=localhost port=%d dbname=%s user=%s password=%s sslmode=disable",
		port, dbName, dbUser, pw)
}

// skipPendingExpiryTestIfNoPostgres skips the test when Postgres is unreachable.
func skipPendingExpiryTestIfNoPostgres(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Postgres test in short mode")
	}
	dsn := buildPendingExpiryPostgresDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("Postgres not available:", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skip("Postgres not reachable:", err)
	}
	return dsn
}

// TestPendingExpiryJobStoreRequirements_DeclarationShape verifies that
// registration.StoreRequirements declares exactly one requirement:
// PendingRegistrationStore as required for the "registration" subsystem.
func TestPendingExpiryJobStoreRequirements_DeclarationShape(t *testing.T) {
	reqs := registration.StoreRequirements
	require.Len(t, reqs, 1, "PendingExpiryJob must declare exactly one required store")
	assert.Equal(t, "registration", reqs[0].Subsystem,
		"subsystem must be named 'registration' so startup errors are operator-readable")
	assert.Equal(t, interfaces.StoreNamePendingRegistration, reqs[0].Store,
		"declaration must reference PendingRegistrationStore")
	assert.Equal(t, interfaces.RequirementRequired, reqs[0].Severity,
		"expiry job cannot function without this store: severity must be Required")
}

// TestPendingExpiryJobStoreRequirements_OSSCompositionPassesValidation verifies that a
// controller composed with the OSS (flatfile+SQLite) storage manager satisfies
// registration.StoreRequirements — the OSS clean-start acceptance criterion.
func TestPendingExpiryJobStoreRequirements_OSSCompositionPassesValidation(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	err = interfaces.ValidateStorageRequirements(sm, registration.StoreRequirements)
	require.NoError(t, err,
		"OSS composite storage manager must satisfy PendingExpiryJob store requirements")
}

// TestPendingExpiryJobStoreRequirements_ClusterCompositionPassesValidation verifies that a
// controller composed with the database-provider storage manager satisfies
// registration.StoreRequirements — the cluster clean-start acceptance criterion.
// Skipped when Postgres is unreachable.
func TestPendingExpiryJobStoreRequirements_ClusterCompositionPassesValidation(t *testing.T) {
	pgDSN := skipPendingExpiryTestIfNoPostgres(t)

	sm, err := interfaces.CreateClusterStorageManager(pgDSN, "test-hmac-key-32-bytes-padding--", nil)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	err = interfaces.ValidateStorageRequirements(sm, registration.StoreRequirements)
	require.NoError(t, err,
		"cluster storage manager must satisfy PendingExpiryJob store requirements")
}

// TestPendingExpiryJobStoreRequirements_DecliningProviderFailsStartup verifies that
// when the backing provider declines PendingRegistrationStore, ValidateStorageRequirements
// returns an error that names the "registration" subsystem. This guards against the #3400
// condition — a provider gap that previously surfaced as a 503 at request time rather than
// a startup failure.
//
// The test reproduces the condition against a real database provider implementation
// that overrides only CreatePendingRegistrationStore (via
// pkgtesting.SetupDecliningPendingRegistrationClusterStorage), composed through the
// real CreateClusterStorageManager path — not a hand-built store-less StorageManager.
// Skipped when Postgres is unreachable.
func TestPendingExpiryJobStoreRequirements_DecliningProviderFailsStartup(t *testing.T) {
	pgDSN := skipPendingExpiryTestIfNoPostgres(t)

	sm := pkgtesting.SetupDecliningPendingRegistrationClusterStorage(t, pgDSN)
	require.False(t, sm.HasStore(interfaces.StoreNamePendingRegistration),
		"a declining provider must leave PendingRegistrationStore absent from the composed manager")

	err := interfaces.ValidateStorageRequirements(sm, registration.StoreRequirements)
	require.Error(t, err,
		"a real provider declining PendingRegistrationStore must block startup via ValidateStorageRequirements")
	assert.Contains(t, err.Error(), "registration",
		"startup error must name the registration subsystem so operators can diagnose the gap")
	assert.Contains(t, err.Error(), string(interfaces.StoreNamePendingRegistration),
		"startup error must name the missing store")
}
