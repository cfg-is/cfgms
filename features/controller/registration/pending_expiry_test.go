// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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
