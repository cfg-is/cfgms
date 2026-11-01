// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemUpgradeStore is a minimal in-memory UpgradeStore for contract tests.
type inMemUpgradeStore struct {
	mu      sync.RWMutex
	records map[string]*business.UpgradeRecord
}

func newInMemUpgradeStore() business.UpgradeStore {
	return &inMemUpgradeStore{records: make(map[string]*business.UpgradeRecord)}
}

func (s *inMemUpgradeStore) CreateUpgrade(_ context.Context, record *business.UpgradeRecord) error {
	if record == nil {
		return errTestNilRecord
	}
	if len(record.BundleSignature) == 0 {
		return errTestMissingSignature
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return errTestDuplicateID
	}
	cp := *record
	s.records[record.ID] = &cp
	return nil
}

func (s *inMemUpgradeStore) UpdateUpgradeStatus(_ context.Context, id string, status business.UpgradeStatus, errorMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok {
		return business.ErrUpgradeNotFound
	}
	r.Status = status
	r.ErrorMessage = errorMsg
	if status == business.UpgradeStatusCommitted ||
		status == business.UpgradeStatusRolledBack ||
		status == business.UpgradeStatusFailed {
		now := time.Now().UTC()
		r.CompletedAt = &now
	}
	return nil
}

func (s *inMemUpgradeStore) GetUpgrade(_ context.Context, id string) (*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrUpgradeNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *inMemUpgradeStore) ListUpgradesBySteward(_ context.Context, stewardID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.StewardID == stewardID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *inMemUpgradeStore) ListUpgradesByTenant(_ context.Context, tenantID string) ([]*business.UpgradeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*business.UpgradeRecord
	for _, r := range s.records {
		if r.TenantID == tenantID {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *inMemUpgradeStore) HealthCheck(_ context.Context) error { return nil }

func (s *inMemUpgradeStore) Initialize(_ context.Context) error { return nil }

func (s *inMemUpgradeStore) Close() error { return nil }

// test-only sentinel errors
var (
	errTestNilRecord        = errTestStr("nil record")
	errTestMissingSignature = errTestStr("bundle signature is required")
	errTestDuplicateID      = errTestStr("duplicate upgrade ID")
)

type errTestStr string

func (e errTestStr) Error() string { return string(e) }

// Compile-time assertion that inMemUpgradeStore satisfies UpgradeStore.
var _ business.UpgradeStore = (*inMemUpgradeStore)(nil)

// --- Helpers ---

func newTestUpgradeRecord(id, stewardID, tenantID string) *business.UpgradeRecord {
	return &business.UpgradeRecord{
		ID:        id,
		StewardID: stewardID,
		TenantID:  tenantID,
		Version:   "1.2.3",
		Platform:  "linux",
		Arch:      "amd64",
		SHA256:    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Status:    business.UpgradeStatusDispatched,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "operator@example.com",
			TenantID:   tenantID,
			AuthMethod: "api_key",
		},
		Publisher:       "cfgms",
		SignatureDigest: "deadbeefdeadbeefdeadbeefdeadbeef",
		BundleSignature: make([]byte, 64),
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
		DispatchedAt:    time.Now().UTC(),
	}
}

// --- Contract tests ---

func TestUpgradeStore_Contract(t *testing.T) {
	store := newInMemUpgradeStore()
	ctx := context.Background()

	// Initialize and HealthCheck must succeed on a fresh store.
	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	t.Run("create and get", func(t *testing.T) {
		rec := newTestUpgradeRecord("upg-1", "steward-a", "tenant-1")
		require.NoError(t, store.CreateUpgrade(ctx, rec))

		got, err := store.GetUpgrade(ctx, "upg-1")
		require.NoError(t, err)
		assert.Equal(t, "upg-1", got.ID)
		assert.Equal(t, "steward-a", got.StewardID)
		assert.Equal(t, "tenant-1", got.TenantID)
		assert.Equal(t, business.UpgradeStatusDispatched, got.Status)
		assert.Equal(t, "cfgms", got.Publisher)
		assert.Len(t, got.BundleSignature, 64)
		assert.Len(t, got.OperationNonce, 32)
		assert.Equal(t, "operator@example.com", got.InitiatedBy.Subject)
	})

	t.Run("get not found", func(t *testing.T) {
		_, err := store.GetUpgrade(ctx, "no-such-id")
		assert.ErrorIs(t, err, business.ErrUpgradeNotFound)
	})

	t.Run("create rejects empty BundleSignature", func(t *testing.T) {
		rec := newTestUpgradeRecord("upg-nosig", "steward-a", "tenant-1")
		rec.BundleSignature = nil
		err := store.CreateUpgrade(ctx, rec)
		require.Error(t, err, "CreateUpgrade must reject nil BundleSignature")

		rec.BundleSignature = []byte{}
		err = store.CreateUpgrade(ctx, rec)
		require.Error(t, err, "CreateUpgrade must reject empty BundleSignature")
	})

	t.Run("update status through all states", func(t *testing.T) {
		rec := newTestUpgradeRecord("upg-states", "steward-b", "tenant-1")
		require.NoError(t, store.CreateUpgrade(ctx, rec))

		states := []business.UpgradeStatus{
			business.UpgradeStatusDownloaded,
			business.UpgradeStatusSwapped,
			business.UpgradeStatusCommitted,
		}
		for _, s := range states {
			require.NoError(t, store.UpdateUpgradeStatus(ctx, "upg-states", s, ""))
			got, err := store.GetUpgrade(ctx, "upg-states")
			require.NoError(t, err)
			assert.Equal(t, s, got.Status)
		}

		// Terminal state sets CompletedAt.
		got, err := store.GetUpgrade(ctx, "upg-states")
		require.NoError(t, err)
		require.NotNil(t, got.CompletedAt)
	})

	t.Run("update status to failed sets error message", func(t *testing.T) {
		rec := newTestUpgradeRecord("upg-fail", "steward-b", "tenant-1")
		require.NoError(t, store.CreateUpgrade(ctx, rec))

		require.NoError(t, store.UpdateUpgradeStatus(ctx, "upg-fail", business.UpgradeStatusFailed, "disk full"))
		got, err := store.GetUpgrade(ctx, "upg-fail")
		require.NoError(t, err)
		assert.Equal(t, business.UpgradeStatusFailed, got.Status)
		assert.Equal(t, "disk full", got.ErrorMessage)
		require.NotNil(t, got.CompletedAt)
	})

	t.Run("update status to rolled_back sets error message", func(t *testing.T) {
		rec := newTestUpgradeRecord("upg-rb", "steward-c", "tenant-2")
		require.NoError(t, store.CreateUpgrade(ctx, rec))

		require.NoError(t, store.UpdateUpgradeStatus(ctx, "upg-rb", business.UpgradeStatusRolledBack, "health check failed"))
		got, err := store.GetUpgrade(ctx, "upg-rb")
		require.NoError(t, err)
		assert.Equal(t, business.UpgradeStatusRolledBack, got.Status)
		assert.Equal(t, "health check failed", got.ErrorMessage)
	})

	t.Run("update status not found", func(t *testing.T) {
		err := store.UpdateUpgradeStatus(ctx, "ghost", business.UpgradeStatusFailed, "n/a")
		assert.ErrorIs(t, err, business.ErrUpgradeNotFound)
	})

	t.Run("list by steward", func(t *testing.T) {
		r1 := newTestUpgradeRecord("upg-ls-1", "steward-x", "tenant-1")
		r1.CreatedAt = time.Now().UTC().Add(-2 * time.Second)
		r2 := newTestUpgradeRecord("upg-ls-2", "steward-x", "tenant-1")
		r2.CreatedAt = time.Now().UTC().Add(-1 * time.Second)
		r3 := newTestUpgradeRecord("upg-ls-3", "steward-y", "tenant-1")

		require.NoError(t, store.CreateUpgrade(ctx, r1))
		require.NoError(t, store.CreateUpgrade(ctx, r2))
		require.NoError(t, store.CreateUpgrade(ctx, r3))

		list, err := store.ListUpgradesBySteward(ctx, "steward-x")
		require.NoError(t, err)
		assert.Len(t, list, 2)
		// Most recent first.
		assert.Equal(t, "upg-ls-2", list[0].ID)
		assert.Equal(t, "upg-ls-1", list[1].ID)

		// steward-y has exactly one.
		listY, err := store.ListUpgradesBySteward(ctx, "steward-y")
		require.NoError(t, err)
		assert.Len(t, listY, 1)

		// Unknown steward returns empty slice, not an error.
		listNone, err := store.ListUpgradesBySteward(ctx, "steward-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	t.Run("list by tenant", func(t *testing.T) {
		r1 := newTestUpgradeRecord("upg-lt-1", "steward-p", "tenant-A")
		r2 := newTestUpgradeRecord("upg-lt-2", "steward-q", "tenant-A")
		r3 := newTestUpgradeRecord("upg-lt-3", "steward-p", "tenant-B")

		require.NoError(t, store.CreateUpgrade(ctx, r1))
		require.NoError(t, store.CreateUpgrade(ctx, r2))
		require.NoError(t, store.CreateUpgrade(ctx, r3))

		listA, err := store.ListUpgradesByTenant(ctx, "tenant-A")
		require.NoError(t, err)
		assert.Len(t, listA, 2)

		listB, err := store.ListUpgradesByTenant(ctx, "tenant-B")
		require.NoError(t, err)
		assert.Len(t, listB, 1)
		assert.Equal(t, "upg-lt-3", listB[0].ID)

		// Unknown tenant returns empty slice, not an error.
		listNone, err := store.ListUpgradesByTenant(ctx, "tenant-unknown")
		require.NoError(t, err)
		assert.Empty(t, listNone)
	})

	// Close must not error.
	require.NoError(t, store.Close())
}

func TestUpgradeStore_StatusConstants(t *testing.T) {
	assert.Equal(t, business.UpgradeStatus("dispatched"), business.UpgradeStatusDispatched)
	assert.Equal(t, business.UpgradeStatus("downloaded"), business.UpgradeStatusDownloaded)
	assert.Equal(t, business.UpgradeStatus("swapped"), business.UpgradeStatusSwapped)
	assert.Equal(t, business.UpgradeStatus("committed"), business.UpgradeStatusCommitted)
	assert.Equal(t, business.UpgradeStatus("rolled_back"), business.UpgradeStatusRolledBack)
	assert.Equal(t, business.UpgradeStatus("failed"), business.UpgradeStatusFailed)
}

func TestErrUpgradeNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrUpgradeNotFound)
	assert.Equal(t, "upgrade record not found", business.ErrUpgradeNotFound.Error())
}

func TestUpgradeRecord_SerializationRoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	completed := now.Add(5 * time.Minute)

	original := &business.UpgradeRecord{
		ID:        "upg-serial-1",
		StewardID: "steward-serial",
		TenantID:  "tenant-serial",
		Version:   "2.0.0",
		Platform:  "windows",
		Arch:      "arm64",
		SHA256:    "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222",
		Status:    business.UpgradeStatusCommitted,
		InitiatedBy: business.InitiatedByIdentity{
			Subject:    "admin@acme-corp.example",
			TenantID:   "tenant-serial",
			AuthMethod: "mtls",
		},
		Publisher:       "cfgms",
		SignatureDigest: "cafebabecafebabecafebabecafebabe",
		BundleSignature: []byte("ed25519signatureofcontenthashherexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		CreatedAt:       now,
		OperationNonce:  []byte("32byterandomnoncefortheupgrade12"),
		DispatchedAt:    now,
		CompletedAt:     &completed,
		ErrorMessage:    "",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded business.UpgradeRecord
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.StewardID, decoded.StewardID)
	assert.Equal(t, original.TenantID, decoded.TenantID)
	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.Platform, decoded.Platform)
	assert.Equal(t, original.Arch, decoded.Arch)
	assert.Equal(t, original.SHA256, decoded.SHA256)
	assert.Equal(t, original.Status, decoded.Status)
	assert.Equal(t, original.InitiatedBy, decoded.InitiatedBy)
	assert.Equal(t, original.Publisher, decoded.Publisher)
	assert.Equal(t, original.SignatureDigest, decoded.SignatureDigest)
	assert.Equal(t, original.BundleSignature, decoded.BundleSignature)
	assert.True(t, original.CreatedAt.Equal(decoded.CreatedAt), "CreatedAt mismatch: got %v want %v", decoded.CreatedAt, original.CreatedAt)
	assert.Equal(t, original.OperationNonce, decoded.OperationNonce)
	assert.True(t, original.DispatchedAt.Equal(decoded.DispatchedAt), "DispatchedAt mismatch: got %v want %v", decoded.DispatchedAt, original.DispatchedAt)
	require.NotNil(t, decoded.CompletedAt)
	assert.True(t, original.CompletedAt.Equal(*decoded.CompletedAt), "CompletedAt mismatch")
	assert.Equal(t, original.ErrorMessage, decoded.ErrorMessage)
}
