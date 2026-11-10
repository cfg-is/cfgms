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

// --- Contract tests ---

func TestUpgradeStore_Contract(t *testing.T) {
	business.UpgradeStoreContract(t, newInMemUpgradeStore())
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
