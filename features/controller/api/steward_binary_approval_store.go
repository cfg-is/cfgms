// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// stewardBinaryApprovalNamespace is the config-store namespace owned by
// StewardBinaryApprovalStore. The store is the only writer: no route and no sync
// path may store into it (see TestStewardBinaryApprovalNamespace_OnlyStoreWrites).
const stewardBinaryApprovalNamespace = "steward-binary-approval"

// stewardBinaryTestApprover is the approver recorded for a binary published while
// the test seed mode is active.
const stewardBinaryTestApprover = "auto-approved-test"

// errStewardBinaryApprovalUnavailable is returned by every approval read and write
// when no approval store is wired. Callers answer 503 and never treat it as approved.
var errStewardBinaryApprovalUnavailable = errors.New("steward binary approval store not available")

// StewardBinaryApproval is the approval of one steward binary, bound to the exact
// bytes approved: TenantID is the blob tenant the binary is stored under and SHA256
// is the hex SHA-256 of those bytes. A binary re-published with different bytes
// hashes differently and so no longer matches the record.
type StewardBinaryApproval struct {
	TenantID   string    `json:"tenant_id"`
	Version    string    `json:"version"`
	Platform   string    `json:"platform"`
	Arch       string    `json:"arch"`
	SHA256     string    `json:"sha256"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// stewardBinaryApprovalLookup is the tuple an approval lookup must match exactly.
type stewardBinaryApprovalLookup struct {
	tenant, version, platform, arch, sha256 string
}

func (l stewardBinaryApprovalLookup) complete() bool {
	return l.tenant != "" && l.version != "" && l.platform != "" && l.arch != "" && l.sha256 != ""
}

func (l stewardBinaryApprovalLookup) matches(a *StewardBinaryApproval) bool {
	return a.TenantID == l.tenant && a.Version == l.version && a.Platform == l.platform &&
		a.Arch == l.arch && a.SHA256 == l.sha256
}

// StewardBinaryApprovalStore persists steward binary approvals over a durable
// config store.
type StewardBinaryApprovalStore struct {
	store cfgconfig.ConfigStore
	now   func() time.Time
	// mu serializes the read-then-store fallback within this process for a config
	// store that cannot create-if-absent atomically.
	mu sync.Mutex
}

// NewStewardBinaryApprovalStore builds a store over cs, which must be a durable
// provider.
func NewStewardBinaryApprovalStore(cs cfgconfig.ConfigStore) (*StewardBinaryApprovalStore, error) {
	if cs == nil {
		return nil, errors.New("steward binary approval store: config store is required")
	}
	return &StewardBinaryApprovalStore{store: cs, now: func() time.Time { return time.Now().UTC() }}, nil
}

// stewardBinaryApprovalKey derives a storage-safe, collision-free name from the
// lookup tuple, so the record for one binary and hash is found by key.
func stewardBinaryApprovalKey(l stewardBinaryApprovalLookup) *cfgconfig.ConfigKey {
	h := sha256.New()
	for _, part := range []string{l.version, l.platform, l.arch, l.sha256} {
		h.Write([]byte(strconv.Itoa(len(part)) + ":" + part + "\x00"))
	}
	return &cfgconfig.ConfigKey{
		TenantID:  l.tenant,
		Namespace: stewardBinaryApprovalNamespace,
		Name:      "binary-" + hex.EncodeToString(h.Sum(nil)),
	}
}

// Put records an approval and returns the stored record. The record is
// immutable: approving the same (tenant, version, platform, arch, SHA-256) again
// keeps the first record and reports created=false. With a ConditionalConfigStore
// the create is one atomic step at the storage layer, so two concurrent approvals
// leave exactly one first record.
func (s *StewardBinaryApprovalStore) Put(ctx context.Context, a StewardBinaryApproval) (*StewardBinaryApproval, bool, error) {
	l := stewardBinaryApprovalLookup{tenant: a.TenantID, version: a.Version, platform: a.Platform, arch: a.Arch, sha256: a.SHA256}
	if !l.complete() || a.ApprovedBy == "" {
		return nil, false, errors.New("steward binary approval store: tenant, version, platform, arch, sha256 and approver are required")
	}
	if a.ApprovedAt.IsZero() {
		a.ApprovedAt = s.now()
	}
	entry, err := stewardBinaryApprovalEntry(l, a)
	if err != nil {
		return nil, false, err
	}
	cond, conditional := s.store.(cfgconfig.ConditionalConfigStore)
	if !conditional {
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	if existing, err := s.get(ctx, l); err != nil {
		return nil, false, err
	} else if existing != nil {
		return existing, false, nil
	}
	if conditional {
		return s.createConditional(ctx, cond, l, entry, a)
	}
	if err := s.store.StoreConfig(ctx, entry); err != nil {
		return nil, false, fmt.Errorf("steward binary approval store: write approval: %w", err)
	}
	return &a, true, nil
}

// stewardBinaryApprovalEntry encodes the approval a as the config entry stored
// under the key of l.
func stewardBinaryApprovalEntry(l stewardBinaryApprovalLookup, a StewardBinaryApproval) (*cfgconfig.ConfigEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("steward binary approval store: encode approval: %w", err)
	}
	return &cfgconfig.ConfigEntry{
		Key:       stewardBinaryApprovalKey(l),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(data)),
		UpdatedAt: a.ApprovedAt,
		UpdatedBy: a.ApprovedBy,
		Source:    "steward-binary-approval",
	}, nil
}

// createConditional creates the record only when none exists (expected version 0).
// When another writer created it first, that record is returned with created=false.
func (s *StewardBinaryApprovalStore) createConditional(ctx context.Context, cond cfgconfig.ConditionalConfigStore, l stewardBinaryApprovalLookup, entry *cfgconfig.ConfigEntry, a StewardBinaryApproval) (*StewardBinaryApproval, bool, error) {
	_, won, err := cond.CompareAndSwapConfig(ctx, entry, 0)
	if err != nil {
		return nil, false, fmt.Errorf("steward binary approval store: write approval: %w", err)
	}
	if won {
		return &a, true, nil
	}
	// Another writer created the record first; it is the one that stays.
	existing, err := s.get(ctx, l)
	if err != nil {
		return nil, false, err
	}
	if existing == nil {
		return nil, false, errors.New("steward binary approval store: approval create lost the race but no record exists")
	}
	return existing, false, nil
}

// Get returns the approval for the blob tenant, version, platform, arch and
// SHA-256, or (nil, nil) when none matches. An incomplete tuple matches nothing.
func (s *StewardBinaryApprovalStore) Get(ctx context.Context, tenant, version, platform, arch, sha string) (*StewardBinaryApproval, error) {
	return s.get(ctx, stewardBinaryApprovalLookup{tenant: tenant, version: version, platform: platform, arch: arch, sha256: sha})
}

func (s *StewardBinaryApprovalStore) get(ctx context.Context, l stewardBinaryApprovalLookup) (*StewardBinaryApproval, error) {
	if !l.complete() {
		return nil, nil
	}
	entry, err := s.store.GetConfig(ctx, stewardBinaryApprovalKey(l))
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("steward binary approval store: read approval: %w", err)
	}
	var a StewardBinaryApproval
	if err := json.Unmarshal(entry.Data, &a); err != nil {
		return nil, fmt.Errorf("steward binary approval store: decode approval: %w", err)
	}
	// The key already pins the tuple; re-check the decoded record so a misfiled
	// or tampered entry can never satisfy a lookup.
	if !l.matches(&a) {
		return nil, nil
	}
	return &a, nil
}

// SetStewardBinaryApprovalStore wires the store that holds steward binary
// approvals. Until it is set every approval check fails closed.
func (s *Server) SetStewardBinaryApprovalStore(st *StewardBinaryApprovalStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewardBinaryApprovalStore = st
}

// StewardBinaryApprovalStore returns the wired store, or nil when unwired.
func (s *Server) StewardBinaryApprovalStore() *StewardBinaryApprovalStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stewardBinaryApprovalStore
}

// approveStewardBinary is the one writer of steward binary approvals. It records
// that approver approved the binary stored under blobTenant for version, platform
// and arch whose bytes hash to sha256. created is false when the same binary bytes
// were already approved; the first record is kept.
func (s *Server) approveStewardBinary(ctx context.Context, blobTenant, version, platform, arch, sha, approver string) (created bool, err error) {
	_, created, err = s.putStewardBinaryApproval(ctx, blobTenant, version, platform, arch, sha, approver)
	return created, err
}

func (s *Server) putStewardBinaryApproval(ctx context.Context, blobTenant, version, platform, arch, sha, approver string) (*StewardBinaryApproval, bool, error) {
	st := s.StewardBinaryApprovalStore()
	if st == nil {
		return nil, false, errStewardBinaryApprovalUnavailable
	}
	return st.Put(ctx, StewardBinaryApproval{
		TenantID: blobTenant, Version: version, Platform: platform, Arch: arch,
		SHA256: sha, ApprovedBy: approver,
	})
}

// stewardBinaryApproval returns the approval record for the exact bytes, or nil.
func (s *Server) stewardBinaryApproval(ctx context.Context, blobTenant, version, platform, arch, sha string) (*StewardBinaryApproval, error) {
	st := s.StewardBinaryApprovalStore()
	if st == nil {
		return nil, errStewardBinaryApprovalUnavailable
	}
	return st.Get(ctx, blobTenant, version, platform, arch, sha)
}

// stewardBinaryApproved reports whether an approval record exists for the blob
// tenant, version, platform, arch and the SHA-256 recomputed from the stored
// bytes. Any error, including an unwired store, is returned and never read as
// approved.
func (s *Server) stewardBinaryApproved(ctx context.Context, blobTenant, version, platform, arch, sha string) (bool, error) {
	a, err := s.stewardBinaryApproval(ctx, blobTenant, version, platform, arch, sha)
	if err != nil {
		return false, err
	}
	return a != nil, nil
}
