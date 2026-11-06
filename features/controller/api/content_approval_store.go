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
	"sort"
	"strconv"
	"time"

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Config-store namespaces owned by ContentApprovalStore (ADR-036 section 2).
// ContentApprovalStore is the only writer: no route and no sync path may store
// into them (see TestContentApprovalNamespaces_OnlyStoreWrites). The
// publication namespace is reserved here for the workflow publication record so
// the same guard covers it when it is introduced.
const (
	contentApprovalNamespace     = "content-approval"
	contentApprovalModeNamespace = "content-library-mode"
	contentPublicationNamespace  = "content-publication"
)

// ApprovalMode is the approval mode of one content library.
type ApprovalMode string

const (
	// ApprovalModeSigned requires a publisher signature. It is the default.
	ApprovalModeSigned ApprovalMode = "signed"
	// ApprovalModeApprove requires an approval bound to the approval hash.
	ApprovalModeApprove ApprovalMode = "approve"
	// ApprovalModeComment accepts content with a recorded comment only.
	ApprovalModeComment ApprovalMode = "comment"
)

// Valid reports whether m is exactly one of the three modes. The empty value is
// not valid here; use Effective for an in-memory value that may be unset.
func (m ApprovalMode) Valid() bool {
	switch m {
	case ApprovalModeSigned, ApprovalModeApprove, ApprovalModeComment:
		return true
	}
	return false
}

// Effective reads the empty value as signed and returns every other value
// unchanged. It never turns an unrecognised value into a weaker mode.
func (m ApprovalMode) Effective() ApprovalMode {
	if m == "" {
		return ApprovalModeSigned
	}
	return m
}

// LibraryKind is the kind of content a library holds. There is one library per
// tenant per kind.
type LibraryKind string

const (
	LibraryKindScript   LibraryKind = "script"
	LibraryKindWorkflow LibraryKind = "workflow"
)

// Valid reports whether k is a known library kind.
func (k LibraryKind) Valid() bool {
	return k == LibraryKindScript || k == LibraryKindWorkflow
}

// ApprovalMethod records how an approval came to exist.
type ApprovalMethod string

const (
	ApprovalMethodApproveTap      ApprovalMethod = "approve-tap"
	ApprovalMethodSignature       ApprovalMethod = "signature"
	ApprovalMethodWorkflowPublish ApprovalMethod = "workflow-publish"
)

// Valid reports whether m is a known approval method.
func (m ApprovalMethod) Valid() bool {
	switch m {
	case ApprovalMethodApproveTap, ApprovalMethodSignature, ApprovalMethodWorkflowPublish:
		return true
	}
	return false
}

// ContentApproval is an approval of one content version, bound to its approval
// hash. TenantID is the OWNER tenant of the content, and ContentHash holds the
// approval hash (ScriptApprovalHash / WorkflowApprovalHash), which covers the
// owner tenant, so a record cannot satisfy a lookup that resolved to another
// owner. An approval never carries to another version or hash.
type ContentApproval struct {
	TenantID    string         `json:"tenant_id"`
	Kind        LibraryKind    `json:"kind"`
	ContentID   string         `json:"content_id"`
	Version     string         `json:"version"`
	ContentHash string         `json:"content_hash"`
	ApprovedBy  string         `json:"approved_by"`
	ApprovedAt  time.Time      `json:"approved_at"`
	Method      ApprovalMethod `json:"method"`
}

// libraryModeRecord is the stored form of a library's mode. PreviousMode keeps
// the value replaced by the latest SetMode for audit.
type libraryModeRecord struct {
	TenantID     string       `json:"tenant_id"`
	Kind         LibraryKind  `json:"kind"`
	Mode         ApprovalMode `json:"mode"`
	PreviousMode ApprovalMode `json:"previous_mode,omitempty"`
	SetBy        string       `json:"set_by"`
	SetAt        time.Time    `json:"set_at"`
}

// WorkflowApprovalHash returns the hash an approval of a workflow is bound to.
// It shares the encoding of ScriptApprovalHash; the owner tenant is part of it.
func WorkflowApprovalHash(ownerTenant, name, version, canonicalHash string) string {
	return script.ApprovalDigest("cfgms/content-approval/workflow/v1", ownerTenant, name, version, canonicalHash)
}

// ContentApprovalStore persists library approval modes and content approvals
// over a durable config store.
type ContentApprovalStore struct {
	store cfgconfig.ConfigStore
	now   func() time.Time
}

// NewContentApprovalStore builds a store over cs, which must be a durable
// provider.
func NewContentApprovalStore(cs cfgconfig.ConfigStore) (*ContentApprovalStore, error) {
	if cs == nil {
		return nil, errors.New("content approval store: config store is required")
	}
	return &ContentApprovalStore{store: cs, now: func() time.Time { return time.Now().UTC() }}, nil
}

func modeKey(tenantID string, kind LibraryKind) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: contentApprovalModeNamespace, Name: string(kind)}
}

// approvalName derives a storage-safe, collision-free name from the lookup
// tuple, so the record for one (id, version, hash) is found by key.
func approvalName(kind LibraryKind, id, version, hash string) string {
	sum := sha256.Sum256([]byte(strconv.Itoa(len(id)) + ":" + id + "\x00" + strconv.Itoa(len(version)) + ":" + version + "\x00" + hash))
	return string(kind) + "-" + hex.EncodeToString(sum[:])
}

func approvalKey(tenantID string, kind LibraryKind, id, version, hash string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: contentApprovalNamespace, Name: approvalName(kind, id, version, hash)}
}

// GetMode returns the approval mode of the tenant's library of the given kind.
// A library with no record is signed. The mode is not inherited from a parent
// tenant. A store read error, or a stored value that is not one of the three
// modes, is returned as an error and never as a default.
func (s *ContentApprovalStore) GetMode(ctx context.Context, tenantID string, kind LibraryKind) (ApprovalMode, error) {
	if tenantID == "" {
		return "", errors.New("content approval store: tenant is required")
	}
	if !kind.Valid() {
		return "", fmt.Errorf("content approval store: unknown library kind %q", string(kind))
	}
	entry, err := s.store.GetConfig(ctx, modeKey(tenantID, kind))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return ApprovalModeSigned, nil
		}
		return "", fmt.Errorf("content approval store: read library mode: %w", err)
	}
	var rec libraryModeRecord
	if err := json.Unmarshal(entry.Data, &rec); err != nil {
		return "", fmt.Errorf("content approval store: decode library mode: %w", err)
	}
	if !rec.Mode.Valid() {
		return "", fmt.Errorf("content approval store: stored library mode %q is not valid", string(rec.Mode))
	}
	return rec.Mode, nil
}

// SetMode sets the approval mode of the tenant's library. It is the only writer
// of the mode namespace and keeps the replaced value for audit.
func (s *ContentApprovalStore) SetMode(ctx context.Context, tenantID string, kind LibraryKind, mode ApprovalMode, actor string) error {
	if tenantID == "" || actor == "" {
		return errors.New("content approval store: tenant and actor are required")
	}
	if !kind.Valid() {
		return fmt.Errorf("content approval store: unknown library kind %q", string(kind))
	}
	if !mode.Valid() {
		return fmt.Errorf("content approval store: invalid approval mode %q", string(mode))
	}
	// The previous value is audit data only; a corrupt or unreadable previous
	// record must not block an operator from repairing the mode.
	previous, prevErr := s.GetMode(ctx, tenantID, kind)
	if prevErr != nil {
		previous = ""
	}
	rec := libraryModeRecord{
		TenantID: tenantID, Kind: kind, Mode: mode, PreviousMode: previous,
		SetBy: actor, SetAt: s.now(),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("content approval store: encode library mode: %w", err)
	}
	return s.write(ctx, modeKey(tenantID, kind), data, actor, rec.SetAt)
}

// PutApproval records an approval. The record is immutable: storing the same
// (owner, kind, id, version, hash) again keeps the first record.
func (s *ContentApprovalStore) PutApproval(ctx context.Context, a ContentApproval) error {
	switch {
	case a.TenantID == "", a.ContentID == "", a.Version == "", a.ContentHash == "", a.ApprovedBy == "":
		return errors.New("content approval store: tenant, content id, version, hash and approver are required")
	case !a.Kind.Valid():
		return fmt.Errorf("content approval store: unknown library kind %q", string(a.Kind))
	case !a.Method.Valid():
		return fmt.Errorf("content approval store: unknown approval method %q", string(a.Method))
	}
	key := approvalKey(a.TenantID, a.Kind, a.ContentID, a.Version, a.ContentHash)
	if _, err := s.store.GetConfig(ctx, key); err == nil {
		return nil
	} else if !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return fmt.Errorf("content approval store: read approval: %w", err)
	}
	if a.ApprovedAt.IsZero() {
		a.ApprovedAt = s.now()
	}
	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("content approval store: encode approval: %w", err)
	}
	return s.write(ctx, key, data, a.ApprovedBy, a.ApprovedAt)
}

// DeleteApproval withdraws the approval for the owner tenant, kind, id, version
// and approval hash. It reports whether a record existed; withdrawing an absent
// approval changes nothing.
func (s *ContentApprovalStore) DeleteApproval(ctx context.Context, ownerTenant string, kind LibraryKind, id, version, hash string) (bool, error) {
	existing, err := s.GetApproval(ctx, ownerTenant, kind, id, version, hash)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return false, nil
	}
	if err := s.store.DeleteConfig(ctx, approvalKey(ownerTenant, kind, id, version, hash)); err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("content approval store: delete approval: %w", err)
	}
	return true, nil
}

// approvalLookup is the tuple an approval lookup must match exactly.
type approvalLookup struct {
	tenant, id, version, hash string
	kind                      LibraryKind
}

// complete reports whether every element of the tuple is set and the kind is
// known. An incomplete lookup matches nothing.
func (l approvalLookup) complete() bool {
	return l.tenant != "" && l.id != "" && l.version != "" && l.hash != "" && l.kind.Valid()
}

// matches reports whether the decoded record carries exactly this tuple.
func (l approvalLookup) matches(a *ContentApproval) bool {
	return a.TenantID == l.tenant && a.Kind == l.kind && a.ContentID == l.id &&
		a.Version == l.version && a.ContentHash == l.hash
}

// GetApproval returns the approval for the owner tenant, kind, id, version and
// approval hash. It returns (nil, nil) unless all of them match.
func (s *ContentApprovalStore) GetApproval(ctx context.Context, ownerTenant string, kind LibraryKind, id, version, hash string) (*ContentApproval, error) {
	l := approvalLookup{tenant: ownerTenant, id: id, version: version, hash: hash, kind: kind}
	if !l.complete() {
		return nil, nil
	}
	entry, err := s.store.GetConfig(ctx, approvalKey(ownerTenant, kind, id, version, hash))
	if errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("content approval store: read approval: %w", err)
	}
	a, err := decodeApproval(entry)
	if err != nil {
		return nil, err
	}
	// The key already pins the tuple; re-check the decoded record so a
	// misfiled or tampered entry can never satisfy a lookup.
	if !l.matches(a) {
		return nil, nil
	}
	return a, nil
}

// ListApprovals lists the owner tenant's approvals of one kind, oldest first.
func (s *ContentApprovalStore) ListApprovals(ctx context.Context, ownerTenant string, kind LibraryKind) ([]*ContentApproval, error) {
	if ownerTenant == "" || !kind.Valid() {
		return nil, errors.New("content approval store: tenant and a valid kind are required")
	}
	entries, err := s.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: ownerTenant, Namespace: contentApprovalNamespace})
	if err != nil {
		return nil, fmt.Errorf("content approval store: list approvals: %w", err)
	}
	out := make([]*ContentApproval, 0, len(entries))
	for _, e := range entries {
		a, err := decodeApproval(e)
		if err != nil {
			return nil, err
		}
		if a.TenantID == ownerTenant && a.Kind == kind {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ApprovedAt.Before(out[j].ApprovedAt) })
	return out, nil
}

func decodeApproval(e *cfgconfig.ConfigEntry) (*ContentApproval, error) {
	var a ContentApproval
	if err := json.Unmarshal(e.Data, &a); err != nil {
		return nil, fmt.Errorf("content approval store: decode approval: %w", err)
	}
	return &a, nil
}

func (s *ContentApprovalStore) write(ctx context.Context, key *cfgconfig.ConfigKey, data []byte, actor string, at time.Time) error {
	return s.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:       key,
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  fmt.Sprintf("%x", sha256.Sum256(data)),
		UpdatedAt: at,
		UpdatedBy: actor,
		Source:    "content-approval",
	})
}
