// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// ProvisionState is the lifecycle position of a VM that is being provisioned
// from install media. It is a string type so it serialises cleanly to JSON.
type ProvisionState string

const (
	ProvisionStateAbsent     ProvisionState = "absent"
	ProvisionStateCreating   ProvisionState = "creating"
	ProvisionStateInstalling ProvisionState = "installing"
	ProvisionStateFinalizing ProvisionState = "finalizing"
	ProvisionStateReady      ProvisionState = "ready"
	ProvisionStateFailed     ProvisionState = "failed"
	ProvisionStateDegraded   ProvisionState = "degraded"
)

// ErrProvisionNotFound is returned when no provisioning record exists for a VM.
var ErrProvisionNotFound = errors.New("hyperv: provision record not found")

// ErrInvalidSeedPath is returned when a derived seed VHDX path is not a safe
// absolute local Windows path (e.g. a UNC \\server\share path or a path with
// no drive letter). The seed must live on a local/CSV drive next to the VM's
// VHD, never on an arbitrary network share.
var ErrInvalidSeedPath = errors.New("hyperv: invalid seed path: must be an absolute local Windows path (no UNC share)")

// ProvisionRecord tracks the in-progress state of a VM being provisioned from
// install media. It is JSON-serialisable so a controller restart can resume
// from the recorded state. CorrelationID is baked from the VM name and
// enrollment label at provision start; the controller-side completion
// reconciler (story #2050) uses it to match a registered steward to this VM.
type ProvisionRecord struct {
	VMName        string         `json:"vm_name"`
	State         ProvisionState `json:"state"`
	CorrelationID string         `json:"correlation_id"`
	StartedAt     time.Time      `json:"started_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	LastError     string         `json:"last_error,omitempty"`
	// FailedFrom records the state the record was in at the moment it was moved
	// to ProvisionStateFailed. Because State overwrites in place, the prior phase
	// is otherwise lost — but it is exactly the signal needed to tell a
	// host-side seed/create-phase failure (fails from creating, before the guest
	// ever installs) apart from a post-power-on failure (fails from installing/
	// finalizing, e.g. a controller-side completion timeout). Empty on a record
	// that was never failed, and on legacy records written before #2467; callers
	// must treat empty as "unknown" and NOT infer a seed-phase failure from it.
	FailedFrom ProvisionState `json:"failed_from,omitempty"`
	// RetryCount counts every create/seed-phase attempt made for this record —
	// the original attempt AND every bounded auto-retry re-entry into creating
	// (Issue #3802, ADR-009 §2 amendment). Incremented by provisionVM each time
	// it advances the record into ProvisionStateCreating. seedPhaseRetryExhausted
	// compares it against the effective budget (SourceConfig.retryBudget,
	// default 3) to decide whether the exists-branch seed-phase-failure gate
	// (applySourceGated) may retry again or must fall back to surface-and-wait.
	// Not reset on success — once a record leaves ProvisionStateFailed it is no
	// longer consulted, so a stale count from an earlier failed attempt is
	// harmless.
	RetryCount int `json:"retry_count,omitempty"`
}

// ProvisionStore is the persistence interface for VM provisioning records.
// Implementations are pluggable; the in-memory implementation is used in tests.
// Wiring into hypervModule is deferred to story #2044.
type ProvisionStore interface {
	GetProvision(ctx context.Context, vmName string) (*ProvisionRecord, error)
	SetProvision(ctx context.Context, record *ProvisionRecord) error
	DeleteProvision(ctx context.Context, vmName string) error
	// ListProvisions returns a snapshot of all provisioning records. The caller
	// receives independent copies; mutating them does not affect the store.
	ListProvisions(ctx context.Context) ([]*ProvisionRecord, error)
}

// memProvisionStore is a thread-safe in-memory ProvisionStore (and MoveStore —
// see vm_storage.go) for tests.
type memProvisionStore struct {
	mu      sync.RWMutex
	records map[string]*ProvisionRecord
	moves   map[string]*MoveRecord
}

// NewMemProvisionStore returns a new in-memory ProvisionStore suitable for
// tests and as a no-op placeholder when the hyperv feature is not configured.
func NewMemProvisionStore() *memProvisionStore {
	return &memProvisionStore{
		records: make(map[string]*ProvisionRecord),
		moves:   make(map[string]*MoveRecord),
	}
}

func (s *memProvisionStore) GetProvision(_ context.Context, vmName string) (*ProvisionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[vmName]
	if !ok {
		return nil, ErrProvisionNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *memProvisionStore) SetProvision(_ context.Context, record *ProvisionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *record
	s.records[record.VMName] = &cp
	return nil
}

func (s *memProvisionStore) DeleteProvision(_ context.Context, vmName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[vmName]; !ok {
		return ErrProvisionNotFound
	}
	delete(s.records, vmName)
	return nil
}

// usesCSVStore reports whether cfg's provisioning record is cluster-visible
// (CSV-backed): an ha_role VM whose primary VHD is on a Cluster Shared Volume.
// This is the single routing predicate — storeFor and the isOwnIncompleteAttempt
// fail-loud scope must agree on it. An ha_role VM with a non-CSV vhd_path (rare,
// and ErrInvalidHARoleSeedDir already constrains the common case) keeps the
// host-local store.
func (m *hypervModule) usesCSVStore(cfg *VMConfig) bool {
	return cfg != nil && cfg.HARole != nil && isUnderCSV(cfg.VHDPath)
}

// storeFor selects the ProvisionStore for cfg. An ha_role+CSV VM routes to the
// cluster-visible CSV store (records persisted beside the VM's VHD, readable from
// any member node's CSV mount) so a mid-provision CNO failover reads the
// in-progress record and surfaces-and-waits instead of creating a duplicate VM
// (ADR-009 Amendment 1 A1.4, Option A). Every other VM keeps the configured
// host-local store. Test seam: an injected m.csvProvisionStore wins for the CSV
// branch (mirrors the m.provisionStore injection seam), so routing is assertable
// against a fake without touching the filesystem.
//
// The CSV home dir is computed with vmHomeDir (NOT filepath.Dir, which mangles an
// always-Windows vhd_path on the Linux CI host — Issue #2044).
func (m *hypervModule) storeFor(cfg *VMConfig) ProvisionStore {
	if m.usesCSVStore(cfg) {
		if m.csvProvisionStore != nil {
			return m.csvProvisionStore
		}
		return newCSVProvisionStore(vmHomeDir(cfg.VHDPath))
	}
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	return m.provisionStore
}

// loadOrInitProvision returns the existing provisioning record for vmName, or
// initialises a fresh one at absent when none exists. A freshly initialised
// record carries StartedAt and the correlation identity baked from the VM name
// (the expected enrollment label per ADR-009 §8) so the controller-side
// reconciler (#2050) can match a registered steward to this VM. It is NOT
// persisted until advanceProvision writes a state.
func (m *hypervModule) loadOrInitProvision(ctx context.Context, cfg *VMConfig, vmName string) (*ProvisionRecord, error) {
	record, err := m.storeFor(cfg).GetProvision(ctx, vmName)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, ErrProvisionNotFound) {
		return nil, err
	}
	now := time.Now().UTC()
	return &ProvisionRecord{
		VMName:        vmName,
		State:         ProvisionStateAbsent,
		CorrelationID: vmName,
		StartedAt:     now,
		UpdatedAt:     now,
	}, nil
}

// advanceProvision sets the record to newState, stamps UpdatedAt, persists it,
// and emits a structured log event. It mutates the passed record in place so
// the caller's subsequent state checks see the new state.
func (m *hypervModule) advanceProvision(ctx context.Context, cfg *VMConfig, vmName string, record *ProvisionRecord, newState ProvisionState) error {
	prev := record.State
	record.State = newState
	record.UpdatedAt = time.Now().UTC()
	record.LastError = ""
	// Advancing forward means a fresh attempt is making progress; clear any stale
	// failure phase from a prior failed attempt so a later ready/installing record
	// does not carry a misleading FailedFrom (#2467). failedDuringSeedPhase gates
	// on State==Failed first, so this is data hygiene, not a correctness gate.
	record.FailedFrom = ""
	if err := m.storeFor(cfg).SetProvision(ctx, record); err != nil {
		return err
	}
	if logger, ok := m.GetLogger(); ok {
		logger.Info("hyperv: provisioning state advanced",
			"vm_name", logging.SanitizeLogValue(vmName),
			"from_state", string(prev),
			"to_state", string(newState),
			"correlation_id", logging.SanitizeLogValue(record.CorrelationID))
	}
	return nil
}

// failProvision records the failure on the provisioning record (state=failed,
// LastError set), persists it, emits a structured log event, and returns the
// original error so the caller can propagate it. The error message is not
// exposed via the log at error-detail level beyond the sanitized value.
func (m *hypervModule) failProvision(ctx context.Context, cfg *VMConfig, vmName string, record *ProvisionRecord, cause error) error {
	// Preserve the phase we failed from BEFORE overwriting State, so the exists-
	// branch power-on gate (applySourceGated, #2467) can tell a seed/create-phase
	// failure from a post-install one. Do not clobber an already-set FailedFrom on
	// a re-fail of an already-failed record (keep the earliest failure phase).
	if record.State != ProvisionStateFailed {
		record.FailedFrom = record.State
	}
	record.State = ProvisionStateFailed
	record.UpdatedAt = time.Now().UTC()
	if cause != nil {
		record.LastError = cause.Error()
	}
	// Persist best-effort; the original cause is the error we surface.
	_ = m.storeFor(cfg).SetProvision(ctx, record)
	if logger, ok := m.GetLogger(); ok {
		logger.Warn("hyperv: provisioning failed",
			"vm_name", logging.SanitizeLogValue(vmName),
			"correlation_id", logging.SanitizeLogValue(record.CorrelationID))
	}
	return cause
}

// isOwnIncompleteAttempt reports whether a provisioning record exists for vmName
// in a non-terminal, host-side-in-progress state — i.e. one of {creating,
// installing, finalizing}. Such a record proves the VM (or a half-built VM under
// the same name) is the module's own incomplete provisioning attempt rather than
// a pre-existing operator workload, which the existence-gating safety invariant
// (ADR-009 §2) treats differently: an own-incomplete attempt is surfaced-and-
// waited-on (never auto-destroyed), while a real existing VM is left untouched.
//
// A missing record, or a record in a terminal state (absent/ready/failed/
// degraded), returns (false, nil).
//
// Read-error handling is ASYMMETRIC by store, and this asymmetry is deliberate
// (#2447): for the cluster-visible CSV store the record is LOAD-BEARING for
// cluster duplicate-prevention — an unreadable record must fail LOUD (return the
// error) so createVM never fires while the cluster record state is unknown (the
// exact duplicate a mid-provision CNO failover would otherwise cause). For the
// host-local store the record is not load-bearing, so the historical
// swallow-on-error semantics are preserved byte-for-byte: a read error is treated
// as "no in-progress attempt" (false, nil) and the create path proceeds.
func (m *hypervModule) isOwnIncompleteAttempt(ctx context.Context, cfg *VMConfig) (bool, error) {
	record, err := m.storeFor(cfg).GetProvision(ctx, cfg.Name)
	if errors.Is(err, ErrProvisionNotFound) {
		return false, nil
	}
	if err != nil {
		if m.usesCSVStore(cfg) {
			return false, err // CSV record load-bearing → fail loud
		}
		return false, nil // host-local → preserve swallow-on-error
	}
	if record == nil {
		return false, nil
	}
	switch record.State {
	case ProvisionStateCreating, ProvisionStateInstalling, ProvisionStateFinalizing:
		return true, nil
	default:
		return false, nil
	}
}

// failedDuringSeedPhase reports whether record is a Failed provisioning record
// whose failure happened during the host-side create/seed phase — before the
// guest ever started installing. Such a VM has no working seed, so powering it
// on would boot an unprovisioned guest; the exists-branch gate (applySourceGated,
// #2467) leaves it OFF (surface-and-wait) until it is reseeded.
//
// The signal is FailedFrom (captured by failProvision, and by the controller-
// side completion reconciler, at the moment of failure). The seed phase only
// runs while the record is at creating (provisionVM's re-entry guard skips it
// once at installing+), so a seed-phase failure always fails from creating (or,
// defensively, absent). A record that failed from installing/finalizing is a
// different, post-power-on failure class (e.g. a completion-timeout) and must
// keep converging normally — so it returns false. An empty FailedFrom is
// "unknown" (legacy record, or a failure path that did not record a phase): to
// avoid regressing a VM that is actually fine into a stuck-off state, unknown is
// treated as NOT a seed-phase failure.
func failedDuringSeedPhase(record *ProvisionRecord) bool {
	if record == nil || record.State != ProvisionStateFailed {
		return false
	}
	switch record.FailedFrom {
	case ProvisionStateAbsent, ProvisionStateCreating:
		return true
	default:
		return false
	}
}

// defaultSeedPhaseRetryMax is the built-in bounded auto-retry budget (total
// create/seed-phase attempts, including the original) applied when a VM
// source declares no explicit retry_max (Issue #3802, ADR-009 §2 amendment).
const defaultSeedPhaseRetryMax = 3

// seedPhaseRetryExhausted reports whether a Failed seed-phase record (see
// failedDuringSeedPhase) has used up its bounded auto-retry budget. maxRetries
// is the effective total-attempt budget (SourceConfig.retryBudget: the
// declared retry_max, or defaultSeedPhaseRetryMax when unset). A maxRetries of
// 0 is the disable value — RetryCount starts at 0, so 0 >= 0 is immediately
// exhausted and the seed-phase gate never retries. This is a pure function of
// the record and the budget; it does not read or write the store.
func seedPhaseRetryExhausted(record *ProvisionRecord, maxRetries int) bool {
	return record.RetryCount >= maxRetries
}

// degradeProvision records that a VM which already exists on the host is in a
// broken/unhealthy state (ADR-009 §2 degraded surface). It writes a
// ProvisionRecord at state=degraded with LastError describing the observed
// Hyper-V state, persists it, and emits a structured log event. It is the
// non-destructive surface for an existing-but-broken VM: the module NEVER
// delete-and-rebuilds — degradation is observed and reported, not remediated.
// observedState is the raw VM power/health state string and is sanitised before
// it reaches any log field.
func (m *hypervModule) degradeProvision(ctx context.Context, cfg *VMConfig, vmName string, record *ProvisionRecord, observedState string) error {
	prev := record.State
	record.State = ProvisionStateDegraded
	record.UpdatedAt = time.Now().UTC()
	record.LastError = "hyperv: VM in broken state: " + observedState
	if err := m.storeFor(cfg).SetProvision(ctx, record); err != nil {
		return err
	}
	if logger, ok := m.GetLogger(); ok {
		logger.Warn("hyperv: existing VM is in a broken state; surfaced as degraded (not torn down)",
			"vm_name", logging.SanitizeLogValue(vmName),
			"from_state", string(prev),
			"observed_state", logging.SanitizeLogValue(observedState),
			"correlation_id", logging.SanitizeLogValue(record.CorrelationID))
	}
	return nil
}

// ListProvisions returns snapshot copies of all provisioning records. Used by
// the controller-side completion reconciler (#2050) to match a registered
// steward to a provisioning VM via CorrelationID.
func (s *memProvisionStore) ListProvisions(_ context.Context) ([]*ProvisionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ProvisionRecord, 0, len(s.records))
	for _, r := range s.records {
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

// ── Durable ProvisionStore (flatfile-backed) ──────────────────────────────────

// provisionNamespace is the stored-config namespace for hyperv provision records.
// A dash separator (not slash) is required for keysafe path-safety compliance.
const provisionNamespace = "hyperv-provisions"

// provisionTenantID is the fixed local tenant scope used for steward-local
// provision records. Stewards are single-tenant on the host side; using a
// fixed non-empty value satisfies the flatfile store's ErrTenantRequired guard.
const provisionTenantID = "local"

// ConfigBackedProvisionStore implements ProvisionStore by persisting
// ProvisionRecord values as JSON-encoded ConfigEntry data through a
// cfgconfig.ConfigStore backend (typically a FlatFileConfigStore). It follows
// the shape of ConfigBackedProfileStore: namespace = provisionNamespace, key
// name = VM name, data = JSON-encoded ProvisionRecord. Write-through: every
// SetProvision and DeleteProvision goes immediately to the backing store.
type ConfigBackedProvisionStore struct {
	store    cfgconfig.ConfigStore
	tenantID string
}

// NewConfigBackedProvisionStore constructs a ConfigBackedProvisionStore over
// the given config store. tenantID must be non-empty; callers that do not
// have a tenant scope should pass provisionTenantID ("local").
func NewConfigBackedProvisionStore(store cfgconfig.ConfigStore, tenantID string) *ConfigBackedProvisionStore {
	if tenantID == "" {
		tenantID = provisionTenantID
	}
	return &ConfigBackedProvisionStore{store: store, tenantID: tenantID}
}

// NewFlatFileProvisionStore constructs a durable ProvisionStore backed by a
// FlatFileConfigStore rooted at root. root is created (with MkdirAll) if it
// does not already exist. This is the production constructor called by the
// steward factory; tests inject the store directly via WithProvisionStore.
func NewFlatFileProvisionStore(root string) (ProvisionStore, error) {
	ffStore, err := flatfile.NewFlatFileConfigStore(root)
	if err != nil {
		return nil, fmt.Errorf("hyperv: open provision store at %q: %w", root, err)
	}
	return NewConfigBackedProvisionStore(ffStore, provisionTenantID), nil
}

func (s *ConfigBackedProvisionStore) provisionKey(vmName string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{
		TenantID:  s.tenantID,
		Namespace: provisionNamespace,
		Name:      vmName,
	}
}

// GetProvision reads the provision record for vmName from the backing store.
// Returns ErrProvisionNotFound when no record exists.
func (s *ConfigBackedProvisionStore) GetProvision(ctx context.Context, vmName string) (*ProvisionRecord, error) {
	entry, err := s.store.GetConfig(ctx, s.provisionKey(vmName))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, ErrProvisionNotFound
		}
		return nil, fmt.Errorf("hyperv: get provision record %q: %w", vmName, err)
	}
	var record ProvisionRecord
	if err := json.Unmarshal(entry.Data, &record); err != nil {
		return nil, fmt.Errorf("hyperv: decode provision record %q: %w", vmName, err)
	}
	return &record, nil
}

// SetProvision persists record to the backing store, overwriting any existing
// entry for the same VM name.
func (s *ConfigBackedProvisionStore) SetProvision(ctx context.Context, record *ProvisionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("hyperv: encode provision record %q: %w", record.VMName, err)
	}
	return s.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    s.provisionKey(record.VMName),
		Data:   data,
		Format: cfgconfig.ConfigFormatJSON,
	})
}

// DeleteProvision removes the provision record for vmName from the backing
// store. Returns ErrProvisionNotFound when no record exists.
func (s *ConfigBackedProvisionStore) DeleteProvision(ctx context.Context, vmName string) error {
	err := s.store.DeleteConfig(ctx, s.provisionKey(vmName))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return ErrProvisionNotFound
		}
		return fmt.Errorf("hyperv: delete provision record %q: %w", vmName, err)
	}
	return nil
}

// ListProvisions returns a snapshot of all provision records stored under the
// provision namespace. Each ConfigEntry's Data is decoded directly (no second
// GetConfig round-trip per name, per the ListConfigs contract). Returns an
// empty non-nil slice when no records exist.
func (s *ConfigBackedProvisionStore) ListProvisions(ctx context.Context) ([]*ProvisionRecord, error) {
	entries, err := s.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		TenantID:  s.tenantID,
		Namespace: provisionNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("hyperv: list provision records: %w", err)
	}
	out := make([]*ProvisionRecord, 0, len(entries))
	for _, e := range entries {
		if e == nil || len(e.Data) == 0 {
			continue
		}
		var r ProvisionRecord
		if err := json.Unmarshal(e.Data, &r); err != nil {
			continue // skip malformed entries
		}
		out = append(out, &r)
	}
	return out, nil
}

// Verify ConfigBackedProvisionStore satisfies the ProvisionStore contract.
var _ ProvisionStore = (*ConfigBackedProvisionStore)(nil)
