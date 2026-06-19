// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
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

// memProvisionStore is a thread-safe in-memory ProvisionStore for tests.
type memProvisionStore struct {
	mu      sync.RWMutex
	records map[string]*ProvisionRecord
}

// NewMemProvisionStore returns a new in-memory ProvisionStore suitable for
// tests and as a no-op placeholder when the hyperv feature is not configured.
func NewMemProvisionStore() *memProvisionStore {
	return &memProvisionStore{records: make(map[string]*ProvisionRecord)}
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

// loadOrInitProvision returns the existing provisioning record for vmName, or
// initialises a fresh one at absent when none exists. A freshly initialised
// record carries StartedAt and the correlation identity baked from the VM name
// (the expected enrollment label per ADR-009 §8) so the controller-side
// reconciler (#2050) can match a registered steward to this VM. It is NOT
// persisted until advanceProvision writes a state.
func (m *hypervModule) loadOrInitProvision(ctx context.Context, vmName string) (*ProvisionRecord, error) {
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	record, err := m.provisionStore.GetProvision(ctx, vmName)
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
func (m *hypervModule) advanceProvision(ctx context.Context, vmName string, record *ProvisionRecord, newState ProvisionState) error {
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	prev := record.State
	record.State = newState
	record.UpdatedAt = time.Now().UTC()
	record.LastError = ""
	if err := m.provisionStore.SetProvision(ctx, record); err != nil {
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
func (m *hypervModule) failProvision(ctx context.Context, vmName string, record *ProvisionRecord, cause error) error {
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	record.State = ProvisionStateFailed
	record.UpdatedAt = time.Now().UTC()
	if cause != nil {
		record.LastError = cause.Error()
	}
	// Persist best-effort; the original cause is the error we surface.
	_ = m.provisionStore.SetProvision(ctx, record)
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
// degraded), returns false. A store read error is treated as "no in-progress
// attempt" (false) — the caller's downstream gating is conservative regardless.
func (m *hypervModule) isOwnIncompleteAttempt(ctx context.Context, vmName string) bool {
	if m.provisionStore == nil {
		return false
	}
	record, err := m.provisionStore.GetProvision(ctx, vmName)
	if err != nil || record == nil {
		return false
	}
	switch record.State {
	case ProvisionStateCreating, ProvisionStateInstalling, ProvisionStateFinalizing:
		return true
	default:
		return false
	}
}

// degradeProvision records that a VM which already exists on the host is in a
// broken/unhealthy state (ADR-009 §2 degraded surface). It writes a
// ProvisionRecord at state=degraded with LastError describing the observed
// Hyper-V state, persists it, and emits a structured log event. It is the
// non-destructive surface for an existing-but-broken VM: the module NEVER
// delete-and-rebuilds — degradation is observed and reported, not remediated.
// observedState is the raw VM power/health state string and is sanitised before
// it reaches any log field.
func (m *hypervModule) degradeProvision(ctx context.Context, vmName string, record *ProvisionRecord, observedState string) error {
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	prev := record.State
	record.State = ProvisionStateDegraded
	record.UpdatedAt = time.Now().UTC()
	record.LastError = "hyperv: VM in broken state: " + observedState
	if err := m.provisionStore.SetProvision(ctx, record); err != nil {
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
