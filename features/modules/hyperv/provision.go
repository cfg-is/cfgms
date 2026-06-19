// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"sync"
	"time"
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
}

// memProvisionStore is a thread-safe in-memory ProvisionStore for tests.
type memProvisionStore struct {
	mu      sync.RWMutex
	records map[string]*ProvisionRecord
}

func newMemProvisionStore() *memProvisionStore {
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
