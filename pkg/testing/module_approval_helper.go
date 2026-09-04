// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testing

import (
	"context"
	"sync"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemModuleApprovalStore is a minimal in-process, mutex-guarded implementation of
// business.ModuleApprovalStore used for tests that need two or more simulated
// controller nodes (e.g. two ModuleCache/ApprovalWorkflow instances) to contend over
// the same bundle's approval status (CLAUDE.md's no-mocks rule — this is a real,
// entirely-correct implementation of the interface's CAS contract, not a framework
// mock recording expectations). It is in-process only: sufficient to prove a CAS
// algorithm's mutual exclusion, not evidence of node-shared storage — see
// pkg/storage/providers/database's Postgres-backed DatabaseModuleApprovalStore for
// the implementation that actually makes approval status cluster-visible.
type inMemModuleApprovalStore struct {
	mu     sync.Mutex
	status map[string]business.ModuleApprovalStatus
}

// SetupTestModuleApprovalStore returns a real (not mocked) business.ModuleApprovalStore
// for tests that need multiple ApprovalWorkflow/ModuleCache instances to share one
// approval-status backend in-process, simulating multiple cluster nodes racing an
// approve/reject decision against the same bundle.
func SetupTestModuleApprovalStore() business.ModuleApprovalStore {
	return &inMemModuleApprovalStore{status: make(map[string]business.ModuleApprovalStatus)}
}

func (s *inMemModuleApprovalStore) GetApprovalStatus(_ context.Context, addr string) (business.ModuleApprovalStatus, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.status[addr]
	return status, ok, nil
}

func (s *inMemModuleApprovalStore) PutApprovalStatusIfAbsent(_ context.Context, addr string, status business.ModuleApprovalStatus) (business.ModuleApprovalStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.status[addr]; ok {
		return existing, nil
	}
	s.status[addr] = status
	return status, nil
}

func (s *inMemModuleApprovalStore) CompareAndSetApprovalStatus(_ context.Context, addr string, expectedCurrent, newStatus business.ModuleApprovalStatus) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.status[addr]
	if !ok || current != expectedCurrent {
		return false, nil
	}
	s.status[addr] = newStatus
	return true, nil
}

// Compile-time assertion.
var _ business.ModuleApprovalStore = (*inMemModuleApprovalStore)(nil)
