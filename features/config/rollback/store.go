// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package rollback

import (
	"context"
	"fmt"
	"sync"
)

// InMemoryRollbackStore provides an in-memory implementation of RollbackStore
type InMemoryRollbackStore struct {
	mu         sync.RWMutex
	operations map[string]*RollbackOperation
}

// NewInMemoryRollbackStore creates a new in-memory rollback store
func NewInMemoryRollbackStore() RollbackStore {
	return &InMemoryRollbackStore{
		operations: make(map[string]*RollbackOperation),
	}
}

// SaveOperation saves a rollback operation
func (s *InMemoryRollbackStore) SaveOperation(ctx context.Context, operation *RollbackOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if operation.ID == "" {
		return fmt.Errorf("operation ID cannot be empty")
	}

	// Clone the operation to avoid external modifications
	s.operations[operation.ID] = s.cloneOperation(operation)

	return nil
}

// GetOperation retrieves an operation by ID
func (s *InMemoryRollbackStore) GetOperation(ctx context.Context, id string) (*RollbackOperation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	operation, exists := s.operations[id]
	if !exists {
		return nil, nil
	}

	// Return a clone to avoid external modifications
	return s.cloneOperation(operation), nil
}

// ListOperations lists operations matching the filters
func (s *InMemoryRollbackStore) ListOperations(ctx context.Context, filters RollbackFilters) ([]RollbackOperation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []RollbackOperation

	for _, op := range s.operations {
		// Apply filters
		if filters.TargetType != "" && op.Request.TargetType != filters.TargetType {
			continue
		}

		if filters.TargetID != "" && op.Request.TargetID != filters.TargetID {
			continue
		}

		if filters.Status != "" && op.Status != filters.Status {
			continue
		}

		if filters.InitiatedBy != "" && op.InitiatedBy != filters.InitiatedBy {
			continue
		}

		if filters.StartTime != nil && op.InitiatedAt.Before(*filters.StartTime) {
			continue
		}

		if filters.EndTime != nil && op.InitiatedAt.After(*filters.EndTime) {
			continue
		}

		// Clone and add to results
		results = append(results, *s.cloneOperation(op))

		// Check limit
		if filters.Limit > 0 && len(results) >= filters.Limit {
			break
		}
	}

	// Sort by initiated time (newest first)
	// In a real implementation, would use proper sorting

	return results, nil
}

// UpdateOperation updates an existing operation
func (s *InMemoryRollbackStore) UpdateOperation(ctx context.Context, operation *RollbackOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if operation.ID == "" {
		return fmt.Errorf("operation ID cannot be empty")
	}

	if _, exists := s.operations[operation.ID]; !exists {
		return fmt.Errorf("operation not found: %s", operation.ID)
	}

	// Update with a clone
	s.operations[operation.ID] = s.cloneOperation(operation)

	return nil
}

// AddAuditEntry adds an audit log entry to an operation
func (s *InMemoryRollbackStore) AddAuditEntry(ctx context.Context, operationID string, entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	operation, exists := s.operations[operationID]
	if !exists {
		return fmt.Errorf("operation not found: %s", operationID)
	}

	// Add audit entry
	operation.AuditTrail = append(operation.AuditTrail, entry)

	return nil
}

// Helper method to clone an operation
func (s *InMemoryRollbackStore) cloneOperation(op *RollbackOperation) *RollbackOperation {
	if op == nil {
		return nil
	}

	// Deep clone the operation
	clone := &RollbackOperation{
		ID:          op.ID,
		Request:     op.Request,
		Status:      op.Status,
		InitiatedBy: op.InitiatedBy,
		InitiatedAt: op.InitiatedAt,
		Progress:    op.Progress,
	}

	if op.CompletedAt != nil {
		t := *op.CompletedAt
		clone.CompletedAt = &t
	}

	if op.Result != nil {
		clone.Result = &RollbackResult{
			Success:                  op.Result.Success,
			ConfigurationsRolledBack: op.Result.ConfigurationsRolledBack,
			DevicesAffected:          op.Result.DevicesAffected,
			PartialSuccess:           op.Result.PartialSuccess,
			Metrics:                  op.Result.Metrics,
		}

		// Clone failures
		clone.Result.Failures = make([]RollbackFailure, len(op.Result.Failures))
		copy(clone.Result.Failures, op.Result.Failures)
	}

	// Clone audit trail
	clone.AuditTrail = make([]AuditEntry, len(op.AuditTrail))
	copy(clone.AuditTrail, op.AuditTrail)

	return clone
}
