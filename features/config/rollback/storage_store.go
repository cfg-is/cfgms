// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// StorageRollbackStore provides a storage-backed implementation of RollbackStore
// using pkg/storage for durable persistence across controller restarts
type StorageRollbackStore struct {
	configStore cfgconfig.ConfigStore
	mu          sync.RWMutex // Protects audit entry appends for concurrency safety
}

// NewStorageRollbackStore creates a new storage-backed rollback store
// configStore must be initialized and operational
func NewStorageRollbackStore(configStore cfgconfig.ConfigStore) RollbackStore {
	if configStore == nil {
		panic("configStore cannot be nil")
	}
	return &StorageRollbackStore{
		configStore: configStore,
	}
}

// SaveOperation saves a rollback operation to durable storage
func (s *StorageRollbackStore) SaveOperation(ctx context.Context, operation *RollbackOperation) error {
	if operation.ID == "" {
		return fmt.Errorf("operation ID cannot be empty")
	}

	// Marshal operation to YAML for storage
	// Git ConfigStore expects YAML-formatted data in the Data field
	yamlData, err := yaml.Marshal(operation)
	if err != nil {
		return fmt.Errorf("failed to marshal operation: %w", err)
	}

	// Create config entry for operation
	entry := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "system", // System-level rollback operations
			Namespace: "rollback/operations",
			Name:      operation.ID,
		},
		Data:   yamlData,
		Format: cfgconfig.ConfigFormatYAML,
		Metadata: map[string]interface{}{
			"target_type":  string(operation.Request.TargetType),
			"target_id":    operation.Request.TargetID,
			"status":       string(operation.Status),
			"initiated_by": operation.InitiatedBy,
		},
		CreatedAt: operation.InitiatedAt,
		UpdatedAt: time.Now(),
		CreatedBy: operation.InitiatedBy,
		UpdatedBy: operation.InitiatedBy,
		Source:    "rollback_manager",
		Tags:      []string{"rollback", string(operation.Status), string(operation.Request.TargetType)},
	}

	// Store in durable storage
	if err := s.configStore.StoreConfig(ctx, entry); err != nil {
		return fmt.Errorf("failed to store operation: %w", err)
	}

	return nil
}

// GetOperation retrieves an operation by ID from storage
func (s *StorageRollbackStore) GetOperation(ctx context.Context, id string) (*RollbackOperation, error) {
	key := &cfgconfig.ConfigKey{
		TenantID:  "system",
		Namespace: "rollback/operations",
		Name:      id,
	}

	entry, err := s.configStore.GetConfig(ctx, key)
	if err != nil {
		// Check if it's a "not found" error
		if err == cfgconfig.ErrConfigNotFound {
			return nil, nil // Return nil operation for not found
		}
		return nil, fmt.Errorf("failed to get operation: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// Unmarshal operation from YAML
	var operation RollbackOperation
	if err := yaml.Unmarshal(entry.Data, &operation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal operation: %w", err)
	}

	return &operation, nil
}

// ListOperations lists operations matching the filters
func (s *StorageRollbackStore) ListOperations(ctx context.Context, filters RollbackFilters) ([]RollbackOperation, error) {
	// Build config filter from rollback filters
	configFilter := &cfgconfig.ConfigFilter{
		TenantID:  "system",
		Namespace: "rollback/operations",
		SortBy:    "created_at",
		Order:     "desc",
	}

	// Add tag filters based on rollback filters
	if filters.Status != "" {
		configFilter.Tags = append(configFilter.Tags, string(filters.Status))
	}
	if filters.TargetType != "" {
		configFilter.Tags = append(configFilter.Tags, string(filters.TargetType))
	}

	// Time-based filtering
	if filters.StartTime != nil {
		configFilter.CreatedAfter = filters.StartTime
	}
	if filters.EndTime != nil {
		configFilter.CreatedBefore = filters.EndTime
	}

	// Set limit if specified (storage layer may have its own max)
	if filters.Limit > 0 {
		configFilter.Limit = filters.Limit * 2 // Get extra for filtering
	}

	// List all operations from storage
	entries, err := s.configStore.ListConfigs(ctx, configFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list operations: %w", err)
	}

	// Unmarshal and filter operations
	var results []RollbackOperation
	for _, entry := range entries {
		var operation RollbackOperation
		if err := yaml.Unmarshal(entry.Data, &operation); err != nil {
			// Log error but continue processing other operations
			continue
		}

		// Apply additional filters that tags can't handle
		if filters.TargetID != "" && operation.Request.TargetID != filters.TargetID {
			continue
		}

		if filters.InitiatedBy != "" && operation.InitiatedBy != filters.InitiatedBy {
			continue
		}

		// Apply strict status filter (tag filtering may be approximate)
		if filters.Status != "" && operation.Status != filters.Status {
			continue
		}

		// Apply strict target type filter
		if filters.TargetType != "" && operation.Request.TargetType != filters.TargetType {
			continue
		}

		results = append(results, operation)

		// Check limit
		if filters.Limit > 0 && len(results) >= filters.Limit {
			break
		}
	}

	// Sort by initiated time (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].InitiatedAt.After(results[j].InitiatedAt)
	})

	return results, nil
}

// UpdateOperation updates an existing operation in storage
func (s *StorageRollbackStore) UpdateOperation(ctx context.Context, operation *RollbackOperation) error {
	if operation.ID == "" {
		return fmt.Errorf("operation ID cannot be empty")
	}

	// Check if operation exists
	existing, err := s.GetOperation(ctx, operation.ID)
	if err != nil {
		return fmt.Errorf("failed to check existing operation: %w", err)
	}

	if existing == nil {
		return fmt.Errorf("operation not found: %s", operation.ID)
	}

	// Marshal operation to YAML for storage
	yamlData, err := yaml.Marshal(operation)
	if err != nil {
		return fmt.Errorf("failed to marshal operation: %w", err)
	}

	// Create updated config entry
	entry := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "system",
			Namespace: "rollback/operations",
			Name:      operation.ID,
		},
		Data:   yamlData,
		Format: cfgconfig.ConfigFormatYAML,
		Metadata: map[string]interface{}{
			"target_type":  string(operation.Request.TargetType),
			"target_id":    operation.Request.TargetID,
			"status":       string(operation.Status),
			"initiated_by": operation.InitiatedBy,
		},
		CreatedAt: existing.InitiatedAt, // Preserve original creation time
		UpdatedAt: time.Now(),
		CreatedBy: existing.InitiatedBy,
		UpdatedBy: operation.InitiatedBy,
		Source:    "rollback_manager",
		Tags:      []string{"rollback", string(operation.Status), string(operation.Request.TargetType)},
	}

	// Update in storage
	if err := s.configStore.StoreConfig(ctx, entry); err != nil {
		return fmt.Errorf("failed to update operation: %w", err)
	}

	return nil
}

// AddAuditEntry adds an audit log entry to an operation
// This method uses a lock to ensure thread-safe audit entry appending
func (s *StorageRollbackStore) AddAuditEntry(ctx context.Context, operationID string, entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get current operation
	operation, err := s.GetOperation(ctx, operationID)
	if err != nil {
		return fmt.Errorf("failed to get operation: %w", err)
	}

	if operation == nil {
		return fmt.Errorf("operation not found: %s", operationID)
	}

	// Append audit entry
	operation.AuditTrail = append(operation.AuditTrail, entry)

	// Update operation with new audit entry
	if err := s.UpdateOperation(ctx, operation); err != nil {
		return fmt.Errorf("failed to update operation with audit entry: %w", err)
	}

	return nil
}
