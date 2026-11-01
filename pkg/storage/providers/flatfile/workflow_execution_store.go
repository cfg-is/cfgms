// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.WorkflowExecutionStore = (*FlatFileWorkflowExecutionStore)(nil)

// FlatFileWorkflowExecutionStore implements business.WorkflowExecutionStore with one
// JSON file per execution.
//
// File layout: <root>/workflow_executions/<tenant>/<execution>.json
//
// Tenant and execution ids are base64url-encoded into path segments, so no id can
// escape its directory and the root tenant (empty id) has a directory of its own.
// Writes are atomic (temp-file + rename); sync.Mutex serializes read-modify-write
// within the process. The files live on one host, so only that node sees them: use
// the database provider where every controller node must read every run.
type FlatFileWorkflowExecutionStore struct {
	root string
	mu   sync.Mutex
}

// workflowExecutionJSON is the on-disk representation of an execution record.
type workflowExecutionJSON struct {
	TenantID     string          `json:"tenant_id"`
	ExecutionID  string          `json:"execution_id"`
	WorkflowName string          `json:"workflow_name"`
	Status       string          `json:"status"`
	StartTime    time.Time       `json:"start_time"`
	EndTime      *time.Time      `json:"end_time,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
}

// NewFlatFileWorkflowExecutionStore creates a store rooted at <root>/workflow_executions.
func NewFlatFileWorkflowExecutionStore(root string) (*FlatFileWorkflowExecutionStore, error) {
	if err := os.MkdirAll(filepath.Join(root, "workflow_executions"), 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create workflow executions directory: %w", err)
	}
	return &FlatFileWorkflowExecutionStore{root: root}, nil
}

func executionSegment(id string) string {
	if id == "" {
		return "_"
	}
	return "-" + base64.RawURLEncoding.EncodeToString([]byte(id))
}

func (s *FlatFileWorkflowExecutionStore) tenantDir(tenantID string) string {
	return filepath.Join(s.root, "workflow_executions", executionSegment(tenantID))
}

func (s *FlatFileWorkflowExecutionStore) recordPath(tenantID, executionID string) string {
	return filepath.Join(s.tenantDir(tenantID), executionSegment(executionID)+".json")
}

func toWorkflowExecutionRecord(j workflowExecutionJSON) *business.WorkflowExecutionRecord {
	return &business.WorkflowExecutionRecord{
		TenantID: j.TenantID, ExecutionID: j.ExecutionID, WorkflowName: j.WorkflowName, Status: j.Status,
		StartTime: j.StartTime, EndTime: timeVal(j.EndTime), Payload: []byte(j.Payload),
	}
}

// readOne reads one record file. Must be called with the lock held.
func (s *FlatFileWorkflowExecutionStore) readOne(path string) (workflowExecutionJSON, error) {
	var j workflowExecutionJSON
	raw, err := readFile(path)
	if err != nil {
		return j, err
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return j, fmt.Errorf("flatfile: failed to parse workflow execution file: %w", err)
	}
	return j, nil
}

// readTenant loads every record of tenantID, newest StartTime first.
// Must be called with the lock held.
func (s *FlatFileWorkflowExecutionStore) readTenant(tenantID string) ([]workflowExecutionJSON, error) {
	entries, err := os.ReadDir(s.tenantDir(tenantID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read workflow executions directory: %w", err)
	}
	records := make([]workflowExecutionJSON, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		j, err := s.readOne(filepath.Join(s.tenantDir(tenantID), entry.Name()))
		if err != nil {
			return nil, err
		}
		records = append(records, j)
	}
	sort.Slice(records, func(a, b int) bool {
		if !records[a].StartTime.Equal(records[b].StartTime) {
			return records[a].StartTime.After(records[b].StartTime)
		}
		return records[a].ExecutionID > records[b].ExecutionID
	})
	return records, nil
}

// Save implements business.WorkflowExecutionStore.
func (s *FlatFileWorkflowExecutionStore) Save(_ context.Context, r *business.WorkflowExecutionRecord) error {
	if r == nil || r.ExecutionID == "" {
		return fmt.Errorf("flatfile: workflow execution requires an execution id")
	}
	payload := json.RawMessage(r.Payload)
	if len(payload) > 0 && !json.Valid(payload) {
		return fmt.Errorf("flatfile: workflow execution payload is not valid JSON")
	}
	j := workflowExecutionJSON{
		TenantID: r.TenantID, ExecutionID: r.ExecutionID, WorkflowName: r.WorkflowName, Status: r.Status,
		StartTime: r.StartTime.UTC(), EndTime: timePtr(r.EndTime), Payload: payload,
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal workflow execution: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.recordPath(r.TenantID, r.ExecutionID)
	if existing, err := s.readOne(path); err == nil {
		if business.IsTerminalWorkflowExecutionStatus(existing.Status) && !business.IsTerminalWorkflowExecutionStatus(r.Status) {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(s.tenantDir(r.TenantID), 0750); err != nil {
		return fmt.Errorf("flatfile: failed to create workflow executions tenant directory: %w", err)
	}
	return writeAtomic(path, raw)
}

// Get implements business.WorkflowExecutionStore.
func (s *FlatFileWorkflowExecutionStore) Get(_ context.Context, tenantID, executionID string) (*business.WorkflowExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.readOne(s.recordPath(tenantID, executionID))
	if os.IsNotExist(err) {
		return nil, business.ErrWorkflowExecutionNotFound
	}
	if err != nil {
		return nil, err
	}
	return toWorkflowExecutionRecord(j), nil
}

// List implements business.WorkflowExecutionStore.
func (s *FlatFileWorkflowExecutionStore) List(_ context.Context, tenantID, workflowName string, limit int) ([]*business.WorkflowExecutionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readTenant(tenantID)
	if err != nil {
		return nil, err
	}
	result := make([]*business.WorkflowExecutionRecord, 0, len(records))
	for _, j := range records {
		if workflowName != "" && j.WorkflowName != workflowName {
			continue
		}
		result = append(result, toWorkflowExecutionRecord(j))
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result, nil
}

// Prune implements business.WorkflowExecutionStore.
func (s *FlatFileWorkflowExecutionStore) Prune(_ context.Context, tenantID string, keep int) (int, error) {
	if keep < 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readTenant(tenantID)
	if err != nil {
		return 0, err
	}
	kept, deleted := 0, 0
	for _, j := range records {
		if !business.IsTerminalWorkflowExecutionStatus(j.Status) {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if err := os.Remove(s.recordPath(j.TenantID, j.ExecutionID)); err != nil && !os.IsNotExist(err) {
			return deleted, fmt.Errorf("flatfile: failed to prune workflow execution: %w", err)
		}
		deleted++
	}
	return deleted, nil
}
