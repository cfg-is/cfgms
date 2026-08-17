// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.AlertStore = (*FlatFileAlertStore)(nil)

// FlatFileAlertStore implements business.AlertStore backed by a single JSON file.
//
// File layout: <root>/alerts/alert_states.json
//
// All states across all tenants are stored in a flat JSON array. Writes are
// atomic (temp-file + rename). sync.RWMutex serializes goroutine access within
// one process.
type FlatFileAlertStore struct {
	root string
	mu   sync.RWMutex
}

// alertStateJSON is the on-disk representation of an alert state.
type alertStateJSON struct {
	AlertID        string    `json:"alert_id"`
	TenantID       string    `json:"tenant_id"`
	Acknowledged   bool      `json:"acknowledged"`
	AcknowledgedBy string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt time.Time `json:"acknowledged_at,omitempty"`
	Silenced       bool      `json:"silenced"`
	SilencedBy     string    `json:"silenced_by,omitempty"`
	SilencedUntil  time.Time `json:"silenced_until,omitempty"`
}

// NewFlatFileAlertStore creates a FlatFileAlertStore rooted at <root>/alerts.
// The directory is created if it does not exist.
func NewFlatFileAlertStore(root string) (*FlatFileAlertStore, error) {
	dir := filepath.Join(root, "alerts")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create alerts directory: %w", err)
	}
	return &FlatFileAlertStore{root: root}, nil
}

func (s *FlatFileAlertStore) dataFilePath() string {
	return filepath.Join(s.root, "alerts", "alert_states.json")
}

// load reads and parses the alert_states.json file.
// Returns nil slice when the file does not exist.
// Must be called with at least a read lock held.
func (s *FlatFileAlertStore) load() ([]alertStateJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read alert states file: %w", err)
	}
	var states []alertStateJSON
	if err := json.Unmarshal(raw, &states); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse alert states file: %w", err)
	}
	return states, nil
}

// save atomically writes states to alert_states.json.
// Must be called with a write lock held.
func (s *FlatFileAlertStore) save(states []alertStateJSON) error {
	if states == nil {
		states = []alertStateJSON{}
	}
	raw, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal alert states: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// AcknowledgeAlert implements AlertStore.AcknowledgeAlert.
func (s *FlatFileAlertStore) AcknowledgeAlert(_ context.Context, tenantID, alertID, principal string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	states, err := s.load()
	if err != nil {
		return err
	}

	for i, st := range states {
		if st.TenantID == tenantID && st.AlertID == alertID {
			states[i].Acknowledged = true
			states[i].AcknowledgedBy = principal
			states[i].AcknowledgedAt = at.UTC()
			return s.save(states)
		}
	}

	states = append(states, alertStateJSON{
		AlertID:        alertID,
		TenantID:       tenantID,
		Acknowledged:   true,
		AcknowledgedBy: principal,
		AcknowledgedAt: at.UTC(),
	})
	return s.save(states)
}

// SilenceAlert implements AlertStore.SilenceAlert.
func (s *FlatFileAlertStore) SilenceAlert(_ context.Context, tenantID, alertID, principal string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	states, err := s.load()
	if err != nil {
		return err
	}

	for i, st := range states {
		if st.TenantID == tenantID && st.AlertID == alertID {
			states[i].Silenced = true
			states[i].SilencedBy = principal
			states[i].SilencedUntil = until.UTC()
			return s.save(states)
		}
	}

	states = append(states, alertStateJSON{
		AlertID:       alertID,
		TenantID:      tenantID,
		Silenced:      true,
		SilencedBy:    principal,
		SilencedUntil: until.UTC(),
	})
	return s.save(states)
}

// GetAlertState implements AlertStore.GetAlertState.
// Returns nil, nil when the alertID has never been acknowledged or silenced.
func (s *FlatFileAlertStore) GetAlertState(_ context.Context, tenantID, alertID string) (*business.AlertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states, err := s.load()
	if err != nil {
		return nil, err
	}

	for _, st := range states {
		if st.TenantID == tenantID && st.AlertID == alertID {
			return toAlertState(st), nil
		}
	}
	return nil, nil
}

// ListAlertStates implements AlertStore.ListAlertStates.
// Returns an empty (non-nil) slice when no states exist for tenantID.
func (s *FlatFileAlertStore) ListAlertStates(_ context.Context, tenantID string) ([]*business.AlertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states, err := s.load()
	if err != nil {
		return nil, err
	}

	result := make([]*business.AlertState, 0)
	for _, st := range states {
		if st.TenantID != tenantID {
			continue
		}
		result = append(result, toAlertState(st))
	}
	return result, nil
}

func toAlertState(st alertStateJSON) *business.AlertState {
	return &business.AlertState{
		AlertID:        st.AlertID,
		TenantID:       st.TenantID,
		Acknowledged:   st.Acknowledged,
		AcknowledgedBy: st.AcknowledgedBy,
		AcknowledgedAt: st.AcknowledgedAt,
		Silenced:       st.Silenced,
		SilencedBy:     st.SilencedBy,
		SilencedUntil:  st.SilencedUntil,
	}
}
