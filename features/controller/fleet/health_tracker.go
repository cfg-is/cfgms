// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

// HealthTracker is the controller-side fleet registry. It persists durable
// steward fields (status, last_seen, last_heartbeat) via a StewardStore so the
// fleet view survives controller restarts. Ephemeral per-process metrics (task
// latency, config errors, recovery counters) remain in-memory via a sync.Map
// and are not written to the store.
//
// Constructor injection: the caller (controller initialization) provides the
// concrete StewardStore implementation (flat-file for OSS, SQLite for default
// business-data tier).

import (
	"context"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// HealthStatus represents the health status of a tracked steward.
type HealthStatus string

const (
	// StatusHealthy indicates the steward is operating normally.
	StatusHealthy HealthStatus = "healthy"

	// StatusDegraded indicates the steward is operational but with issues.
	StatusDegraded HealthStatus = "degraded"

	// StatusUnhealthy indicates the steward is not functioning properly.
	StatusUnhealthy HealthStatus = "unhealthy"
)

// HealthMetrics holds ephemeral (in-memory only) health metrics for a single steward.
// These are not persisted — they reset on controller restart.
type HealthMetrics struct {
	Status           HealthStatus
	LastStatusChange time.Time

	ControllerConnected bool
	LastHeartbeat       time.Time
	HeartbeatErrors     int

	TaskCount          int
	TotalTaskLatency   time.Duration
	AverageTaskLatency time.Duration

	ConfigErrors int
}

// HealthTracker tracks fleet health state for the controller.
// Durable fields are persisted via StewardStore; ephemeral HealthMetrics stay in-memory.
type HealthTracker struct {
	store   business.StewardStore
	logger  logging.Logger
	metrics sync.Map // map[stewardID string]*HealthMetrics
}

// NewHealthTracker creates a HealthTracker backed by the given store.
func NewHealthTracker(store business.StewardStore, logger logging.Logger) *HealthTracker {
	return &HealthTracker{
		store:  store,
		logger: logger,
	}
}

// RegisterSteward persists a new steward record and initialises in-memory metrics.
func (t *HealthTracker) RegisterSteward(ctx context.Context, record *business.StewardRecord) error {
	if err := t.store.RegisterSteward(ctx, record); err != nil {
		return err
	}
	t.metrics.Store(record.ID, &HealthMetrics{
		Status:           StatusHealthy,
		LastStatusChange: time.Now(),
	})
	t.logger.Info("Steward registered",
		"steward_id", logging.SanitizeLogValue(record.ID),
		"hostname", logging.SanitizeLogValue(record.Hostname),
		"platform", record.Platform)
	return nil
}

// UpdateHeartbeat records a steward heartbeat, updating durable timestamps.
// Also marks the steward active if it was previously registered.
func (t *HealthTracker) UpdateHeartbeat(ctx context.Context, stewardID string) error {
	if err := t.store.UpdateHeartbeat(ctx, stewardID); err != nil {
		return err
	}
	// Promote registered → active on first heartbeat
	rec, err := t.store.GetSteward(ctx, stewardID)
	if err == nil && rec.Status == business.StewardStatusRegistered {
		if statusErr := t.store.UpdateStewardStatus(ctx, stewardID, business.StewardStatusActive); statusErr != nil {
			t.logger.Warn("Failed to promote steward to active",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", statusErr)
		}
	}
	// Refresh in-memory heartbeat time
	if m, ok := t.metrics.Load(stewardID); ok {
		metrics := m.(*HealthMetrics)
		metrics.LastHeartbeat = time.Now()
		metrics.HeartbeatErrors = 0
		metrics.ControllerConnected = true
	}
	return nil
}

// MarkLost marks a steward as lost (last_seen exceeded the configured TTL).
func (t *HealthTracker) MarkLost(ctx context.Context, stewardID string) error {
	t.logger.Warn("Marking steward as lost", "steward_id", logging.SanitizeLogValue(stewardID))
	return t.store.UpdateStewardStatus(ctx, stewardID, business.StewardStatusLost)
}

// DeregisterSteward marks a steward as deregistered. Records are retained for audit.
func (t *HealthTracker) DeregisterSteward(ctx context.Context, stewardID string) error {
	t.logger.Info("Deregistering steward", "steward_id", logging.SanitizeLogValue(stewardID))
	return t.store.DeregisterSteward(ctx, stewardID)
}

// GetSteward returns the durable record for the given steward.
func (t *HealthTracker) GetSteward(ctx context.Context, stewardID string) (*business.StewardRecord, error) {
	return t.store.GetSteward(ctx, stewardID)
}

// ListStewards returns all steward records from the durable store.
func (t *HealthTracker) ListStewards(ctx context.Context) ([]*business.StewardRecord, error) {
	return t.store.ListStewards(ctx)
}

// ListActiveStewards returns stewards currently in the active state.
func (t *HealthTracker) ListActiveStewards(ctx context.Context) ([]*business.StewardRecord, error) {
	return t.store.ListStewardsByStatus(ctx, business.StewardStatusActive)
}

// GetEphemeralMetrics returns the in-memory HealthMetrics for a steward.
// Returns nil if no metrics have been initialised for the steward (e.g. after a controller restart).
func (t *HealthTracker) GetEphemeralMetrics(stewardID string) *HealthMetrics {
	if v, ok := t.metrics.Load(stewardID); ok {
		return v.(*HealthMetrics)
	}
	return nil
}

// RecordTaskLatency records task latency for a steward's in-memory metrics.
func (t *HealthTracker) RecordTaskLatency(stewardID string, latency time.Duration) {
	m := t.getOrInitMetrics(stewardID)
	m.TaskCount++
	m.TotalTaskLatency += latency
	if m.TaskCount > 0 {
		m.AverageTaskLatency = m.TotalTaskLatency / time.Duration(m.TaskCount)
	}
}

// RecordConfigError increments the config error counter for a steward's in-memory metrics.
func (t *HealthTracker) RecordConfigError(stewardID string) {
	m := t.getOrInitMetrics(stewardID)
	m.ConfigErrors++
}

// getOrInitMetrics loads or creates the in-memory HealthMetrics for a steward.
func (t *HealthTracker) getOrInitMetrics(stewardID string) *HealthMetrics {
	v, _ := t.metrics.LoadOrStore(stewardID, &HealthMetrics{
		Status:           StatusHealthy,
		LastStatusChange: time.Now(),
	})
	return v.(*HealthMetrics)
}
