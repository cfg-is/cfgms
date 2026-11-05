// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package heartbeat

import (
	"context"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Audit actions written for the progress of a steward's repair (Issue #5726).
const (
	auditActionRepairRunning = "steward_tamper_repair_running"
	auditActionRepairFailed  = "steward_tamper_repair_failed"
)

const (
	// repairProgressWindow and repairProgressMaxPerWindow bound the repair audit
	// events for one steward. The reasons are steward-controlled, so a steward
	// cannot grow the audit log faster than this by varying them. A real repair
	// reports a handful of changes (running, then an outcome).
	repairProgressWindow       = time.Minute
	repairProgressMaxPerWindow = 6

	// repairProgressMaxTracked bounds the stewards tracked for deduplication.
	repairProgressMaxTracked = 10000
)

// repairProgressKey identifies the last repair outcome recorded for a steward.
type repairProgressKey struct {
	code     string
	repairID string
}

type repairProgressLast struct {
	key         repairProgressKey
	windowStart time.Time
	count       int
}

// repairRecorder turns the repair reasons of a heartbeat into audit events. A
// reason repeated on every heartbeat is recorded once.
type repairRecorder struct {
	audit  *audit.Manager
	tenant func(ctx context.Context, stewardID string) (string, error)
	logger logging.Logger

	mu   sync.Mutex
	last map[string]repairProgressLast
}

// withRepairProgress returns the per-heartbeat callback of cfg, extended to record
// repair progress when the audit manager and tenant lookup are configured. The
// repair recorder runs first, so a slow user callback never delays it.
func withRepairProgress(cfg *Config) HeartbeatReceivedCallback {
	rec := newRepairRecorder(cfg.RepairAudit, cfg.StewardTenant, cfg.Logger)
	if rec == nil {
		return cfg.OnHeartbeatReceived
	}
	next := cfg.OnHeartbeatReceived
	return func(stewardID string, reasons []controlplaneTypes.HealthReason) {
		rec.record(context.Background(), stewardID, reasons)
		if next != nil {
			next(stewardID, reasons)
		}
	}
}

func newRepairRecorder(am *audit.Manager, tenant func(ctx context.Context, stewardID string) (string, error), logger logging.Logger) *repairRecorder {
	if am == nil || tenant == nil {
		return nil
	}
	return &repairRecorder{audit: am, tenant: tenant, logger: logger, last: make(map[string]repairProgressLast)}
}

// record writes steward_tamper_repair_running for repair.running and
// steward_tamper_repair_failed for a repair failure code. The repair_id is the
// reason's message. The steward stays tampered either way and nothing retries.
func (r *repairRecorder) record(ctx context.Context, stewardID string, reasons []controlplaneTypes.HealthReason) {
	if r == nil {
		return
	}
	for _, reason := range reasons {
		var action string
		switch {
		case reason.Code == controlplaneTypes.ReasonCodeRepairRunning:
			action = auditActionRepairRunning
		case controlplaneTypes.IsRepairFailureCode(reason.Code):
			action = auditActionRepairFailed
		default:
			continue
		}
		repairID := logging.SanitizeLogValue(reason.Message)
		if !r.claim(stewardID, repairProgressKey{code: reason.Code, repairID: repairID}, time.Now()) {
			continue
		}
		r.write(ctx, stewardID, action, reason.Code, repairID)
		return // one event per heartbeat
	}
}

// claim reports whether (steward, outcome) differs from the last one recorded for
// the steward and the steward is inside its event budget for the window.
func (r *repairRecorder) claim(stewardID string, key repairProgressKey, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, ok := r.last[stewardID]
	if ok && prev.key == key {
		return false
	}
	if !ok || now.Sub(prev.windowStart) >= repairProgressWindow {
		prev = repairProgressLast{windowStart: now}
	}
	if prev.count >= repairProgressMaxPerWindow || (!ok && !r.makeRoom(now)) {
		return false
	}
	prev.key = key
	prev.count++
	r.last[stewardID] = prev
	return true
}

// makeRoom drops expired entries when the table is full and reports whether a new
// steward can be tracked. The caller holds r.mu.
func (r *repairRecorder) makeRoom(now time.Time) bool {
	if len(r.last) < repairProgressMaxTracked {
		return true
	}
	for id, p := range r.last {
		if now.Sub(p.windowStart) >= repairProgressWindow {
			delete(r.last, id)
		}
	}
	return len(r.last) < repairProgressMaxTracked
}

func (r *repairRecorder) write(ctx context.Context, stewardID, action, code, repairID string) {
	tenantID, err := r.tenant(ctx, stewardID)
	if err != nil || tenantID == "" {
		if r.logger != nil {
			r.logger.Warn("Repair progress not recorded: steward tenant unknown",
				"steward_id", logging.SanitizeLogValue(stewardID))
		}
		return
	}
	result := business.AuditResultSuccess
	severity := business.AuditSeverityMedium
	if action == auditActionRepairFailed {
		result = business.AuditResultFailure
		severity = business.AuditSeverityHigh
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSecurityEvent).
		Action(action).
		User(stewardID, business.AuditUserTypeSystem).
		Resource("steward", stewardID, "").
		Result(result).
		Severity(severity).
		Detail("steward_id", stewardID).
		Detail("repair_id", repairID).
		Detail("codes", []string{code})
	if err := r.audit.RecordEvent(context.WithoutCancel(ctx), b); err != nil && r.logger != nil {
		r.logger.Warn("Failed to record repair progress audit event",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
