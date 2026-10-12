// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// auditActionIdentityConflict is the audit action recorded when one steward
	// identity is seen on two endpoints (ADR-034 §3).
	auditActionIdentityConflict = "steward_identity_conflict_detected"

	// identityConflictInterval is the minimum spacing between audit events for
	// one steward ID, so a looping copy cannot flood the audit log.
	identityConflictInterval = time.Minute

	// identityConflictFallbackTenant owns the event when the steward has no
	// resolvable tenant; the audit store requires a tenant on every entry.
	identityConflictFallbackTenant = "system"
)

// identityConflictAuditObserver writes a high-severity audit event for each
// reported identity conflict, rate-limited per steward ID (in memory).
type identityConflictAuditObserver struct {
	audit  *audit.Manager
	logger logging.Logger
	now    func() time.Time

	mu       sync.Mutex
	lastSeen map[string]time.Time
}

var _ grpcCP.IdentityConflictObserver = (*identityConflictAuditObserver)(nil)

func newIdentityConflictAuditObserver(auditManager *audit.Manager, logger logging.Logger) *identityConflictAuditObserver {
	return &identityConflictAuditObserver{
		audit:    auditManager,
		logger:   logger,
		now:      time.Now,
		lastSeen: make(map[string]time.Time),
	}
}

// allow reports whether an event for stewardID may be written now, and records
// the attempt. Stale entries are pruned so the map stays bounded.
func (o *identityConflictAuditObserver) allow(stewardID string) bool {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	if last, ok := o.lastSeen[stewardID]; ok && now.Sub(last) < identityConflictInterval {
		return false
	}
	for id, t := range o.lastSeen {
		if now.Sub(t) >= identityConflictInterval {
			delete(o.lastSeen, id)
		}
	}
	o.lastSeen[stewardID] = now
	return true
}

// ObserveIdentityConflict implements grpcCP.IdentityConflictObserver.
func (o *identityConflictAuditObserver) ObserveIdentityConflict(ctx context.Context, c grpcCP.IdentityConflict) {
	if o.audit == nil || !o.allow(c.StewardID) {
		return
	}
	tenantID := c.TenantID
	if tenantID == "" {
		tenantID = identityConflictFallbackTenant
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionIdentityConflict).
		User(c.StewardID, business.AuditUserTypeSystem).
		Resource("steward", c.StewardID, "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Detail("steward_id", c.StewardID).
		Detail("existing_addr", c.ExistingAddr).
		Detail("new_addr", c.NewAddr).
		Detail("existing_serial", c.ExistingSerial).
		Detail("new_serial", c.NewSerial).
		Detail("detected_at", c.DetectedAt.UTC().Format(time.RFC3339))
	if err := o.audit.RecordEvent(ctx, b); err != nil {
		o.logger.Warn("Failed to record steward identity conflict audit event",
			"steward_id", logging.SanitizeLogValue(c.StewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
