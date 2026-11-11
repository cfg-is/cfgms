// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/version"
)

// Audit actions for rollout and upgrade lifecycle events.
const (
	auditRolloutStarted        = "rollout_started"
	auditRolloutCompleted      = "rollout_completed"
	auditRolloutHalted         = "rollout_halted"
	auditRolloutAutoHalted     = "rollout_auto_halted"
	auditUpgradeDispatched     = "steward_upgrade_dispatched"
	auditUpgradeRolledBack     = "steward_upgrade_rolled_back"
	markerKindRolloutStarted   = "rollout_started"
	markerKindRolloutCompleted = "rollout_completed"
	markerKindRolloutHalted    = "rollout_halted"
	markerKindRolloutAutoHalt  = "rollout_auto_halted"
	markerKindUpgradeDispatch  = "upgrade_dispatched"
	markerKindUpgradeRollback  = "upgrade_rolled_back"
)

// Halt reason classes recorded on rollout_auto_halted.
const (
	haltClassRingHealthQueryFailed = "ring_health_query_failed"
	haltClassFailureRateExceeded   = "failure_rate_exceeded"
)

// systemAuditPrincipal attributes a system-initiated event whose rollout record names no
// initiating principal.
const systemAuditPrincipal = "system"

// rolloutAuditEvent describes one deploy-relevant event. It is written twice: as an
// audit row under the owning tenant and as a marker row under the system tenant.
type rolloutAuditEvent struct {
	tenantID     string
	action       string
	markerKind   string
	resourceType string
	resourceID   string
	// revision is the target (or restored) version string.
	revision  string
	principal string
	userType  business.AuditUserType
	severity  business.AuditSeverity
	details   map[string]interface{}
}

// auditDetails returns the tenant audit row details: the event's own details plus the
// revision, the controller revision and the principal.
func (e rolloutAuditEvent) auditDetails() map[string]interface{} {
	d := make(map[string]interface{}, len(e.details)+3)
	for k, v := range e.details {
		d[k] = v
	}
	d["revision"] = e.revision
	d["controller_revision"] = version.Revision()
	d["principal"] = e.principal
	return d
}

// emitRolloutAudit writes the event's tenant audit row and its system-tenant marker row.
// It never blocks or fails the caller: a write failure is logged and dropped, matching
// emitOperatorAudit.
func (s *Server) emitRolloutAudit(ctx context.Context, e rolloutAuditEvent) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(rolloutAuditTenant(e.tenantID)).
		Type(business.AuditEventConfiguration).
		Action(e.action).
		User(e.principal, e.userType).
		Resource(e.resourceType, e.resourceID, "").
		Result(business.AuditResultSuccess).
		Severity(e.severity)
	for k, v := range e.auditDetails() {
		b = b.Detail(k, v)
	}
	s.recordRolloutAudit(ctx, e.action, b)
	s.emitDeployMarker(ctx, e)
}

// emitDeployMarker is the single writer of the six marker_* rows for rollout and upgrade
// events. The row is always under the system tenant, regardless of the event's tenant, so
// the marker reader (system tenant only) sees tenant-bound rollouts. It carries only the
// revision, the principal id and the rollout or upgrade id.
func (s *Server) emitDeployMarker(ctx context.Context, e rolloutAuditEvent) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSystemEvent).
		Action(markerActionPrefix+e.markerKind).
		User(e.principal, e.userType).
		Resource(e.resourceType, e.resourceID, "").
		Detail("principal", e.principal).
		Detail("revision", e.revision).
		Severity(business.AuditSeverityLow)
	s.recordRolloutAudit(ctx, markerActionPrefix+e.markerKind, b)
}

func (s *Server) recordRolloutAudit(ctx context.Context, action string, b *audit.AuditEventBuilder) {
	auditCtx, cancel := detachedAuditContext(ctx)
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit rollout audit event",
			"error", logging.SanitizeLogValue(err.Error()), "action", logging.SanitizeLogValue(action))
	}
}

// emitOperatorDeployEvent audits an operator-initiated rollout or upgrade event, naming
// the request's principal, and writes its marker row.
func (s *Server) emitOperatorDeployEvent(r *http.Request, principal *Principal, e rolloutAuditEvent) {
	e.principal = systemAuditPrincipal
	if principal != nil && principal.ID != "" {
		e.principal = principal.ID
	}
	e.userType = principalAuditUserType(principal)
	s.emitRolloutAudit(r.Context(), e)
}

// emitSystemRolloutEvent audits an event runRollout produced without a request. It
// attributes the principal that started the rollout.
func (s *Server) emitSystemRolloutEvent(ctx context.Context, record *business.RolloutRecord, action, markerKind string, severity business.AuditSeverity, details map[string]interface{}) {
	principal := record.InitiatedBy
	if principal == "" {
		principal = systemAuditPrincipal
	}
	d := map[string]interface{}{
		"rollout_id":     record.ID,
		"target_version": record.TargetVersion,
		"tenant_id":      record.TenantID,
		"rings_total":    record.RingsTotal,
	}
	for k, v := range details {
		d[k] = v
	}
	s.emitRolloutAudit(ctx, rolloutAuditEvent{
		tenantID:     record.TenantID,
		action:       action,
		markerKind:   markerKind,
		resourceType: "rollout",
		resourceID:   record.ID,
		revision:     record.TargetVersion,
		principal:    principal,
		userType:     business.AuditUserTypeSystem,
		severity:     severity,
		details:      d,
	})
}
