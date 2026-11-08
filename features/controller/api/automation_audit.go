// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// emitAutomationAudit records one automation-route call, accepted or refused, under
// the grant identity and the triggering event (ADR-036 section 3), via
// audit.NewEventBuilder as emitOperatorPayloadDispatchAudit does. The record is filed
// under the run tenant; ownerTenant is the grant's own tenant. runID is whatever the
// caller presented (a refused call may present an id that names no run), and the
// credential is never an input here. Every caller-supplied value is passed through
// logging.SanitizeLogValue. It is a no-op while no audit manager is wired.
func (s *Server) emitAutomationAudit(ctx context.Context, grantID, runID, tenant, ownerTenant, eventRef, action string, result business.AuditResult, details ...auditDetail) {
	if s.auditManager == nil {
		return
	}
	auditTenant := tenant
	if auditTenant == "" {
		auditTenant = ownerTenant
	}
	if auditTenant == "" {
		auditTenant = audit.SystemTenantID
	}

	severity := business.AuditSeverityMedium
	if result != business.AuditResultSuccess {
		severity = business.AuditSeverityHigh
	}

	resourceID := logging.SanitizeLogValue(runID)
	if resourceID == "" {
		resourceID = "unresolved"
	}
	userID := logging.SanitizeLogValue(grantID)
	if userID == "" {
		userID = "unresolved"
	}

	b := audit.NewEventBuilder().
		Tenant(auditTenant).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(userID, business.AuditUserTypeAPI).
		Resource("automation_run", resourceID, "").
		Result(result).
		Severity(severity).
		Detail("grant_id", userID).
		Detail("run_id", resourceID).
		Detail("tenant_id", logging.SanitizeLogValue(tenant)).
		Detail("owner_tenant_id", logging.SanitizeLogValue(ownerTenant)).
		Detail("event_ref", logging.SanitizeLogValue(eventRef))
	for _, d := range details {
		b = b.Detail(d.Key, logging.SanitizeLogValue(d.Value))
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit automation audit event",
			"run_id", logging.SanitizeLogValue(runID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
