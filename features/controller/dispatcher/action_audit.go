// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dispatcher

import (
	"context"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// auditResourceStewardAction is the audit resource type for steward actions.
const auditResourceStewardAction = "steward_action"

// AuditManagerSink is the production ActionAuditSink: it writes each steward
// action the expiry sweep closed without a result to the controller's durable
// audit log (Issue #4625).
type AuditManagerSink struct {
	manager *audit.Manager
	logger  logging.Logger
}

// NewAuditManagerSink returns an ActionAuditSink backed by manager. It returns a
// nil interface (not a typed nil) when manager is nil, so the dispatcher's own
// nil check holds.
func NewAuditManagerSink(manager *audit.Manager, logger logging.Logger) ActionAuditSink {
	if manager == nil {
		return nil
	}
	return &AuditManagerSink{manager: manager, logger: logger}
}

// RecordActionExpired records one closed action. The operator who issued the
// action is the audited actor, so the outcome stays attributable to them; the
// controller closed it, which is recorded in the details.
func (s *AuditManagerSink) RecordActionExpired(ctx context.Context, job ExpiredActionJob) {
	tenantID := job.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	userID, userType := job.CreatedBy, business.AuditUserTypeHuman
	if userID == "" {
		userID, userType = audit.SystemUserID, business.AuditUserTypeSystem
	}
	resourceID := job.ExecutionID
	if resourceID == "" {
		resourceID = job.JobID
	}

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(auditResourceStewardAction+"_"+job.ResultCode).
		User(userID, userType).
		Resource(auditResourceStewardAction, resourceID, job.Action.Verb).
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityMedium).
		Details(map[string]interface{}{
			"run_id":      job.RunID,
			"job_id":      job.JobID,
			"device_id":   job.DeviceID,
			"verb":        job.Action.Verb,
			"target_kind": job.Action.TargetKind,
			"target_name": job.Action.TargetName,
			"result_code": job.ResultCode,
			"detail":      job.Detail,
			"closed_by":   "controller",
			"closed_at":   job.At,
		})

	if err := s.manager.RecordEvent(ctx, event); err != nil && s.logger != nil {
		s.logger.Error("Failed to audit steward action closed without a result",
			"run_id", logging.SanitizeLogValue(job.RunID),
			"execution_id", logging.SanitizeLogValue(job.ExecutionID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
