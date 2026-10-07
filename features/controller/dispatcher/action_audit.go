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

// RecordActionCompleted records one action that reported a result. The audited
// actor is the operator who issued it, so the outcome stays attributable to them.
// A result other than "ok" is recorded as a failure.
func (s *AuditManagerSink) RecordActionCompleted(ctx context.Context, job ExpiredActionJob) {
	result, severity := business.AuditResultSuccess, business.AuditSeverityHigh
	if job.ResultCode != "ok" {
		result, severity = business.AuditResultFailure, business.AuditSeverityMedium
	}
	s.record(ctx, job, auditResourceStewardAction+"_completed", result, severity, map[string]interface{}{
		"completed_at": job.At,
	})
}

// RecordActionExpired records one closed action. The operator who issued the
// action is the audited actor, so the outcome stays attributable to them; the
// controller closed it, which is recorded in the details.
func (s *AuditManagerSink) RecordActionExpired(ctx context.Context, job ExpiredActionJob) {
	s.record(ctx, job, auditResourceStewardAction+"_"+job.ResultCode, business.AuditResultFailure, business.AuditSeverityMedium, map[string]interface{}{
		"detail":    job.Detail,
		"closed_by": "controller",
		"closed_at": job.At,
	})
}

// record writes one steward-action outcome event. The resource id is the
// execution id (cfg-declared by the controller, never a live host name).
func (s *AuditManagerSink) record(ctx context.Context, job ExpiredActionJob, action string, result business.AuditResult, severity business.AuditSeverity, extra map[string]interface{}) {
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

	details := map[string]interface{}{
		"run_id":      job.RunID,
		"job_id":      job.JobID,
		"device_id":   job.DeviceID,
		"verb":        job.Action.Verb,
		"target_kind": job.Action.TargetKind,
		"target_name": job.Action.TargetName,
		"result_code": job.ResultCode,
	}
	for k, v := range extra {
		details[k] = v
	}

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(userID, userType).
		Resource(auditResourceStewardAction, resourceID, job.Action.Verb).
		Result(result).
		Severity(severity).
		Details(details)

	if err := s.manager.RecordEvent(ctx, event); err != nil && s.logger != nil {
		s.logger.Error("Failed to audit steward action outcome",
			"run_id", logging.SanitizeLogValue(job.RunID),
			"execution_id", logging.SanitizeLogValue(job.ExecutionID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
