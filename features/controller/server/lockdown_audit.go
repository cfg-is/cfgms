// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"

	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// auditActionCommandRefusedLockedDown is recorded for each command the
	// lockdown gate refuses.
	auditActionCommandRefusedLockedDown = "command_refused_locked_down"

	// auditActionOperatorCommandLockedDown is recorded for each operator-origin
	// command the gate lets through to a locked-down steward.
	auditActionOperatorCommandLockedDown = "operator_command_to_locked_steward"

	lockdownAuditFallbackTenant = "system"
)

// lockdownAuditObserver writes the command gate's audit events (Issue #5665).
type lockdownAuditObserver struct {
	audit  *audit.Manager
	store  business.StewardStore
	logger logging.Logger
}

var _ controlplaneInterfaces.LockdownObserver = (*lockdownAuditObserver)(nil)

func newLockdownAuditObserver(auditManager *audit.Manager, store business.StewardStore, logger logging.Logger) *lockdownAuditObserver {
	return &lockdownAuditObserver{audit: auditManager, store: store, logger: logger}
}

func (o *lockdownAuditObserver) tenantOf(ctx context.Context, stewardID string) string {
	if o.store != nil {
		if rec, err := o.store.GetSteward(ctx, stewardID); err == nil && rec != nil && rec.TenantID != "" {
			return rec.TenantID
		}
	}
	return lockdownAuditFallbackTenant
}

// CommandRefused implements controlplaneInterfaces.LockdownObserver.
func (o *lockdownAuditObserver) CommandRefused(ctx context.Context, stewardID string, cmdType controlplaneTypes.CommandType, reason string) {
	cmd := logging.SanitizeLogValue(string(cmdType))
	o.logger.Warn("Command refused: steward is locked down",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"command_type", cmd,
		"reason", logging.SanitizeLogValue(reason))
	if o.audit == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(o.tenantOf(ctx, stewardID)).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionCommandRefusedLockedDown).
		User("controller", business.AuditUserTypeSystem).
		Resource("steward", stewardID, "").
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Detail("steward_id", stewardID).
		Detail("command_type", cmd).
		Detail("reason", reason)
	if err := o.audit.RecordEvent(ctx, b); err != nil {
		o.logger.Warn("Failed to record command refusal audit event",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// OperatorCommandAllowed implements controlplaneInterfaces.LockdownObserver.
func (o *lockdownAuditObserver) OperatorCommandAllowed(ctx context.Context, operator, stewardID string, cmdType controlplaneTypes.CommandType) {
	cmd := logging.SanitizeLogValue(string(cmdType))
	o.logger.Info("Operator command allowed to locked-down steward",
		"operator", logging.SanitizeLogValue(operator),
		"steward_id", logging.SanitizeLogValue(stewardID),
		"command_type", cmd)
	if o.audit == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(o.tenantOf(ctx, stewardID)).
		Type(business.AuditEventSecurityEvent).
		Action(auditActionOperatorCommandLockedDown).
		User(operator, business.AuditUserTypeHuman).
		Resource("steward", stewardID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("operator", operator).
		Detail("steward_id", stewardID).
		Detail("command_type", cmd)
	if err := o.audit.RecordEvent(ctx, b); err != nil {
		o.logger.Warn("Failed to record operator command audit event",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
