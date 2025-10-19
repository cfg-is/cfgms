// Package rbac - Sensitive operation controls for admin actions
package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

var (
	// ErrJustificationRequired is returned when a sensitive operation lacks justification
	ErrJustificationRequired = errors.New("justification required for sensitive operation")
)

// M-AUTH-2: Sensitive operation tracking (security audit finding)
// These operations require additional justification and audit logging

// SensitiveOperationType defines categories of sensitive operations
type SensitiveOperationType string

const (
	// Permission management operations
	SensitiveOpCreateRole   SensitiveOperationType = "create_role"
	SensitiveOpDeleteRole   SensitiveOperationType = "delete_role"
	SensitiveOpModifyRole   SensitiveOperationType = "modify_role"
	SensitiveOpAssignRole   SensitiveOperationType = "assign_role"
	SensitiveOpRevokeRole   SensitiveOperationType = "revoke_role"

	// Permission operations
	SensitiveOpCreatePermission SensitiveOperationType = "create_permission"
	SensitiveOpDeletePermission SensitiveOperationType = "delete_permission"

	// User management operations
	SensitiveOpCreateUser   SensitiveOperationType = "create_user"
	SensitiveOpDeleteUser   SensitiveOperationType = "delete_user"
	SensitiveOpModifyUser   SensitiveOperationType = "modify_user"

	// System configuration operations
	SensitiveOpModifyConfig     SensitiveOperationType = "modify_config"
	SensitiveOpDisableSecurity  SensitiveOperationType = "disable_security"
	SensitiveOpViewAuditLogs    SensitiveOperationType = "view_audit_logs"
	SensitiveOpModifyAuditLogs  SensitiveOperationType = "modify_audit_logs"

	// Data operations
	SensitiveOpBulkDelete  SensitiveOperationType = "bulk_delete"
	SensitiveOpDataExport  SensitiveOperationType = "data_export"
)

// SensitiveOperationContext contains context for a sensitive operation
// M-AUTH-2: Required information for auditing sensitive admin operations
type SensitiveOperationContext struct {
	OperationType SensitiveOperationType
	SubjectID     string // User performing the operation
	TenantID      string
	ResourceID    string // Resource being operated on
	Justification string // Required justification for the operation
	Metadata      map[string]interface{} // Additional context
}

// ValidateSensitiveOperation validates that a sensitive operation has proper justification
// M-AUTH-2: Enforces justification requirement for sensitive operations
func ValidateSensitiveOperation(opCtx *SensitiveOperationContext) error {
	if opCtx == nil {
		return errors.New("operation context required for sensitive operations")
	}

	// M-AUTH-2: Justification is mandatory for all sensitive operations
	if opCtx.Justification == "" {
		return fmt.Errorf("%w: operation '%s' requires justification",
			ErrJustificationRequired, opCtx.OperationType)
	}

	// M-AUTH-2: Minimum justification length (prevent empty/trivial justifications)
	if len(opCtx.Justification) < 10 {
		return fmt.Errorf("justification too short (minimum 10 characters): operation '%s'",
			opCtx.OperationType)
	}

	// M-AUTH-2: Maximum justification length (prevent abuse)
	if len(opCtx.Justification) > 1000 {
		return fmt.Errorf("justification too long (maximum 1000 characters): operation '%s'",
			opCtx.OperationType)
	}

	return nil
}

// IsSensitiveOperation checks if an operation type is sensitive
func IsSensitiveOperation(opType SensitiveOperationType) bool {
	sensitiveOps := map[SensitiveOperationType]bool{
		SensitiveOpCreateRole:       true,
		SensitiveOpDeleteRole:       true,
		SensitiveOpModifyRole:       true,
		SensitiveOpAssignRole:       true,
		SensitiveOpRevokeRole:       true,
		SensitiveOpCreatePermission: true,
		SensitiveOpDeletePermission: true,
		SensitiveOpCreateUser:       true,
		SensitiveOpDeleteUser:       true,
		SensitiveOpModifyUser:       true,
		SensitiveOpModifyConfig:     true,
		SensitiveOpDisableSecurity:  true,
		SensitiveOpViewAuditLogs:    true,
		SensitiveOpModifyAuditLogs:  true,
		SensitiveOpBulkDelete:       true,
		SensitiveOpDataExport:       true,
	}

	return sensitiveOps[opType]
}

// AuditSensitiveOperation logs a sensitive operation with full context
// M-AUTH-2: Comprehensive audit logging for sensitive admin operations
func (m *Manager) AuditSensitiveOperation(ctx context.Context, opCtx *SensitiveOperationContext, result interfaces.AuditResult, operationErr error) {
	if m.auditManager == nil {
		return
	}

	// M-AUTH-2: Create detailed audit event for sensitive operation using existing audit helpers
	event := audit.UserManagementEvent(
		opCtx.TenantID,
		opCtx.SubjectID,
		opCtx.ResourceID,
		"sensitive_"+string(opCtx.OperationType),
	).
		Resource("sensitive_operation", opCtx.ResourceID, string(opCtx.OperationType)).
		Result(result).
		// M-AUTH-2: Include justification in audit trail
		Detail("justification", opCtx.Justification).
		Detail("operation_type", string(opCtx.OperationType)).
		// M-AUTH-2: Mark as sensitive operation
		Detail("security_classification", "sensitive_admin_operation").
		Severity(interfaces.AuditSeverityCritical)

	// M-AUTH-2: Include any additional metadata
	for key, value := range opCtx.Metadata {
		event = event.Detail(key, value)
	}

	// M-AUTH-2: Record error if operation failed
	if operationErr != nil {
		event = event.Error("SENSITIVE_OPERATION_FAILED", operationErr.Error())
	}

	// Record the audit event
	_ = m.auditManager.RecordEvent(ctx, event)
}

// GetSensitiveOperationJustification retrieves justification from context
// M-AUTH-2: Helper to extract justification from request context
func GetSensitiveOperationJustification(ctx context.Context) string {
	if justification, ok := ctx.Value("operation_justification").(string); ok {
		return justification
	}
	return ""
}

// WithSensitiveOperationJustification adds justification to context
// M-AUTH-2: Helper to add justification to request context
func WithSensitiveOperationJustification(ctx context.Context, justification string) context.Context {
	return context.WithValue(ctx, "operation_justification", justification)
}
