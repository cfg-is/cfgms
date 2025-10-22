package zerotrust

import (
	"time"
)

// PolicyLifecycleManager implementation is in policy_lifecycle.go

// ComplianceMonitor implementation is in compliance_monitor.go

// ContextStatus represents the current context status
type ContextStatus struct {
	Valid          bool      `json:"valid"`
	LastValidated  time.Time `json:"last_validated"`
	ChangeDetected bool      `json:"change_detected"`
}

// Additional missing types referenced in the main engine

// RequirementType is defined in types.go
