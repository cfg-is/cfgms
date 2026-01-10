// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
)

// TerminalPermissions defines all terminal-related permissions
var TerminalPermissions = []*common.Permission{
	{
		Id:           "terminal.session.create",
		Name:         "Create Terminal Session",
		Description:  "Create new terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"create"},
	},
	{
		Id:           "terminal.session.read",
		Name:         "Read Terminal Sessions",
		Description:  "View terminal session information and status",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.session.terminate",
		Name:         "Terminate Terminal Sessions",
		Description:  "Terminate active terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"delete"},
	},
	{
		Id:           "terminal.session.monitor",
		Name:         "Monitor Terminal Sessions",
		Description:  "Real-time monitoring of terminal sessions",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.recording.read",
		Name:         "Read Terminal Recordings",
		Description:  "Access terminal session recordings",
		ResourceType: "terminal",
		Actions:      []string{"read"},
	},
	{
		Id:           "terminal.admin",
		Name:         "Terminal Administration",
		Description:  "Full terminal system administration",
		ResourceType: "terminal",
		Actions:      []string{"create", "read", "update", "delete", "execute"},
	},
}

// CommandFilterRule represents a rule for filtering terminal commands
type CommandFilterRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Pattern     string            `json:"pattern"`   // Regex pattern to match
	Action      FilterAction      `json:"action"`    // Allow, block, or audit
	Severity    FilterSeverity    `json:"severity"`  // Risk level
	TenantID    string            `json:"tenant_id"` // Tenant scope
	DeviceID    string            `json:"device_id"` // Device scope (optional)
	GroupID     string            `json:"group_id"`  // Group scope (optional)
	Metadata    map[string]string `json:"metadata"`  // Additional rule metadata
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	compiledRx  *regexp.Regexp    // Compiled regex for performance
}

// FilterAction defines what action to take when a command matches a rule
type FilterAction string

const (
	FilterActionAllow FilterAction = "allow" // Allow command execution
	FilterActionBlock FilterAction = "block" // Block command execution
	FilterActionAudit FilterAction = "audit" // Allow but log for audit
)

// FilterSeverity defines the risk level of a command filter rule
type FilterSeverity string

const (
	FilterSeverityLow      FilterSeverity = "low"      // Informational
	FilterSeverityMedium   FilterSeverity = "medium"   // Moderate risk
	FilterSeverityHigh     FilterSeverity = "high"     // High risk
	FilterSeverityCritical FilterSeverity = "critical" // Critical security risk
)

// SessionSecurityContext contains security information for a terminal session
type SessionSecurityContext struct {
	SessionID       string              `json:"session_id"`
	UserID          string              `json:"user_id"`
	StewardID       string              `json:"steward_id"`
	TenantID        string              `json:"tenant_id"`
	Permissions     []string            `json:"permissions"`      // User's terminal permissions
	FilterRules     []CommandFilterRule `json:"filter_rules"`     // Applicable command filter rules
	AuditEnabled    bool                `json:"audit_enabled"`    // Whether session is being audited
	MonitoringLevel SecurityLevel       `json:"monitoring_level"` // Level of session monitoring
	CreatedAt       time.Time           `json:"created_at"`
	ExpiresAt       *time.Time          `json:"expires_at,omitempty"` // Optional session expiration
}

// SecurityLevel defines the level of security monitoring for a session
type SecurityLevel string

const (
	SecurityLevelNone     SecurityLevel = "none"     // No special monitoring
	SecurityLevelBasic    SecurityLevel = "basic"    // Basic command logging
	SecurityLevelEnhanced SecurityLevel = "enhanced" // Enhanced monitoring with real-time analysis
	SecurityLevelMaximum  SecurityLevel = "maximum"  // Maximum security with full recording and analysis
)

// CommandAuditEvent represents an audit event for a terminal command
type CommandAuditEvent struct {
	SessionID string            `json:"session_id"`
	UserID    string            `json:"user_id"`
	StewardID string            `json:"steward_id"`
	TenantID  string            `json:"tenant_id"`
	Command   string            `json:"command"`
	Action    FilterAction      `json:"action"`    // Action taken (allow/block/audit)
	RuleID    string            `json:"rule_id"`   // Filter rule that triggered
	Severity  FilterSeverity    `json:"severity"`  // Risk level
	Output    string            `json:"output"`    // Command output (if captured)
	ExitCode  int               `json:"exit_code"` // Command exit code
	Duration  time.Duration     `json:"duration"`  // Command execution time
	Metadata  map[string]string `json:"metadata"`  // Additional context
	Timestamp time.Time         `json:"timestamp"`
	IPAddress string            `json:"ip_address"` // Client IP address
	UserAgent string            `json:"user_agent"` // Client user agent
}

// SecurityValidator validates security requirements for terminal operations
type SecurityValidator struct {
	rbacManager  rbac.RBACManager
	filterRules  []CommandFilterRule
	auditEnabled bool
	defaultRules []CommandFilterRule
}

// NewSecurityValidator creates a new security validator with default rules
func NewSecurityValidator(rbacManager rbac.RBACManager) *SecurityValidator {
	validator := &SecurityValidator{
		rbacManager:  rbacManager,
		auditEnabled: true,
		defaultRules: getDefaultCommandFilterRules(),
	}

	// Compile regex patterns for performance
	for i := range validator.defaultRules {
		if rx, err := regexp.Compile(validator.defaultRules[i].Pattern); err == nil {
			validator.defaultRules[i].compiledRx = rx
		}
	}

	return validator
}

// ValidateSessionAccess validates if a user can create a terminal session to a specific steward
func (sv *SecurityValidator) ValidateSessionAccess(ctx context.Context, userID, stewardID, tenantID string) (*SessionSecurityContext, error) {
	// Check terminal session creation permission
	accessReq := &common.AccessRequest{
		SubjectId:    userID,
		PermissionId: "terminal.session.create",
		ResourceId:   stewardID,
		TenantId:     tenantID,
		Context: map[string]string{
			"resource_type": "steward",
			"steward_id":    stewardID,
		},
	}

	response, err := sv.rbacManager.CheckPermission(ctx, accessReq)
	if err != nil {
		return nil, fmt.Errorf("failed to check terminal access: %w", err)
	}

	if !response.Granted {
		return nil, fmt.Errorf("access denied: %s", response.Reason)
	}

	// Get user's terminal permissions
	permissions, err := sv.getUserTerminalPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Get applicable filter rules
	filterRules := sv.getApplicableFilterRules(tenantID, stewardID)

	// Determine monitoring level based on permissions and risk
	monitoringLevel := sv.determineMonitoringLevel(permissions, filterRules)

	securityContext := &SessionSecurityContext{
		UserID:          userID,
		StewardID:       stewardID,
		TenantID:        tenantID,
		Permissions:     permissions,
		FilterRules:     filterRules,
		AuditEnabled:    sv.auditEnabled,
		MonitoringLevel: monitoringLevel,
		CreatedAt:       time.Now(),
	}

	return securityContext, nil
}

// ValidateCommand validates a command against security rules
func (sv *SecurityValidator) ValidateCommand(ctx context.Context, securityContext *SessionSecurityContext, command string) (*CommandValidationResult, error) {
	result := &CommandValidationResult{
		Command:   command,
		Allowed:   true,
		Action:    FilterActionAllow,
		Timestamp: time.Now(),
	}

	// Apply command filter rules
	for _, rule := range securityContext.FilterRules {
		if rule.compiledRx != nil && rule.compiledRx.MatchString(command) {
			result.MatchedRules = append(result.MatchedRules, rule)

			// Take the most restrictive action
			if rule.Action == FilterActionBlock {
				result.Allowed = false
				result.Action = FilterActionBlock
				result.BlockReason = fmt.Sprintf("Command blocked by security rule: %s", rule.Name)
			} else if rule.Action == FilterActionAudit && result.Action == FilterActionAllow {
				result.Action = FilterActionAudit
				result.AuditReason = fmt.Sprintf("Command flagged for audit by rule: %s", rule.Name)
			}

			// Track highest severity
			if result.Severity == "" || isHigherSeverity(rule.Severity, result.Severity) {
				result.Severity = rule.Severity
			}
		}
	}

	// Generate audit event if needed
	if result.Action == FilterActionAudit || result.Action == FilterActionBlock {
		auditEvent := &CommandAuditEvent{
			SessionID: securityContext.SessionID,
			UserID:    securityContext.UserID,
			StewardID: securityContext.StewardID,
			TenantID:  securityContext.TenantID,
			Command:   command,
			Action:    result.Action,
			Severity:  result.Severity,
			Timestamp: time.Now(),
		}

		if len(result.MatchedRules) > 0 {
			auditEvent.RuleID = result.MatchedRules[0].ID
		}

		result.AuditEvent = auditEvent
	}

	return result, nil
}

// CommandValidationResult represents the result of command validation
type CommandValidationResult struct {
	Command      string              `json:"command"`
	Allowed      bool                `json:"allowed"`
	Action       FilterAction        `json:"action"`
	Severity     FilterSeverity      `json:"severity"`
	MatchedRules []CommandFilterRule `json:"matched_rules"`
	BlockReason  string              `json:"block_reason,omitempty"`
	AuditReason  string              `json:"audit_reason,omitempty"`
	AuditEvent   *CommandAuditEvent  `json:"audit_event,omitempty"`
	Timestamp    time.Time           `json:"timestamp"`
}

// getUserTerminalPermissions gets terminal-related permissions for a user
func (sv *SecurityValidator) getUserTerminalPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	permissions, err := sv.rbacManager.GetSubjectPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	var terminalPermissions []string
	for _, perm := range permissions {
		if perm.ResourceType == "terminal" {
			terminalPermissions = append(terminalPermissions, perm.Id)
		}
	}

	return terminalPermissions, nil
}

// getApplicableFilterRules gets command filter rules applicable to the session
func (sv *SecurityValidator) getApplicableFilterRules(tenantID, stewardID string) []CommandFilterRule {
	var applicableRules []CommandFilterRule

	// Add default system rules
	for _, rule := range sv.defaultRules {
		if rule.TenantID == "" || rule.TenantID == tenantID {
			if rule.DeviceID == "" || rule.DeviceID == stewardID {
				applicableRules = append(applicableRules, rule)
			}
		}
	}

	// Add tenant-specific rules (would be loaded from storage in real implementation)
	applicableRules = append(applicableRules, sv.filterRules...)

	return applicableRules
}

// determineMonitoringLevel determines the appropriate security monitoring level
func (sv *SecurityValidator) determineMonitoringLevel(permissions []string, filterRules []CommandFilterRule) SecurityLevel {
	// Check if user has admin permissions
	for _, perm := range permissions {
		if perm == "terminal.admin" || perm == "system.admin" {
			return SecurityLevelMaximum
		}
	}

	// Check if any critical rules apply
	for _, rule := range filterRules {
		if rule.Severity == FilterSeverityCritical {
			return SecurityLevelMaximum
		}
	}

	// Default to enhanced monitoring for terminal access
	return SecurityLevelEnhanced
}

// isHigherSeverity checks if severity1 is higher than severity2
func isHigherSeverity(severity1, severity2 FilterSeverity) bool {
	severityOrder := map[FilterSeverity]int{
		FilterSeverityLow:      1,
		FilterSeverityMedium:   2,
		FilterSeverityHigh:     3,
		FilterSeverityCritical: 4,
	}

	return severityOrder[severity1] > severityOrder[severity2]
}

// getDefaultCommandFilterRules returns default security rules for command filtering
func getDefaultCommandFilterRules() []CommandFilterRule {
	rules := []CommandFilterRule{
		{
			ID:          "block-rm-rf",
			Name:        "Block Destructive rm Commands",
			Description: "Block dangerous rm -rf commands that could cause data loss",
			Pattern:     `rm\s+.*-[^-]*r[^-]*f|rm\s+.*-[^-]*f[^-]*r`,
			Action:      FilterActionBlock,
			Severity:    FilterSeverityCritical,
		},
		{
			ID:          "block-format-commands",
			Name:        "Block Disk Format Commands",
			Description: "Block commands that format or wipe disk drives",
			Pattern:     `\b(format|mkfs|fdisk|parted|dd\s+if=/dev/zero)\b`,
			Action:      FilterActionBlock,
			Severity:    FilterSeverityCritical,
		},
		{
			ID:          "audit-sudo-commands",
			Name:        "Audit Sudo Commands",
			Description: "Log all sudo command usage for security audit",
			Pattern:     `^\s*sudo\b`,
			Action:      FilterActionAudit,
			Severity:    FilterSeverityHigh,
		},
		{
			ID:          "audit-system-config",
			Name:        "Audit System Configuration Changes",
			Description: "Log changes to critical system configuration files",
			Pattern:     `\b(vi|vim|nano|emacs|sed|awk)\s+.*(passwd|shadow|sudoers|hosts|resolv\.conf|fstab)\b`,
			Action:      FilterActionAudit,
			Severity:    FilterSeverityHigh,
		},
		{
			ID:          "block-network-tools",
			Name:        "Block Network Reconnaissance Tools",
			Description: "Block potentially malicious network scanning tools",
			Pattern:     `\b(nmap|masscan|zmap|nc|netcat|telnet)\s`,
			Action:      FilterActionBlock,
			Severity:    FilterSeverityHigh,
		},
		{
			ID:          "audit-ssh-commands",
			Name:        "Audit SSH and Remote Access",
			Description: "Log SSH and remote access command usage",
			Pattern:     `\b(ssh|scp|sftp|rsync)\s`,
			Action:      FilterActionAudit,
			Severity:    FilterSeverityMedium,
		},
		{
			ID:          "block-privilege-escalation",
			Name:        "Block Common Privilege Escalation",
			Description: "Block common privilege escalation techniques",
			Pattern:     `\b(chmod\s+[0-7]*[4-7][0-7][0-7]|chown\s+root|su\s+-)\b`,
			Action:      FilterActionBlock,
			Severity:    FilterSeverityHigh,
		},
	}

	// Compile regex patterns
	for i := range rules {
		if rx, err := regexp.Compile(rules[i].Pattern); err == nil {
			rules[i].compiledRx = rx
		}
		rules[i].CreatedAt = time.Now()
		rules[i].UpdatedAt = time.Now()
	}

	return rules
}
