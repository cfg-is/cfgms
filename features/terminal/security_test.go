// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/terminal"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestSecurityValidator_ValidateSessionAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("Valid terminal access", func(t *testing.T) {
		manager := pkgtesting.SetupTestRBACManager(t)
		// M-AUTH-2: sensitive RBAC operations require justification in context
		ctxJ := rbac.WithSensitiveOperationJustification(ctx, "test: terminal security validator setup")

		// terminal.session.create and terminal.session.read are pre-loaded by
		// manager.Initialize via DefaultPermissions — no need to create them here.
		require.NoError(t, manager.CreateRole(ctxJ, &common.Role{
			Id:            "terminal-user",
			Name:          "Terminal User",
			TenantId:      "tenant789",
			PermissionIds: []string{"terminal.session.create", "terminal.session.read"},
		}))
		require.NoError(t, manager.CreateSubject(ctxJ, &common.Subject{
			Id:          "user123",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User",
			TenantId:    "tenant789",
			IsActive:    true,
		}))
		require.NoError(t, manager.AssignRole(ctxJ, &common.RoleAssignment{
			SubjectId: "user123",
			RoleId:    "terminal-user",
			TenantId:  "tenant789",
		}))

		validator := terminal.NewSecurityValidator(manager)
		securityContext, err := validator.ValidateSessionAccess(ctx, "user123", "steward456", "tenant789")

		assert.NoError(t, err)
		require.NotNil(t, securityContext)
		assert.Equal(t, "user123", securityContext.UserID)
		assert.Equal(t, "steward456", securityContext.StewardID)
		assert.Equal(t, "tenant789", securityContext.TenantID)
	})

	t.Run("Access denied - no permission", func(t *testing.T) {
		manager := pkgtesting.SetupTestRBACManager(t)

		require.NoError(t, manager.CreateSubject(ctx, &common.Subject{
			Id:          "user123",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User",
			TenantId:    "tenant789",
			IsActive:    true,
		}))

		validator := terminal.NewSecurityValidator(manager)
		securityContext, err := validator.ValidateSessionAccess(ctx, "user123", "steward456", "tenant789")

		assert.Error(t, err)
		assert.Nil(t, securityContext)
	})
}

func TestSecurityValidator_ValidateCommand(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		expectedAllowed  bool
		expectedAction   terminal.FilterAction
		expectedSeverity terminal.FilterSeverity
	}{
		{
			name:             "Safe command - ls",
			command:          "ls -la",
			expectedAllowed:  true,
			expectedAction:   terminal.FilterActionAllow,
			expectedSeverity: "",
		},
		{
			name:             "Dangerous command - rm -rf",
			command:          "rm -rf /",
			expectedAllowed:  false,
			expectedAction:   terminal.FilterActionBlock,
			expectedSeverity: terminal.FilterSeverityCritical,
		},
		{
			name:             "Audit command - sudo",
			command:          "sudo systemctl restart nginx",
			expectedAllowed:  true,
			expectedAction:   terminal.FilterActionAudit,
			expectedSeverity: terminal.FilterSeverityHigh,
		},
		{
			name:             "Network scanning command",
			command:          "nmap -sS 192.168.1.0/24",
			expectedAllowed:  false,
			expectedAction:   terminal.FilterActionBlock,
			expectedSeverity: terminal.FilterSeverityHigh,
		},
		{
			name:             "System configuration edit",
			command:          "vi /etc/passwd",
			expectedAllowed:  true,
			expectedAction:   terminal.FilterActionAudit,
			expectedSeverity: terminal.FilterSeverityHigh,
		},
	}

	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)
	ctx := context.Background()

	securityContext := &terminal.SessionSecurityContext{
		SessionID:    "test-session",
		UserID:       "test-user",
		StewardID:    "test-steward",
		TenantID:     "test-tenant",
		FilterRules:  terminal.GetApplicableFilterRules(validator, "test-tenant", "test-steward"),
		AuditEnabled: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateCommand(ctx, securityContext, tt.command)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.command, result.Command)
			assert.Equal(t, tt.expectedAllowed, result.Allowed)
			assert.Equal(t, tt.expectedAction, result.Action)

			if tt.expectedSeverity != "" {
				assert.Equal(t, tt.expectedSeverity, result.Severity)
			}

			if result.Action == terminal.FilterActionBlock || result.Action == terminal.FilterActionAudit {
				assert.NotNil(t, result.AuditEvent)
				assert.Equal(t, tt.command, result.AuditEvent.Command)
				assert.Equal(t, tt.expectedAction, result.AuditEvent.Action)
			}
		})
	}
}

func TestCommandFilterRules(t *testing.T) {
	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)
	ctx := context.Background()

	filterRules := terminal.GetApplicableFilterRules(validator, "test-tenant", "test-steward")
	secCtx := &terminal.SessionSecurityContext{
		SessionID:   "test-session",
		UserID:      "test-user",
		StewardID:   "test-steward",
		TenantID:    "test-tenant",
		FilterRules: filterRules,
	}

	tests := []struct {
		name           string
		command        string
		expectedAction terminal.FilterAction
	}{
		{
			name:           "rm -rf command",
			command:        "rm -rf /tmp/test",
			expectedAction: terminal.FilterActionBlock,
		},
		{
			name:           "format command",
			command:        "format c:",
			expectedAction: terminal.FilterActionBlock,
		},
		{
			name:           "sudo command",
			command:        "sudo apt update",
			expectedAction: terminal.FilterActionAudit,
		},
		{
			name:           "safe command",
			command:        "echo hello world",
			expectedAction: terminal.FilterActionAllow,
		},
		{
			name:           "nmap command",
			command:        "nmap -sS target.com",
			expectedAction: terminal.FilterActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateCommand(ctx, secCtx, tt.command)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAction, result.Action)
		})
	}
}

func TestSessionMonitor_ThreatLevelCalculation(t *testing.T) {
	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)

	// AutoTerminateOnCritical disabled to prevent session termination during the test.
	config := terminal.DefaultMonitorConfig()
	config.AutoTerminateOnCritical = false
	monitor := terminal.NewSessionMonitor(validator, config)

	ctx := context.Background()
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}
	defer func() {
		if err := monitor.Stop(); err != nil {
			t.Logf("Failed to stop monitor: %v", err)
		}
	}()

	session := &terminal.Session{
		ID:        "test-session",
		UserID:    "test-user",
		StewardID: "test-steward",
		CreatedAt: time.Now(),
	}

	securityContext := &terminal.SessionSecurityContext{
		SessionID: session.ID,
		UserID:    session.UserID,
		StewardID: session.StewardID,
		TenantID:  "test-tenant",
	}

	err := monitor.AddSession(session, securityContext)
	require.NoError(t, err)

	t.Run("Low threat level - normal activity", func(t *testing.T) {
		sessionInfo, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)
		assert.Equal(t, terminal.ThreatLevelLow, sessionInfo.ThreatLevel)
	})

	t.Run("Medium threat level - some alerts", func(t *testing.T) {
		// Get a working copy of the session from the monitor.
		sessionCopy, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)

		// Generate 3 alerts on the copy (AlertCount > 2 → Medium).
		terminal.GenerateAlert(monitor, sessionCopy, "test_alert", terminal.FilterSeverityMedium, "Test alert")
		terminal.GenerateAlert(monitor, sessionCopy, "test_alert", terminal.FilterSeverityMedium, "Test alert")
		terminal.GenerateAlert(monitor, sessionCopy, "test_alert", terminal.FilterSeverityMedium, "Test alert")

		terminal.UpdateThreatLevel(monitor, sessionCopy)

		assert.Equal(t, terminal.ThreatLevelMedium, sessionCopy.ThreatLevel)
	})

	t.Run("High threat level - many alerts", func(t *testing.T) {
		// Get a fresh copy; add enough alerts to reach High (AlertCount > 5).
		sessionCopy, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)

		for i := 0; i < 6; i++ {
			terminal.GenerateAlert(monitor, sessionCopy, "test_alert", terminal.FilterSeverityMedium, "Test alert")
		}

		terminal.UpdateThreatLevel(monitor, sessionCopy)

		assert.Equal(t, terminal.ThreatLevelHigh, sessionCopy.ThreatLevel)
	})

	t.Run("Critical threat level - blocked commands", func(t *testing.T) {
		// Get a fresh copy and set BlockedCommands directly (BlockedCommands > 3 → Critical).
		sessionCopy, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)

		sessionCopy.BlockedCommands = 5
		terminal.UpdateThreatLevel(monitor, sessionCopy)

		assert.Equal(t, terminal.ThreatLevelCritical, sessionCopy.ThreatLevel)
	})
}

func TestCommandInterceptor_InputFiltering(t *testing.T) {
	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)

	securityContext := &terminal.SessionSecurityContext{
		SessionID:   "test-session",
		UserID:      "test-user",
		StewardID:   "test-steward",
		TenantID:    "test-tenant",
		FilterRules: terminal.GetApplicableFilterRules(validator, "test-tenant", "test-steward"),
	}

	auditChan := make(chan *terminal.CommandAuditEvent, 10)
	interceptor := terminal.NewCommandInterceptor(validator, securityContext, auditChan)

	ctx := context.Background()

	tests := []struct {
		name           string
		input          string
		expectedOutput bool
		expectBlocked  bool
	}{
		{
			name:           "Safe command",
			input:          "ls -la\n",
			expectedOutput: true,
			expectBlocked:  false,
		},
		{
			name:           "Dangerous command",
			input:          "rm -rf /\n",
			expectedOutput: false,
			expectBlocked:  true,
		},
		{
			name:           "Partial command input",
			input:          "echo hello",
			expectedOutput: true,
			expectBlocked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := interceptor.InterceptInput(ctx, []byte(tt.input))
			assert.NoError(t, err)

			if tt.expectedOutput {
				assert.NotEmpty(t, output)
			}

			if tt.expectBlocked {
				select {
				case event := <-auditChan:
					assert.Equal(t, terminal.FilterActionBlock, event.Action)
				case <-time.After(100 * time.Millisecond):
					// No event received, which might be expected for partial inputs
				}
			}
		})
	}
}

func TestDefaultCommandFilterRules(t *testing.T) {
	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)
	ctx := context.Background()

	filterRules := terminal.GetApplicableFilterRules(validator, "test-tenant", "test-steward")
	secCtx := &terminal.SessionSecurityContext{
		SessionID:   "test-session",
		UserID:      "test-user",
		StewardID:   "test-steward",
		TenantID:    "test-tenant",
		FilterRules: filterRules,
	}

	// Verify that default filter rules are non-empty (compiled and loaded correctly).
	assert.NotEmpty(t, filterRules, "Default filter rules should be present")

	// Test that dangerous patterns are caught by the compiled rules.
	dangerousCommands := []string{
		"rm -rf /",
		"format c:",
		"sudo rm -rf /home",
		"nmap -sS 192.168.1.1",
		"chmod 777 /etc/passwd",
	}

	for _, cmd := range dangerousCommands {
		t.Run(fmt.Sprintf("Dangerous command: %s", cmd), func(t *testing.T) {
			result, err := validator.ValidateCommand(ctx, secCtx, cmd)
			require.NoError(t, err)
			assert.Contains(t, []terminal.FilterAction{terminal.FilterActionBlock, terminal.FilterActionAudit}, result.Action,
				"Dangerous command should be blocked or audited")
		})
	}
}

func BenchmarkCommandValidation(b *testing.B) {
	// ValidateCommand does not use the rbacManager; nil is safe here.
	validator := terminal.NewSecurityValidator(nil)
	ctx := context.Background()

	securityContext := &terminal.SessionSecurityContext{
		SessionID:   "bench-session",
		UserID:      "bench-user",
		StewardID:   "bench-steward",
		TenantID:    "bench-tenant",
		FilterRules: terminal.GetApplicableFilterRules(validator, "bench-tenant", "bench-steward"),
	}

	testCommands := []string{
		"ls -la",
		"cd /tmp",
		"cat /etc/passwd",
		"sudo systemctl status nginx",
		"rm -rf /tmp/test",
		"echo 'hello world'",
		"ps aux",
		"netstat -tulpn",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		command := testCommands[i%len(testCommands)]
		_, err := validator.ValidateCommand(ctx, securityContext, command)
		if err != nil {
			b.Fatal(err)
		}
	}
}
