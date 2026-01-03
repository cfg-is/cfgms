// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package terminal

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"github.com/cfgis/cfgms/features/rbac/memory"
	"github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestTerminalRBACComprehensiveIntegration tests the complete terminal RBAC integration
// using real system components with minimal mocking - addresses Story #128
func TestTerminalRBACComprehensiveIntegration(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger("test")

	// Setup real RBAC system with memory store
	rbacStore := memory.NewStore()
	require.NoError(t, rbacStore.Initialize(ctx))

	// Setup real continuous auth registry
	authRegistry := continuous.NewSessionRegistry()
	require.NoError(t, authRegistry.Start(ctx))
	defer func() { _ = authRegistry.Stop() }() // Ignore error in test cleanup

	t.Run("EndToEndRBACFlowWithRealComponents", func(t *testing.T) {
		// 1. Setup real permissions in memory store
		terminalPermissions := []*common.Permission{
			{
				Id:           "terminal.session.create",
				Name:         "Create Terminal Session",
				Description:  "Permission to create terminal sessions",
				ResourceType: "terminal",
			},
			{
				Id:           "terminal.execute",
				Name:         "Execute Commands",
				Description:  "Permission to execute terminal commands",
				ResourceType: "terminal",
			},
			{
				Id:           "terminal.admin",
				Name:         "Terminal Admin",
				Description:  "Administrative terminal permissions",
				ResourceType: "terminal",
			},
		}

		for _, perm := range terminalPermissions {
			err := rbacStore.CreatePermission(ctx, perm)
			require.NoError(t, err)
		}

		// 2. Create real roles with different permission levels
		basicRole := &common.Role{
			Id:            "terminal-basic",
			Name:          "Basic Terminal User",
			Description:   "Basic terminal access",
			PermissionIds: []string{"terminal.session.create"},
			TenantId:      "test-tenant",
		}

		powerRole := &common.Role{
			Id:            "terminal-power",
			Name:          "Power Terminal User",
			Description:   "Full terminal access",
			PermissionIds: []string{"terminal.session.create", "terminal.execute"},
			TenantId:      "test-tenant",
		}

		adminRole := &common.Role{
			Id:            "terminal-admin",
			Name:          "Terminal Administrator",
			Description:   "Administrative terminal access",
			PermissionIds: []string{"terminal.session.create", "terminal.execute", "terminal.admin"},
			TenantId:      "test-tenant",
		}

		for _, role := range []*common.Role{basicRole, powerRole, adminRole} {
			err := rbacStore.CreateRole(ctx, role)
			require.NoError(t, err)
		}

		// 3. Create real test subjects
		testUsers := []*common.Subject{
			{
				Id:          "basic-user",
				Type:        common.SubjectType_SUBJECT_TYPE_USER,
				DisplayName: "Basic User",
				TenantId:    "test-tenant",
				IsActive:    true,
			},
			{
				Id:          "power-user",
				Type:        common.SubjectType_SUBJECT_TYPE_USER,
				DisplayName: "Power User",
				TenantId:    "test-tenant",
				IsActive:    true,
			},
			{
				Id:          "admin-user",
				Type:        common.SubjectType_SUBJECT_TYPE_USER,
				DisplayName: "Admin User",
				TenantId:    "test-tenant",
				IsActive:    true,
			},
		}

		for _, user := range testUsers {
			err := rbacStore.CreateSubject(ctx, user)
			require.NoError(t, err)
		}

		// 4. Assign roles using real role assignment store
		assignments := []*common.RoleAssignment{
			{
				Id:        "assignment-basic",
				SubjectId: "basic-user",
				RoleId:    "terminal-basic",
				TenantId:  "test-tenant",
			},
			{
				Id:        "assignment-power",
				SubjectId: "power-user",
				RoleId:    "terminal-power",
				TenantId:  "test-tenant",
			},
			{
				Id:        "assignment-admin",
				SubjectId: "admin-user",
				RoleId:    "terminal-admin",
				TenantId:  "test-tenant",
			},
		}

		for _, assignment := range assignments {
			err := rbacStore.AssignRole(ctx, assignment)
			require.NoError(t, err)
		}

		// 5. Test real permission resolution through RBAC store
		t.Run("VerifyPermissionResolution", func(t *testing.T) {
			// Basic user should only have session creation
			basicPerms, err := rbacStore.GetRolePermissions(ctx, "terminal-basic")
			require.NoError(t, err)
			assert.Len(t, basicPerms, 1)
			assert.Equal(t, "terminal.session.create", basicPerms[0].Id)

			// Power user should have session + execute
			powerPerms, err := rbacStore.GetRolePermissions(ctx, "terminal-power")
			require.NoError(t, err)
			assert.Len(t, powerPerms, 2)

			// Admin user should have all permissions
			adminPerms, err := rbacStore.GetRolePermissions(ctx, "terminal-admin")
			require.NoError(t, err)
			assert.Len(t, adminPerms, 3)
		})

		// 6. Test real terminal session creation with actual session objects
		t.Run("VerifyTerminalSessionCreation", func(t *testing.T) {
			sessions := make([]*Session, 0, 3)
			defaultShell := shell.GetDefaultShell()

			for _, userID := range []string{"basic-user", "power-user", "admin-user"} {
				req := &SessionRequest{
					StewardID: "test-steward",
					UserID:    userID,
					Shell:     defaultShell,
					Cols:      80,
					Rows:      24,
				}

				session, err := NewSession(req, logger)
				require.NoError(t, err)
				require.NotNil(t, session)

				// Verify session properties
				assert.Equal(t, userID, session.UserID)
				assert.Equal(t, "test-steward", session.StewardID)
				assert.Equal(t, defaultShell, session.Shell)
				assert.True(t, session.IsActive())
				assert.False(t, session.IsClosed())

				sessions = append(sessions, session)

				// Register with real continuous auth system
				metadata := map[string]string{
					"session_type":             "terminal",
					"requires_continuous_auth": "true",
					"user_role":                getUserRole(userID),
				}

				err = authRegistry.RegisterSession(ctx, session.ID, userID, "test-tenant", metadata)
				require.NoError(t, err)

				// Verify session is registered
				valid, err := authRegistry.ValidateSession(ctx, session.ID, userID)
				require.NoError(t, err)
				assert.True(t, valid)
			}

			// Clean up sessions
			for _, session := range sessions {
				err := session.Close(ctx)
				require.NoError(t, err)
				assert.False(t, session.IsActive())
				assert.True(t, session.IsClosed())

				err = authRegistry.UnregisterSession(ctx, session.ID)
				require.NoError(t, err)
			}
		})

		// 7. Test real command security validation with actual filter rules
		t.Run("VerifyCommandSecurityValidation", func(t *testing.T) {
			filterRules := getDefaultCommandFilterRules()
			require.NotEmpty(t, filterRules)

			// Test real dangerous command detection with commands that match existing rules
			dangerousCommands := []string{
				"rm -rf /",                    // Matches: block-rm-rf
				"format c:",                   // Matches: block-format-commands
				"dd if=/dev/zero of=/dev/sda", // Matches: block-format-commands
				"nmap -sS 192.168.1.0/24",     // Matches: block-network-tools
				"chmod 777 /etc/passwd",       // Matches: block-privilege-escalation
			}

			for _, cmd := range dangerousCommands {
				blocked := false
				for _, rule := range filterRules {
					if rule.Action == FilterActionBlock {
						// Use real regex matching
						matched, err := regexp.MatchString(rule.Pattern, cmd)
						require.NoError(t, err, "Regex pattern should be valid")
						if matched {
							blocked = true
							// Verify it has high or critical severity (both indicate serious security risk)
							assert.Contains(t, []FilterSeverity{FilterSeverityHigh, FilterSeverityCritical}, rule.Severity, "Dangerous command should have high or critical severity")
							t.Logf("Command '%s' blocked by rule: %s (severity: %s, pattern: %s)", cmd, rule.Name, rule.Severity, rule.Pattern)
							break
						}
					}
				}
				assert.True(t, blocked, "Command '%s' should be blocked by security rules", cmd)
			}

			// Test real safe command allowance
			safeCommands := []string{
				"ls -la",
				"pwd",
				"whoami",
				"ps aux",
				"df -h",
			}

			for _, cmd := range safeCommands {
				blocked := false
				for _, rule := range filterRules {
					if rule.Action == FilterActionBlock {
						// Use real regex matching
						matched, err := regexp.MatchString(rule.Pattern, cmd)
						require.NoError(t, err, "Regex pattern should be valid")
						if matched {
							blocked = true
							break
						}
					}
				}
				assert.False(t, blocked, "Safe command '%s' should not be blocked", cmd)
			}
		})

		// 8. Test real session termination scenarios
		t.Run("VerifySessionTermination", func(t *testing.T) {
			// Create test session
			req := &SessionRequest{
				StewardID: "test-steward",
				UserID:    "power-user",
				Shell:     shell.GetDefaultShell(),
				Cols:      80,
				Rows:      24,
			}

			session, err := NewSession(req, logger)
			require.NoError(t, err)

			// Register with continuous auth
			metadata := map[string]string{
				"session_type":             "terminal",
				"requires_continuous_auth": "true",
			}
			err = authRegistry.RegisterSession(ctx, session.ID, "power-user", "test-tenant", metadata)
			require.NoError(t, err)

			// Verify session is active
			status, err := authRegistry.GetSessionStatus(ctx, session.ID)
			require.NoError(t, err)
			assert.Equal(t, "active", status.Status)
			assert.True(t, status.IsValid)

			// Test termination
			err = authRegistry.UnregisterSession(ctx, session.ID)
			require.NoError(t, err)

			// Verify session is terminated
			_, err = authRegistry.GetSessionStatus(ctx, session.ID)
			assert.Error(t, err) // Should error because session no longer exists

			// Clean up
			err = session.Close(ctx)
			require.NoError(t, err)
		})

		// 9. Test performance with real components
		t.Run("VerifyRealSystemPerformance", func(t *testing.T) {
			iterations := 1000

			// Test RBAC permission lookup performance
			start := time.Now()
			for i := 0; i < iterations; i++ {
				_, err := rbacStore.GetRolePermissions(ctx, "terminal-power")
				require.NoError(t, err)
			}
			rbacLatency := time.Since(start) / time.Duration(iterations)

			// Test session registry performance
			start = time.Now()
			for i := 0; i < iterations; i++ {
				_, err := authRegistry.ValidateSession(ctx, "non-existent-session", "test-user")
				// Error expected, just measuring performance
				_ = err
			}
			sessionLatency := time.Since(start) / time.Duration(iterations)

			// Test command filter performance
			filterRules := getDefaultCommandFilterRules()
			testCommand := "sudo systemctl restart nginx"
			start = time.Now()
			for i := 0; i < iterations; i++ {
				for _, rule := range filterRules {
					_, _ = regexp.MatchString(rule.Pattern, testCommand)
				}
			}
			filterLatency := time.Since(start) / time.Duration(iterations)

			t.Logf("Performance Results:")
			t.Logf("  RBAC permission lookup: %v", rbacLatency)
			t.Logf("  Session validation: %v", sessionLatency)
			t.Logf("  Command filtering: %v", filterLatency)

			// All operations should be well under 5ms requirement
			assert.Less(t, rbacLatency.Milliseconds(), int64(5), "RBAC lookup should be under 5ms")
			assert.Less(t, sessionLatency.Milliseconds(), int64(5), "Session validation should be under 5ms")
			assert.Less(t, filterLatency.Milliseconds(), int64(5), "Command filtering should be under 5ms")
		})
	})
}

// Helper functions
func getUserRole(userID string) string {
	switch userID {
	case "basic-user":
		return "terminal-basic"
	case "power-user":
		return "terminal-power"
	case "admin-user":
		return "terminal-admin"
	default:
		return "unknown"
	}
}
