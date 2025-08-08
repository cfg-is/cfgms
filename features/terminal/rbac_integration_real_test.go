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
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestTerminalRBACIntegrationReal tests terminal RBAC integration using real components
// This demonstrates the architecture without extensive mocking
func TestTerminalRBACIntegrationReal(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger("test")

	t.Run("RealRBACMemoryStore", func(t *testing.T) {
		// Use the real in-memory RBAC store instead of mocking
		store := memory.NewStore()
		
		// Initialize with basic permissions
		err := store.CreatePermission(ctx, &common.Permission{
			Id:          "terminal.session.create",
			Name:        "Create Terminal Session",
			Description: "Permission to create terminal sessions",
		})
		require.NoError(t, err)
		
		err = store.CreatePermission(ctx, &common.Permission{
			Id:          "terminal.execute",
			Name:        "Execute Commands",
			Description: "Permission to execute terminal commands",
		})
		require.NoError(t, err)

		// Create a test role with permissions
		err = store.CreateRole(ctx, &common.Role{
			Id:            "terminal-user",
			Name:          "Terminal User", 
			Description:   "Basic terminal access role",
			PermissionIds: []string{"terminal.session.create", "terminal.execute"},
			TenantId:      "test-tenant", // Set the tenant ID to match our test
		})
		require.NoError(t, err)

		// Create a test subject
		err = store.CreateSubject(ctx, &common.Subject{
			Id:          "test-user",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Test User",
			TenantId:    "test-tenant",
		})
		require.NoError(t, err)

		// Assign the role to the subject
		err = store.AssignRole(ctx, &common.RoleAssignment{
			Id:        "test-assignment",
			SubjectId: "test-user",
			RoleId:    "terminal-user", 
			TenantId:  "test-tenant",
		})
		require.NoError(t, err)
		
		// Test that we can retrieve the permissions
		permissions, err := store.GetRolePermissions(ctx, "terminal-user")
		require.NoError(t, err)
		assert.Len(t, permissions, 2)
		
		// Test that we can get subject roles
		roles, err := store.GetSubjectRoles(ctx, "test-user", "test-tenant")
		require.NoError(t, err)
		assert.Len(t, roles, 1)
		assert.Equal(t, "terminal-user", roles[0].Id)
	})

	t.Run("TerminalSessionWithRealComponents", func(t *testing.T) {
		// Test terminal session creation with real session management
		req := &SessionRequest{
			StewardID: "test-steward",
			UserID:    "test-user",
			Shell:     "bash",
			Cols:      80,
			Rows:      24,
		}

		session, err := NewSession(req, logger)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Validate real session properties
		assert.Equal(t, "test-user", session.UserID)
		assert.Equal(t, "test-steward", session.StewardID)
		assert.Equal(t, "bash", session.Shell)
		assert.True(t, session.IsActive())
		assert.False(t, session.IsClosed())

		// Test session metadata (resize would fail without actual shell)
		// In a real environment, session.Resize() would work, but in tests
		// we just verify the session was created correctly
		assert.Equal(t, 80, session.Cols)
		assert.Equal(t, 24, session.Rows)

		// Test session cleanup
		err = session.Close(ctx)
		require.NoError(t, err)
		assert.False(t, session.IsActive())
		assert.True(t, session.IsClosed())
	})

	t.Run("SecurityValidatorWithRealRules", func(t *testing.T) {
		// Test security validator directly without requiring full RBAC manager
		// Just test the command filtering logic which doesn't require RBAC
		filterRules := getDefaultCommandFilterRules()
		require.NotEmpty(t, filterRules)

		// Test command filtering logic directly using filter rules

		// Test command validation logic using filter rules
		dangerousCommand := "rm -rf /"
		foundBlockRule := false
		for _, rule := range filterRules {
			if rule.Action == FilterActionBlock {
				matched, _ := regexp.MatchString(rule.Pattern, dangerousCommand)
				if matched {
					foundBlockRule = true
					assert.Equal(t, FilterSeverityCritical, rule.Severity)
					break
				}
			}
		}
		assert.True(t, foundBlockRule, "Should find blocking rule for dangerous command")

		// Test safe command - ensure it doesn't match blocking rules
		safeCommand := "ls -la"
		foundBlockingMatch := false
		for _, rule := range filterRules {
			if rule.Action == FilterActionBlock {
				matched, _ := regexp.MatchString(rule.Pattern, safeCommand)
				if matched {
					foundBlockingMatch = true
					break
				}
			}
		}
		assert.False(t, foundBlockingMatch, "Safe command should not match block rules")
	})

	t.Run("ContinuousAuthRegistryReal", func(t *testing.T) {
		// Test real session registry without full continuous auth engine
		registry := continuous.NewSessionRegistry()
		require.NotNil(t, registry)

		err := registry.Start(ctx)
		require.NoError(t, err)

		// Register a real session
		metadata := map[string]string{
			"session_type":             "terminal",
			"requires_continuous_auth": "true",
			"privilege_level":          "high",
		}

		err = registry.RegisterSession(ctx, "test-session", "test-user", "test-tenant", metadata)
		require.NoError(t, err)

		// Validate session
		valid, err := registry.ValidateSession(ctx, "test-session", "test-user")
		require.NoError(t, err)
		assert.True(t, valid)

		// Test session status
		status, err := registry.GetSessionStatus(ctx, "test-session")
		require.NoError(t, err)
		assert.Equal(t, "test-session", status.SessionID)
		assert.Equal(t, "active", status.Status)
		assert.True(t, status.IsValid)
		assert.True(t, status.RequiresReauth)

		// Test session cleanup
		err = registry.UnregisterSession(ctx, "test-session")
		require.NoError(t, err)

		// Should now be invalid
		valid, err = registry.ValidateSession(ctx, "test-session", "test-user")
		require.Error(t, err) // Should error because session not found
		assert.False(t, valid)

		err = registry.Stop()
		require.NoError(t, err)
	})

	t.Run("PerformanceValidationReal", func(t *testing.T) {
		// Test real performance with actual components (not mocked)
		filterRules := getDefaultCommandFilterRules()
		require.NotEmpty(t, filterRules)

		// Measure real command validation performance using direct rule evaluation
		command := "sudo systemctl restart apache2"
		iterations := 1000

		start := time.Now()
		for i := 0; i < iterations; i++ {
			// Test direct rule evaluation performance without full validator
			found := false
			for _, rule := range filterRules {
				matched, err := regexp.MatchString(rule.Pattern, command)
				require.NoError(t, err)
				if matched {
					found = true
					break
				}
			}
			_ = found // Use the result
		}
		duration := time.Since(start)

		avgLatency := duration / time.Duration(iterations)
		t.Logf("Real command rule evaluation average latency: %v", avgLatency)
		
		// Verify performance requirement (should be much faster than 5ms)
		assert.Less(t, avgLatency.Milliseconds(), int64(5), 
			"Real command rule evaluation should be under 5ms, got %v", avgLatency)
	})
}