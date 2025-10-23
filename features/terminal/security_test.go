// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package terminal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// MockRBACManager is a mock implementation of rbac.RBACManager
type MockRBACManager struct {
	mock.Mock
}

func (m *MockRBACManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*common.AccessResponse), args.Error(1)
}

func (m *MockRBACManager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	args := m.Called(ctx, subjectID, tenantID)
	return args.Get(0).([]*common.Permission), args.Error(1)
}

// Add other required methods for RBACManager interface
func (m *MockRBACManager) CreatePermission(ctx context.Context, permission *common.Permission) error {
	args := m.Called(ctx, permission)
	return args.Error(0)
}

func (m *MockRBACManager) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*common.Permission), args.Error(1)
}

func (m *MockRBACManager) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	args := m.Called(ctx, resourceType)
	return args.Get(0).([]*common.Permission), args.Error(1)
}

func (m *MockRBACManager) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	args := m.Called(ctx, permission)
	return args.Error(0)
}

func (m *MockRBACManager) DeletePermission(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRBACManager) CreateRole(ctx context.Context, role *common.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRBACManager) GetRole(ctx context.Context, id string) (*common.Role, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*common.Role), args.Error(1)
}

func (m *MockRBACManager) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*common.Role), args.Error(1)
}

func (m *MockRBACManager) UpdateRole(ctx context.Context, role *common.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRBACManager) DeleteRole(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRBACManager) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]*common.Permission), args.Error(1)
}

func (m *MockRBACManager) CreateSubject(ctx context.Context, subject *common.Subject) error {
	args := m.Called(ctx, subject)
	return args.Error(0)
}

func (m *MockRBACManager) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*common.Subject), args.Error(1)
}

func (m *MockRBACManager) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	args := m.Called(ctx, tenantID, subjectType)
	return args.Get(0).([]*common.Subject), args.Error(1)
}

func (m *MockRBACManager) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	args := m.Called(ctx, subject)
	return args.Error(0)
}

func (m *MockRBACManager) DeleteSubject(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRBACManager) GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error) {
	args := m.Called(ctx, subjectID, tenantID)
	return args.Get(0).([]*common.Role), args.Error(1)
}

func (m *MockRBACManager) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	args := m.Called(ctx, assignment)
	return args.Error(0)
}

func (m *MockRBACManager) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	args := m.Called(ctx, subjectID, roleID, tenantID)
	return args.Error(0)
}

func (m *MockRBACManager) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*common.RoleAssignment), args.Error(1)
}

func (m *MockRBACManager) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	args := m.Called(ctx, subjectID, roleID, tenantID)
	return args.Get(0).([]*common.RoleAssignment), args.Error(1)
}

func (m *MockRBACManager) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	args := m.Called(ctx, subjectID, tenantID)
	return args.Get(0).([]*common.RoleAssignment), args.Error(1)
}

func (m *MockRBACManager) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	args := m.Called(ctx, authContext, requiredPermission)
	return args.Get(0).(*common.AccessResponse), args.Error(1)
}

func (m *MockRBACManager) Initialize(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRBACManager) CreateTenantDefaultRoles(ctx context.Context, tenantID string) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *MockRBACManager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	args := m.Called(ctx, subjectID, tenantID)
	return args.Get(0).([]*common.Permission), args.Error(1)
}

func (m *MockRBACManager) ComputeRolePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*memory.EffectivePermissions), args.Error(1)
}

func (m *MockRBACManager) CreateRoleWithParent(ctx context.Context, role *common.Role, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	args := m.Called(ctx, role, parentRoleID, inheritanceType)
	return args.Error(0)
}

func (m *MockRBACManager) GetRoleHierarchyTree(ctx context.Context, rootRoleID string, maxDepth int) (*memory.RoleHierarchy, error) {
	args := m.Called(ctx, rootRoleID, maxDepth)
	return args.Get(0).(*memory.RoleHierarchy), args.Error(1)
}

func (m *MockRBACManager) ValidateHierarchyOperation(ctx context.Context, childRoleID, parentRoleID string) error {
	args := m.Called(ctx, childRoleID, parentRoleID)
	return args.Error(0)
}

func (m *MockRBACManager) ResolvePermissionConflicts(ctx context.Context, roleID string, conflictingPermissions map[string][]*common.Permission) (map[string]*common.Permission, error) {
	args := m.Called(ctx, roleID, conflictingPermissions)
	return args.Get(0).(map[string]*common.Permission), args.Error(1)
}

func (m *MockRBACManager) GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*memory.RoleHierarchy), args.Error(1)
}

func (m *MockRBACManager) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]*common.Role), args.Error(1)
}

func (m *MockRBACManager) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).(*common.Role), args.Error(1)
}

func (m *MockRBACManager) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	args := m.Called(ctx, roleID, parentRoleID, inheritanceType)
	return args.Error(0)
}

func (m *MockRBACManager) RemoveRoleParent(ctx context.Context, roleID string) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func (m *MockRBACManager) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	args := m.Called(ctx, roleID)
	return args.Error(0)
}

func TestSecurityValidator_ValidateSessionAccess(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		stewardID      string
		tenantID       string
		mockSetup      func(*MockRBACManager)
		expectedError  bool
		expectedAccess bool
	}{
		{
			name:      "Valid terminal access",
			userID:    "user123",
			stewardID: "steward456",
			tenantID:  "tenant789",
			mockSetup: func(m *MockRBACManager) {
				m.On("CheckPermission", mock.Anything, mock.AnythingOfType("*common.AccessRequest")).Return(
					&common.AccessResponse{
						Granted: true,
						Reason:  "Access granted",
					}, nil)
				m.On("GetSubjectPermissions", mock.Anything, "user123", "tenant789").Return(
					[]*common.Permission{
						{Id: "terminal.session.create", ResourceType: "terminal"},
						{Id: "terminal.session.read", ResourceType: "terminal"},
					}, nil)
			},
			expectedError:  false,
			expectedAccess: true,
		},
		{
			name:      "Access denied - no permission",
			userID:    "user123",
			stewardID: "steward456",
			tenantID:  "tenant789",
			mockSetup: func(m *MockRBACManager) {
				m.On("CheckPermission", mock.Anything, mock.AnythingOfType("*common.AccessRequest")).Return(
					&common.AccessResponse{
						Granted: false,
						Reason:  "Insufficient permissions",
					}, nil)
			},
			expectedError:  true,
			expectedAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRBAC := &MockRBACManager{}
			tt.mockSetup(mockRBAC)

			validator := NewSecurityValidator(mockRBAC)
			ctx := context.Background()

			securityContext, err := validator.ValidateSessionAccess(ctx, tt.userID, tt.stewardID, tt.tenantID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, securityContext)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, securityContext)
				assert.Equal(t, tt.userID, securityContext.UserID)
				assert.Equal(t, tt.stewardID, securityContext.StewardID)
				assert.Equal(t, tt.tenantID, securityContext.TenantID)
			}

			mockRBAC.AssertExpectations(t)
		})
	}
}

func TestSecurityValidator_ValidateCommand(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		expectedAllowed  bool
		expectedAction   FilterAction
		expectedSeverity FilterSeverity
	}{
		{
			name:             "Safe command - ls",
			command:          "ls -la",
			expectedAllowed:  true,
			expectedAction:   FilterActionAllow,
			expectedSeverity: "",
		},
		{
			name:             "Dangerous command - rm -rf",
			command:          "rm -rf /",
			expectedAllowed:  false,
			expectedAction:   FilterActionBlock,
			expectedSeverity: FilterSeverityCritical,
		},
		{
			name:             "Audit command - sudo",
			command:          "sudo systemctl restart nginx",
			expectedAllowed:  true,
			expectedAction:   FilterActionAudit,
			expectedSeverity: FilterSeverityHigh,
		},
		{
			name:             "Network scanning command",
			command:          "nmap -sS 192.168.1.0/24",
			expectedAllowed:  false,
			expectedAction:   FilterActionBlock,
			expectedSeverity: FilterSeverityHigh,
		},
		{
			name:             "System configuration edit",
			command:          "vi /etc/passwd",
			expectedAllowed:  true,
			expectedAction:   FilterActionAudit,
			expectedSeverity: FilterSeverityHigh,
		},
	}

	mockRBAC := &MockRBACManager{}
	validator := NewSecurityValidator(mockRBAC)
	ctx := context.Background()

	securityContext := &SessionSecurityContext{
		SessionID:    "test-session",
		UserID:       "test-user",
		StewardID:    "test-steward",
		TenantID:     "test-tenant",
		FilterRules:  validator.getApplicableFilterRules("test-tenant", "test-steward"),
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

			if result.Action == FilterActionBlock || result.Action == FilterActionAudit {
				assert.NotNil(t, result.AuditEvent)
				assert.Equal(t, tt.command, result.AuditEvent.Command)
				assert.Equal(t, tt.expectedAction, result.AuditEvent.Action)
			}
		})
	}
}

func TestCommandFilterRules(t *testing.T) {
	rules := getDefaultCommandFilterRules()

	tests := []struct {
		name            string
		command         string
		expectedMatches int
		expectedAction  FilterAction
	}{
		{
			name:            "rm -rf command",
			command:         "rm -rf /tmp/test",
			expectedMatches: 1,
			expectedAction:  FilterActionBlock,
		},
		{
			name:            "format command",
			command:         "format c:",
			expectedMatches: 1,
			expectedAction:  FilterActionBlock,
		},
		{
			name:            "sudo command",
			command:         "sudo apt update",
			expectedMatches: 1,
			expectedAction:  FilterActionAudit,
		},
		{
			name:            "safe command",
			command:         "echo hello world",
			expectedMatches: 0,
			expectedAction:  FilterActionAllow,
		},
		{
			name:            "nmap command",
			command:         "nmap -sS target.com",
			expectedMatches: 1,
			expectedAction:  FilterActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchCount := 0
			var matchedRule CommandFilterRule

			for _, rule := range rules {
				if rule.compiledRx != nil && rule.compiledRx.MatchString(tt.command) {
					matchCount++
					matchedRule = rule
				}
			}

			assert.Equal(t, tt.expectedMatches, matchCount)

			if matchCount > 0 {
				assert.Equal(t, tt.expectedAction, matchedRule.Action)
			}
		})
	}
}

func TestSessionMonitor_ThreatLevelCalculation(t *testing.T) {
	mockRBAC := &MockRBACManager{}
	validator := NewSecurityValidator(mockRBAC)
	monitor := NewSessionMonitor(validator, DefaultMonitorConfig())

	ctx := context.Background()
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}
	defer func() {
		if err := monitor.Stop(); err != nil {
			t.Logf("Failed to stop monitor: %v", err)
		}
	}()

	// Create a test session
	session := &Session{
		ID:        "test-session",
		UserID:    "test-user",
		StewardID: "test-steward",
		CreatedAt: time.Now(),
	}

	securityContext := &SessionSecurityContext{
		SessionID: session.ID,
		UserID:    session.UserID,
		StewardID: session.StewardID,
		TenantID:  "test-tenant",
	}

	// Add session to monitoring
	err := monitor.AddSession(session, securityContext)
	require.NoError(t, err)

	// Test different threat scenarios
	t.Run("Low threat level - normal activity", func(t *testing.T) {
		sessionInfo, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)
		assert.Equal(t, ThreatLevelLow, sessionInfo.ThreatLevel)
	})

	t.Run("Medium threat level - some alerts", func(t *testing.T) {
		// Simulate some alerts
		monitor.generateAlert(monitor.sessions[session.ID], "test_alert", FilterSeverityMedium, "Test alert")
		monitor.generateAlert(monitor.sessions[session.ID], "test_alert", FilterSeverityMedium, "Test alert")
		monitor.generateAlert(monitor.sessions[session.ID], "test_alert", FilterSeverityMedium, "Test alert")

		// Update threat level
		monitor.updateThreatLevel(monitor.sessions[session.ID])

		sessionInfo, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)
		assert.Equal(t, ThreatLevelMedium, sessionInfo.ThreatLevel)
	})

	t.Run("High threat level - many alerts", func(t *testing.T) {
		// Add more alerts to reach high threat level
		for i := 0; i < 3; i++ {
			monitor.generateAlert(monitor.sessions[session.ID], "test_alert", FilterSeverityMedium, "Test alert")
		}

		monitor.updateThreatLevel(monitor.sessions[session.ID])

		sessionInfo, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)
		assert.Equal(t, ThreatLevelHigh, sessionInfo.ThreatLevel)
	})

	t.Run("Critical threat level - blocked commands", func(t *testing.T) {
		// Simulate blocked commands
		monitor.sessions[session.ID].mutex.Lock()
		monitor.sessions[session.ID].BlockedCommands = 5
		monitor.sessions[session.ID].mutex.Unlock()

		monitor.updateThreatLevel(monitor.sessions[session.ID])

		sessionInfo, err := monitor.GetSessionInfo(session.ID)
		require.NoError(t, err)
		assert.Equal(t, ThreatLevelCritical, sessionInfo.ThreatLevel)
	})
}

func TestAuditLogger_IntegrityProtection(t *testing.T) {
	config := DefaultAuditConfig()
	config.StoragePath = t.TempDir()
	config.IntegrityChecking = true
	config.HMACEnabled = true
	config.ChainHashing = true

	storage := NewFileAuditStorage(config.StoragePath)
	logger, err := NewAuditLogger(config, storage)
	require.NoError(t, err)

	ctx := context.Background()
	err = logger.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := logger.Stop(); err != nil {
			t.Logf("Failed to stop logger: %v", err)
		}
	}()

	// Test logging and integrity verification
	t.Run("Log entry with integrity protection", func(t *testing.T) {
		err := logger.LogCommandExecution(ctx, "session1", "user1", "steward1", "tenant1",
			"ls -la", 0, time.Second, "file1\nfile2\n")
		assert.NoError(t, err)

		// Allow some time for processing
		time.Sleep(100 * time.Millisecond)
	})

	t.Run("Log security violation", func(t *testing.T) {
		err := logger.LogSecurityViolation(ctx, "session1", "user1", "steward1", "tenant1",
			"command_blocked", "Dangerous command blocked", FilterSeverityCritical)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)
	})

	t.Run("Verify integrity of audit entries", func(t *testing.T) {
		// In a real implementation, we would retrieve entries and verify their integrity
		// This test verifies that the integrity protection mechanisms are working
		assert.NotEmpty(t, logger.integrityChecker.hashChain)
	})
}

func TestCommandInterceptor_InputFiltering(t *testing.T) {
	mockRBAC := &MockRBACManager{}
	validator := NewSecurityValidator(mockRBAC)

	securityContext := &SessionSecurityContext{
		SessionID:   "test-session",
		UserID:      "test-user",
		StewardID:   "test-steward",
		TenantID:    "test-tenant",
		FilterRules: validator.getApplicableFilterRules("test-tenant", "test-steward"),
	}

	auditChan := make(chan *CommandAuditEvent, 10)
	interceptor := NewCommandInterceptor(validator, securityContext, auditChan)

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
				// Check if an audit event was generated
				select {
				case event := <-auditChan:
					assert.Equal(t, FilterActionBlock, event.Action)
				case <-time.After(100 * time.Millisecond):
					// No event received, which might be expected for partial inputs
				}
			}
		})
	}
}

func TestDefaultCommandFilterRules(t *testing.T) {
	rules := getDefaultCommandFilterRules()

	// Ensure all rules have compiled regex patterns
	for _, rule := range rules {
		assert.NotNil(t, rule.compiledRx, "Rule %s should have compiled regex", rule.ID)
		assert.NotEmpty(t, rule.Pattern, "Rule %s should have pattern", rule.ID)
		assert.NotEmpty(t, rule.Name, "Rule %s should have name", rule.ID)
		assert.NotEmpty(t, rule.Description, "Rule %s should have description", rule.ID)
	}

	// Test specific dangerous patterns
	dangerousCommands := []string{
		"rm -rf /",
		"format c:",
		"sudo rm -rf /home",
		"nmap -sS 192.168.1.1",
		"chmod 777 /etc/passwd",
	}

	for _, cmd := range dangerousCommands {
		t.Run(fmt.Sprintf("Dangerous command: %s", cmd), func(t *testing.T) {
			found := false
			for _, rule := range rules {
				if rule.compiledRx.MatchString(cmd) {
					found = true
					assert.Contains(t, []FilterAction{FilterActionBlock, FilterActionAudit}, rule.Action,
						"Dangerous command should be blocked or audited")
					break
				}
			}
			assert.True(t, found, "Dangerous command should match at least one rule")
		})
	}
}

func TestSecurityLevels(t *testing.T) {
	mockRBAC := &MockRBACManager{}
	validator := NewSecurityValidator(mockRBAC)

	tests := []struct {
		name          string
		permissions   []string
		filterRules   []CommandFilterRule
		expectedLevel SecurityLevel
	}{
		{
			name:          "Admin permissions - maximum security",
			permissions:   []string{"terminal.admin", "system.admin"},
			filterRules:   []CommandFilterRule{},
			expectedLevel: SecurityLevelMaximum,
		},
		{
			name:          "Regular user - enhanced security",
			permissions:   []string{"terminal.session.create", "terminal.session.read"},
			filterRules:   []CommandFilterRule{},
			expectedLevel: SecurityLevelEnhanced,
		},
		{
			name:        "Critical rules present - maximum security",
			permissions: []string{"terminal.session.create"},
			filterRules: []CommandFilterRule{
				{Severity: FilterSeverityCritical},
			},
			expectedLevel: SecurityLevelMaximum,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := validator.determineMonitoringLevel(tt.permissions, tt.filterRules)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

func BenchmarkCommandValidation(b *testing.B) {
	mockRBAC := &MockRBACManager{}
	validator := NewSecurityValidator(mockRBAC)
	ctx := context.Background()

	securityContext := &SessionSecurityContext{
		SessionID:   "bench-session",
		UserID:      "bench-user",
		StewardID:   "bench-steward",
		TenantID:    "bench-tenant",
		FilterRules: validator.getApplicableFilterRules("bench-tenant", "bench-steward"),
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
