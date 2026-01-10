// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/features/config/git"
	"github.com/cfgis/cfgms/features/config/rollback"
)

// Mock implementations

type MockGitManager struct {
	mock.Mock
}

func (m *MockGitManager) CreateRepository(ctx context.Context, config git.RepositoryConfig) (*git.Repository, error) {
	args := m.Called(ctx, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*git.Repository), args.Error(1)
}

func (m *MockGitManager) GetRepository(ctx context.Context, repoID string) (*git.Repository, error) {
	args := m.Called(ctx, repoID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*git.Repository), args.Error(1)
}

func (m *MockGitManager) ListRepositories(ctx context.Context, filter git.RepositoryFilter) ([]*git.Repository, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*git.Repository), args.Error(1)
}

func (m *MockGitManager) DeleteRepository(ctx context.Context, repoID string) error {
	args := m.Called(ctx, repoID)
	return args.Error(0)
}

func (m *MockGitManager) GetConfiguration(ctx context.Context, ref git.ConfigurationRef) (*git.Configuration, error) {
	args := m.Called(ctx, ref)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*git.Configuration), args.Error(1)
}

func (m *MockGitManager) SaveConfiguration(ctx context.Context, ref git.ConfigurationRef, config *git.Configuration, message string) error {
	args := m.Called(ctx, ref, config, message)
	return args.Error(0)
}

func (m *MockGitManager) DeleteConfiguration(ctx context.Context, ref git.ConfigurationRef, message string) error {
	args := m.Called(ctx, ref, message)
	return args.Error(0)
}

func (m *MockGitManager) CreateBranch(ctx context.Context, repoID, branchName, fromRef string) error {
	args := m.Called(ctx, repoID, branchName, fromRef)
	return args.Error(0)
}

func (m *MockGitManager) DeleteBranch(ctx context.Context, repoID, branchName string) error {
	args := m.Called(ctx, repoID, branchName)
	return args.Error(0)
}

func (m *MockGitManager) MergeBranch(ctx context.Context, repoID, source, target string, message string) error {
	args := m.Called(ctx, repoID, source, target, message)
	return args.Error(0)
}

func (m *MockGitManager) ListBranches(ctx context.Context, repoID string) ([]string, error) {
	args := m.Called(ctx, repoID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockGitManager) GetCommitHistory(ctx context.Context, repoID string, branch string, limit int) ([]*git.Commit, error) {
	args := m.Called(ctx, repoID, branch, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*git.Commit), args.Error(1)
}

func (m *MockGitManager) GetCommit(ctx context.Context, repoID string, sha string) (*git.Commit, error) {
	args := m.Called(ctx, repoID, sha)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*git.Commit), args.Error(1)
}

func (m *MockGitManager) GetDiff(ctx context.Context, repoID string, fromRef, toRef string) ([]git.ConfigChange, error) {
	args := m.Called(ctx, repoID, fromRef, toRef)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]git.ConfigChange), args.Error(1)
}

func (m *MockGitManager) SyncTemplates(ctx context.Context, clientRepoID string) error {
	args := m.Called(ctx, clientRepoID)
	return args.Error(0)
}

func (m *MockGitManager) PropagateChange(ctx context.Context, change git.ChangeSet) error {
	args := m.Called(ctx, change)
	return args.Error(0)
}

func (m *MockGitManager) CreatePullRequest(ctx context.Context, repoID string, config git.PullRequestConfig) (string, error) {
	args := m.Called(ctx, repoID, config)
	return args.String(0), args.Error(1)
}

func (m *MockGitManager) MergePullRequest(ctx context.Context, repoID string, prID string) error {
	args := m.Called(ctx, repoID, prID)
	return args.Error(0)
}

func (m *MockGitManager) CreateWebhook(ctx context.Context, repoID string, config git.WebhookConfig) error {
	args := m.Called(ctx, repoID, config)
	return args.Error(0)
}

func (m *MockGitManager) DeleteWebhook(ctx context.Context, repoID string, webhookID string) error {
	args := m.Called(ctx, repoID, webhookID)
	return args.Error(0)
}

func (m *MockGitManager) SetBranchProtection(ctx context.Context, repoID string, rule git.BranchProtectionRule) error {
	args := m.Called(ctx, repoID, rule)
	return args.Error(0)
}

func (m *MockGitManager) RemoveBranchProtection(ctx context.Context, repoID string, branch string) error {
	args := m.Called(ctx, repoID, branch)
	return args.Error(0)
}

type MockRollbackValidator struct {
	mock.Mock
}

func (m *MockRollbackValidator) ValidateRollback(ctx context.Context, request rollback.RollbackRequest, preview *rollback.RollbackPreview) (*rollback.ValidationResults, error) {
	args := m.Called(ctx, request, preview)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rollback.ValidationResults), args.Error(1)
}

func (m *MockRollbackValidator) AssessRisk(ctx context.Context, request rollback.RollbackRequest, changes []rollback.ConfigurationChange) (*rollback.RiskAssessment, error) {
	args := m.Called(ctx, request, changes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rollback.RiskAssessment), args.Error(1)
}

func (m *MockRollbackValidator) CheckDependencies(ctx context.Context, targetType rollback.TargetType, targetID string, changes []rollback.ConfigurationChange) error {
	args := m.Called(ctx, targetType, targetID, changes)
	return args.Error(0)
}

func (m *MockRollbackValidator) ValidateModuleCompatibility(ctx context.Context, modules []string, targetVersion string) error {
	args := m.Called(ctx, modules, targetVersion)
	return args.Error(0)
}

type MockRollbackNotifier struct {
	mock.Mock
}

func (m *MockRollbackNotifier) NotifyRollbackStarted(ctx context.Context, operation *rollback.RollbackOperation) error {
	args := m.Called(ctx, operation)
	return args.Error(0)
}

func (m *MockRollbackNotifier) NotifyRollbackProgress(ctx context.Context, operation *rollback.RollbackOperation) error {
	args := m.Called(ctx, operation)
	return args.Error(0)
}

func (m *MockRollbackNotifier) NotifyRollbackCompleted(ctx context.Context, operation *rollback.RollbackOperation) error {
	args := m.Called(ctx, operation)
	return args.Error(0)
}

func (m *MockRollbackNotifier) NotifyRollbackFailed(ctx context.Context, operation *rollback.RollbackOperation, err error) error {
	args := m.Called(ctx, operation, err)
	return args.Error(0)
}

// Tests

func TestRollbackManager_ListRollbackPoints(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier)

	// Mock commit history
	commits := []*git.Commit{
		{
			SHA: "abc123",
			Author: git.CommitAuthor{
				Name:  "John Doe",
				Email: "john@example.com",
			},
			Message:   "Update firewall rules",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Files: []git.FileChange{
				{Path: "firewall.yaml", Action: "modified"},
				{Path: "network.yaml", Action: "modified"},
			},
			Metadata: git.CommitMetadata{
				ChangeID: "change-123",
			},
		},
		{
			SHA: "def456",
			Author: git.CommitAuthor{
				Name:  "Jane Smith",
				Email: "jane@example.com",
			},
			Message:   "Add new module",
			Timestamp: time.Now().Add(-2 * time.Hour),
			Files: []git.FileChange{
				{Path: "modules/newmodule/config.yaml", Action: "added"},
			},
			Metadata: git.CommitMetadata{
				ChangeID: "change-456",
			},
		},
	}

	gitManager.On("GetCommitHistory", ctx, "device-123-repo", "", 50).Return(commits, nil)

	// Test
	points, err := manager.ListRollbackPoints(ctx, rollback.TargetTypeDevice, "123", 50)

	// Assertions
	assert.NoError(t, err)
	assert.Len(t, points, 2)
	assert.Equal(t, "abc123", points[0].CommitSHA)
	assert.Equal(t, "John Doe", points[0].Author)
	assert.Contains(t, points[0].Configurations, "firewall.yaml")
	assert.Contains(t, points[0].Configurations, "network.yaml")

	gitManager.AssertExpectations(t)
}

func TestRollbackManager_PreviewRollback(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier)

	// Test request
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "123",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "abc123",
		Reason:       "Revert problematic update",
	}

	// Mock current commit
	currentCommit := []*git.Commit{{SHA: "current123"}}
	gitManager.On("GetCommitHistory", ctx, "device-123-repo", "", 1).Return(currentCommit, nil)

	// Mock diff
	diffs := []git.ConfigChange{
		{
			Path:       "firewall.yaml",
			Action:     "update",
			NewContent: []byte("firewall config"),
		},
	}
	gitManager.On("GetDiff", ctx, "device-123-repo", "abc123", "current123").Return(diffs, nil)

	// Mock validation
	validationResults := &rollback.ValidationResults{
		Passed:   true,
		Warnings: []rollback.ValidationIssue{},
		Errors:   []rollback.ValidationIssue{},
	}
	validator.On("ValidateRollback", ctx, request, mock.Anything).Return(validationResults, nil)

	// Mock risk assessment
	riskAssessment := &rollback.RiskAssessment{
		OverallRisk:   rollback.RiskLevelMedium,
		ServiceImpact: "minimal",
	}
	validator.On("AssessRisk", ctx, request, mock.Anything).Return(riskAssessment, nil)

	// Test
	preview, err := manager.PreviewRollback(ctx, request)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, preview)
	assert.Len(t, preview.Changes, 1)
	assert.Equal(t, "firewall.yaml", preview.Changes[0].Path)
	assert.True(t, preview.ValidationResults.Passed)
	assert.Equal(t, rollback.RiskLevelMedium, preview.RiskAssessment.OverallRisk)

	gitManager.AssertExpectations(t)
	validator.AssertExpectations(t)
}

func TestRollbackManager_ExecuteRollback_RequiresApproval(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier)

	// Test request without approval
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "123",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "abc123",
		Reason:       "Revert problematic update",
	}

	// Mock preview that requires approval
	currentCommit := []*git.Commit{{SHA: "current123"}}
	gitManager.On("GetCommitHistory", ctx, "device-123-repo", "", 1).Return(currentCommit, nil)

	diffs := []git.ConfigChange{{Path: "critical.yaml", Action: "update"}}
	gitManager.On("GetDiff", ctx, "device-123-repo", "abc123", "current123").Return(diffs, nil)

	validationResults := &rollback.ValidationResults{Passed: true}
	validator.On("ValidateRollback", ctx, request, mock.Anything).Return(validationResults, nil)

	// High risk requires approval
	riskAssessment := &rollback.RiskAssessment{OverallRisk: rollback.RiskLevelHigh}
	validator.On("AssessRisk", ctx, request, mock.Anything).Return(riskAssessment, nil)

	// Test
	_, err := manager.ExecuteRollback(ctx, request)

	// Assertions
	assert.Error(t, err)
	rollbackErr, ok := err.(*rollback.RollbackError)
	assert.True(t, ok)
	assert.Equal(t, "APPROVAL_REQUIRED", rollbackErr.Code)

	gitManager.AssertExpectations(t)
	validator.AssertExpectations(t)
}

func TestRollbackValidator_ValidateRollback(t *testing.T) {
	ctx := context.Background()

	// Create validator with mocks
	moduleRegistry := new(MockModuleRegistry)
	configParser := new(MockConfigParser)
	validator := rollback.NewRollbackValidator(moduleRegistry, configParser)

	// Test cases
	tests := []struct {
		name        string
		request     rollback.RollbackRequest
		expectPass  bool
		expectError bool
	}{
		{
			name: "Valid full rollback",
			request: rollback.RollbackRequest{
				TargetType:   rollback.TargetTypeDevice,
				TargetID:     "123",
				RollbackType: rollback.RollbackTypeFull,
				RollbackTo:   "abc123",
				Reason:       "Test rollback",
			},
			expectPass:  true,
			expectError: false,
		},
		{
			name: "Invalid partial rollback - no configs",
			request: rollback.RollbackRequest{
				TargetType:     rollback.TargetTypeDevice,
				TargetID:       "123",
				RollbackType:   rollback.RollbackTypePartial,
				RollbackTo:     "abc123",
				Configurations: []string{}, // Empty
			},
			expectPass:  false,
			expectError: false,
		},
		{
			name: "Invalid target ID",
			request: rollback.RollbackRequest{
				TargetType:   rollback.TargetTypeDevice,
				TargetID:     "", // Empty
				RollbackType: rollback.RollbackTypeFull,
				RollbackTo:   "abc123",
				Reason:       "Test",
			},
			expectPass:  false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := validator.ValidateRollback(ctx, tt.request, nil)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectPass, results.Passed)

				if !tt.expectPass {
					assert.NotEmpty(t, results.Errors)
				}
			}
		})
	}
}

// Mock module registry for validator tests
type MockModuleRegistry struct {
	mock.Mock
}

func (m *MockModuleRegistry) GetModuleVersion(ctx context.Context, moduleName string) (string, error) {
	args := m.Called(ctx, moduleName)
	return args.String(0), args.Error(1)
}

func (m *MockModuleRegistry) GetModuleDependencies(ctx context.Context, moduleName string) ([]string, error) {
	args := m.Called(ctx, moduleName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockModuleRegistry) IsModuleCompatible(ctx context.Context, moduleName, version string) (bool, error) {
	args := m.Called(ctx, moduleName, version)
	return args.Bool(0), args.Error(1)
}

// Mock config parser for validator tests
type MockConfigParser struct {
	mock.Mock
}

func (m *MockConfigParser) ParseConfiguration(content []byte, format string) (map[string]interface{}, error) {
	args := m.Called(content, format)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockConfigParser) ValidateSchema(config map[string]interface{}, schema string) error {
	args := m.Called(config, schema)
	return args.Error(0)
}

func (m *MockConfigParser) GetRequiredFields(schema string) []string {
	args := m.Called(schema)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).([]string)
}
