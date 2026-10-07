// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rollback_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/git"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
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
	// Root scope: this test is about rollback-point construction, not the tenant
	// boundary, and the manager fails closed on an unset caller scope (Issue #4340).
	ctx := rootScopedContext()

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier,
		stewardRegistry(t, map[string]string{"123": "root/msp-a/client-1"}))

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
	ctx := rootScopedContext()

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier,
		stewardRegistry(t, map[string]string{"123": "root/msp-a/client-1"}))

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
	ctx := context.WithValue(rootScopedContext(), ctxkeys.UserIDKey, "test-user")

	// Setup mocks
	gitManager := new(MockGitManager)
	validator := new(MockRollbackValidator)
	store := rollback.NewInMemoryRollbackStore()
	notifier := new(MockRollbackNotifier)

	manager := rollback.NewRollbackManager(gitManager, validator, store, notifier,
		stewardRegistry(t, map[string]string{"123": "root/msp-a/client-1"}))

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

	// Use no-op implementations for interfaces not exercised by these test cases.
	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, &noopConfigParser{}, nil)

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

// noopModuleRegistry satisfies rollback.ModuleRegistry for tests that don't exercise
// module-compatibility paths.
type noopModuleRegistry struct{}

func (r *noopModuleRegistry) GetModuleVersion(_ context.Context, _ string) (string, error) {
	return "1.0.0", nil
}

func (r *noopModuleRegistry) GetModuleDependencies(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (r *noopModuleRegistry) IsModuleCompatible(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// noopConfigParser satisfies rollback.ConfigurationParser for tests that don't exercise
// configuration-parsing paths.
type noopConfigParser struct{}

func (p *noopConfigParser) ParseConfiguration(_ []byte, _ string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (p *noopConfigParser) ValidateSchema(_ map[string]interface{}, _ string) error {
	return nil
}

func (p *noopConfigParser) GetRequiredFields(_ string) []string {
	return nil
}

func TestRollbackManager_ExecuteRollback_ErrorWithoutUserInContext(t *testing.T) {
	// CancelRollback and ExecuteRollback both call getCurrentUser first;
	// use a context with no user ID to assert the auth guard is in place.
	ctx := context.Background()

	store := rollback.NewInMemoryRollbackStore()
	manager := rollback.NewRollbackManager(nil, nil, store, nil,
		stewardRegistry(t, map[string]string{"123": "root/msp-a/client-1"}))

	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "123",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "abc123",
		Reason:       "test",
	}

	_, err := manager.ExecuteRollback(ctx, request)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated")
}

func TestRollbackManager_CancelRollback_UserIDFromContext(t *testing.T) {
	// Seeds an operation directly in the store, then cancels it with a known user in context.
	// Verifies that getCurrentUser reads the user ID from context and records it in the audit trail.
	ctx := context.WithValue(rootScopedContext(), ctxkeys.UserIDKey, "cancel-actor")

	store := rollback.NewInMemoryRollbackStore()
	manager := rollback.NewRollbackManager(nil, nil, store, nil, nil)

	op := &rollback.RollbackOperation{
		ID:          "op-ctx-test",
		Status:      rollback.RollbackStatusPending,
		InitiatedBy: "original-user",
		AuditTrail:  []rollback.AuditEntry{},
	}
	require.NoError(t, store.SaveOperation(ctx, op))

	require.NoError(t, manager.CancelRollback(ctx, "op-ctx-test", "context test"))

	updated, err := store.GetOperation(ctx, "op-ctx-test")
	require.NoError(t, err)
	require.NotEmpty(t, updated.AuditTrail)
	assert.Equal(t, "cancel-actor", updated.AuditTrail[len(updated.AuditTrail)-1].Actor)
}

func TestRollbackManager_CancelRollback_ErrorWithoutUserInContext(t *testing.T) {
	ctx := context.Background() // No user ID in context

	store := rollback.NewInMemoryRollbackStore()
	manager := rollback.NewRollbackManager(nil, nil, store, nil, nil)

	err := manager.CancelRollback(ctx, "any-op-id", "reason")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated")
}

// Tenant-boundary tests (Issue #4340): a caller cannot preview, apply, read or
// cancel a rollback for a target outside its authorized tenant subtree.
//
// The tenant a target belongs to is resolved from the controller's steward
// registry — features/controller/service.ControllerService, the real type wired
// as the rollback manager's TargetTenantResolver in production — so these tests
// drive the control with the same data production feeds it. Nothing in the Git
// history these tests serve carries a tenant, which is the point: Git commits
// never carry one, so a boundary read from commit metadata would admit every
// caller. The rest of the stack is real as well: the real rollback validator,
// the real rollback notifier and the real in-memory rollback store.

// fixtureGitManager serves a fixed commit history and diff for the rollback
// manager's two read calls. It embeds a real *git.DefaultGitManager, so every
// method these tests do not exercise keeps its production behaviour.
//
// It is not a mock: it records no expectations, programs no return values per
// call and asserts nothing about how it was called. It stands in for one thing
// only — repository content — because the only git.GitProvider implementation in
// the tree is the GitHub provider, which requires network access and a token, so
// a real DefaultGitManager cannot resolve a repository inside a unit test. The
// same paths run against a real DefaultGitManager over the go-git
// LocalRepositoryStore in features/controller/api's rollback handler tests.
type fixtureGitManager struct {
	*git.DefaultGitManager

	commits   []*git.Commit
	diff      []git.ConfigChange
	diffCalls int
}

func newFixtureGitManager(t *testing.T, commits []*git.Commit, diff []git.ConfigChange) *fixtureGitManager {
	t.Helper()

	return &fixtureGitManager{
		DefaultGitManager: git.NewGitManager(nil, nil, git.GitManagerConfig{CacheDir: t.TempDir()}, nil),
		commits:           commits,
		diff:              diff,
	}
}

func (f *fixtureGitManager) GetCommitHistory(_ context.Context, _ string, _ string, limit int) ([]*git.Commit, error) {
	if limit > 0 && limit < len(f.commits) {
		return f.commits[:limit], nil
	}
	return f.commits, nil
}

func (f *fixtureGitManager) GetDiff(_ context.Context, _ string, _, _ string) ([]git.ConfigChange, error) {
	f.diffCalls++
	return f.diff, nil
}

// stewardRegistry returns the controller's real steward registry holding the
// given steward ID -> tenant path ownership. It is the production
// TargetTenantResolver: features/controller/service.ControllerService, the same
// registry the reports API asks about device ownership.
func stewardRegistry(t *testing.T, owners map[string]string) rollback.TargetTenantResolver {
	t.Helper()

	registry := service.NewControllerService(logging.NewNoopLogger())
	for stewardID, tenantID := range owners {
		require.NoError(t, registry.RegisterSteward(stewardID, tenantID, "127.0.0.1:9000", "active"))
	}

	return registry
}

// newTenantScopedManager builds a rollback manager from real components with the
// given target ownership, and the supplied Git manager as its only collaborator
// that is not the production type.
func newTenantScopedManager(t *testing.T, gitManager git.GitManager, owners map[string]string) (rollback.RollbackManager, rollback.RollbackStore) {
	t.Helper()

	store := rollback.NewInMemoryRollbackStore()
	// Real validator: nil module registry, parser and RBAC manager leave the
	// registry-backed and permission checks disabled, which is the documented
	// contract of those parameters, and exercise the rest for real.
	validator := rollback.NewRollbackValidator(nil, nil, nil)
	notifier := rollback.NewDefaultRollbackNotifier(logging.NewNoopLogger())

	return rollback.NewRollbackManager(gitManager, validator, store, notifier, stewardRegistry(t, owners)), store
}

// rootScopedContext carries the scope the authentication middleware establishes
// for a verified mTLS admin certificate: unrestricted, cross-tenant access.
func rootScopedContext() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
}

func tenantScopedContext(tenantPath string) context.Context {
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "test-user")
	return context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(tenantPath))
}

// untenantedCommit is a commit as the production stack records it: no tenant on
// its metadata, because neither DefaultGitManager nor the local repository store
// writes one.
func untenantedCommit(sha string) *git.Commit {
	return &git.Commit{
		SHA:       sha,
		Message:   "Update firewall rules",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Author:    git.CommitAuthor{Name: "Jane Smith", Email: "jane@example.com"},
		Files:     []git.FileChange{{Path: "firewall.yaml", Action: "modified"}},
		Metadata:  git.CommitMetadata{ChangeID: "change-" + sha},
	}
}

func tenantRollbackRequest() rollback.RollbackRequest {
	return rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "123",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "abc123",
		Reason:       "Revert problematic update",
	}
}

func TestRollbackManager_PreviewRollback_DeniedOutsideTenantScope(t *testing.T) {
	// The registry owns the target in a sibling tenant, not the caller's subtree.
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-2"})

	_, err := manager.PreviewRollback(tenantScopedContext("root/msp-a/client-1"), tenantRollbackRequest())

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	// The diff must never be fetched once the tenant check denies the request.
	assert.Zero(t, gitManager.diffCalls)
}

func TestRollbackManager_ExecuteRollback_DeniedOutsideTenantScope(t *testing.T) {
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, nil)
	manager, store := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-2"})

	ctx := tenantScopedContext("root/msp-a/client-1")
	_, err := manager.ExecuteRollback(ctx, tenantRollbackRequest())

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Zero(t, gitManager.diffCalls)

	// A denied execute must not leave an operation behind.
	operations, listErr := store.ListOperations(ctx, rollback.RollbackFilters{})
	require.NoError(t, listErr)
	assert.Empty(t, operations)
}

func TestRollbackManager_PreviewRollback_AllowedWithinTenantScope(t *testing.T) {
	// Target belongs to a child of the caller's own tenant scope, and its commit
	// history carries no tenant at all — the boundary comes from the registry.
	diff := []git.ConfigChange{{Path: "firewall.yaml", Action: "update", NewContent: []byte("firewall config")}}
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, diff)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-1"})

	preview, err := manager.PreviewRollback(tenantScopedContext("root/msp-a"), tenantRollbackRequest())

	require.NoError(t, err)
	assert.Equal(t, "root/msp-a/client-1", preview.TargetTenantID)
	assert.Len(t, preview.Changes, 1)
	assert.Equal(t, 1, gitManager.diffCalls)
}

func TestRollbackManager_PreviewRollback_DeniedForTargetUnknownToRegistry(t *testing.T) {
	// A target the ownership authority does not know is outside every tenant, not
	// unowned: a caller must not reach a steward the registry cannot vouch for.
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, nil)

	_, err := manager.PreviewRollback(tenantScopedContext("root/msp-a/client-1"), tenantRollbackRequest())

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Zero(t, gitManager.diffCalls)
}

func TestRollbackManager_PreviewRollback_DeniedWithoutTenantResolver(t *testing.T) {
	// A deployment that wired no ownership authority refuses scoped callers
	// instead of serving them unchecked.
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, nil)
	manager := rollback.NewRollbackManager(gitManager, rollback.NewRollbackValidator(nil, nil, nil),
		rollback.NewInMemoryRollbackStore(), rollback.NewDefaultRollbackNotifier(logging.NewNoopLogger()), nil)

	_, err := manager.PreviewRollback(tenantScopedContext("root/msp-a/client-1"), tenantRollbackRequest())

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackTenantUnverifiable)
	assert.Zero(t, gitManager.diffCalls)
}

func TestRollbackManager_PreviewRollback_DeniedWithUnsetCallerScope(t *testing.T) {
	// A context the authentication middleware never scoped is not root: a lost
	// caller scope must close the door, not open it.
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-1"})

	_, err := manager.PreviewRollback(context.Background(), tenantRollbackRequest())

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Zero(t, gitManager.diffCalls)
}

func TestRollbackManager_ListRollbackPoints_DeniedOutsideTenantScope(t *testing.T) {
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("abc123")}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-2"})

	points, err := manager.ListRollbackPoints(tenantScopedContext("root/msp-a/client-1"), rollback.TargetTypeDevice, "123", 10)

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Nil(t, points)
}

func TestRollbackManager_ListRollbackPoints_AllowedWithinTenantScope(t *testing.T) {
	// The commits carry no tenant metadata, exactly as the production Git stack
	// records them; the caller still gets its own tenant's rollback points.
	gitManager := newFixtureGitManager(t, []*git.Commit{
		untenantedCommit("abc123"),
		untenantedCommit("def456"),
	}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-1"})

	points, err := manager.ListRollbackPoints(tenantScopedContext("root/msp-a/client-1"), rollback.TargetTypeDevice, "123", 10)

	require.NoError(t, err)
	require.Len(t, points, 2)
	assert.Equal(t, "abc123", points[0].CommitSHA)
}

func TestRollbackManager_ListRollbackPoints_DeniedForUnresolvableTargetKind(t *testing.T) {
	// Group, client and MSP-wide targets have no ownership authority, so a
	// tenant-scoped caller cannot enumerate them even when its own tenant matches
	// the target ID.
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("abc123")}, nil)
	manager, _ := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-1"})

	points, err := manager.ListRollbackPoints(tenantScopedContext("root/msp-a/client-1"), rollback.TargetTypeClient, "root/msp-a/client-1", 10)

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Nil(t, points)
}

func TestRollbackManager_ExecuteRollback_RecordsResolvedTenantOnOperation(t *testing.T) {
	// The tenant the boundary is later enforced against must be a real resolved
	// value on the stored operation, not an empty field that admits everyone.
	diff := []git.ConfigChange{{Path: "firewall.yaml", Action: "update", NewContent: []byte("firewall config")}}
	gitManager := newFixtureGitManager(t, []*git.Commit{untenantedCommit("current123")}, diff)
	manager, store := newTenantScopedManager(t, gitManager, map[string]string{"123": "root/msp-a/client-1"})

	ctx := tenantScopedContext("root/msp-a/client-1")
	operation, err := manager.ExecuteRollback(ctx, tenantRollbackRequest())

	require.NoError(t, err)
	require.NotNil(t, operation)
	assert.Equal(t, "root/msp-a/client-1", operation.TargetTenantID)

	stored, getErr := store.GetOperation(ctx, operation.ID)
	require.NoError(t, getErr)
	require.NotNil(t, stored)
	assert.Equal(t, "root/msp-a/client-1", stored.TargetTenantID)
}

func TestRollbackManager_GetRollbackStatus_DeniedOutsideTenantScope(t *testing.T) {
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-2"})

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	require.NoError(t, store.SaveOperation(seedCtx, &rollback.RollbackOperation{
		ID:             "op-status-denied",
		Request:        tenantRollbackRequest(),
		Status:         rollback.RollbackStatusInProgress,
		InitiatedBy:    "other-tenant-operator",
		AuditTrail:     []rollback.AuditEntry{{Action: "rollback_initiated", Actor: "other-tenant-operator"}},
		TargetTenantID: "root/msp-a/client-2",
	}))

	operation, err := manager.GetRollbackStatus(tenantScopedContext("root/msp-a/client-1"), "op-status-denied")

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	// Nothing about the other tenant's operation may reach the caller.
	assert.Nil(t, operation)
}

func TestRollbackManager_GetRollbackStatus_DeniedForOperationWithoutRecordedTenant(t *testing.T) {
	// An operation written before the tenant was recorded carries an empty value.
	// That must resolve against the registry, never read as "no boundary".
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-2"})

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	require.NoError(t, store.SaveOperation(seedCtx, &rollback.RollbackOperation{
		ID:          "op-status-legacy",
		Request:     tenantRollbackRequest(),
		Status:      rollback.RollbackStatusInProgress,
		InitiatedBy: "other-tenant-operator",
		AuditTrail:  []rollback.AuditEntry{{Action: "rollback_initiated", Actor: "other-tenant-operator"}},
	}))

	operation, err := manager.GetRollbackStatus(tenantScopedContext("root/msp-a/client-1"), "op-status-legacy")

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Nil(t, operation)
}

func TestRollbackManager_GetRollbackStatus_AllowedWithinTenantScope(t *testing.T) {
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-1"})

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	require.NoError(t, store.SaveOperation(seedCtx, &rollback.RollbackOperation{
		ID:             "op-status-allowed",
		Request:        tenantRollbackRequest(),
		Status:         rollback.RollbackStatusInProgress,
		InitiatedBy:    "own-tenant-operator",
		AuditTrail:     []rollback.AuditEntry{},
		TargetTenantID: "root/msp-a/client-1",
	}))

	operation, err := manager.GetRollbackStatus(tenantScopedContext("root/msp-a"), "op-status-allowed")

	require.NoError(t, err)
	require.NotNil(t, operation)
	assert.Equal(t, "own-tenant-operator", operation.InitiatedBy)
}

func TestRollbackManager_GetRollbackStatus_DeregisteredTargetKeepsRecordedTenant(t *testing.T) {
	// The target has left the registry; the tenant captured when the operation ran
	// still bounds who may read it, in both directions.
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), nil)

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	require.NoError(t, store.SaveOperation(seedCtx, &rollback.RollbackOperation{
		ID:             "op-status-deregistered",
		Request:        tenantRollbackRequest(),
		Status:         rollback.RollbackStatusCompleted,
		InitiatedBy:    "own-tenant-operator",
		AuditTrail:     []rollback.AuditEntry{},
		TargetTenantID: "root/msp-a/client-1",
	}))

	owner, err := manager.GetRollbackStatus(tenantScopedContext("root/msp-a/client-1"), "op-status-deregistered")
	require.NoError(t, err)
	require.NotNil(t, owner)

	sibling, err := manager.GetRollbackStatus(tenantScopedContext("root/msp-a/client-2"), "op-status-deregistered")
	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)
	assert.Nil(t, sibling)
}

func TestRollbackManager_ListRollbackHistory_OmitsOperationsOutsideTenantScope(t *testing.T) {
	// A device reassigned between clients keeps its operations, so a target's
	// history can span tenants; only the caller's own may be returned.
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-1"})

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	request := tenantRollbackRequest()
	for _, op := range []*rollback.RollbackOperation{
		{ID: "op-own", Request: request, Status: rollback.RollbackStatusCompleted, AuditTrail: []rollback.AuditEntry{}, TargetTenantID: "root/msp-a/client-1"},
		{ID: "op-other", Request: request, Status: rollback.RollbackStatusCompleted, AuditTrail: []rollback.AuditEntry{}, TargetTenantID: "root/msp-a/client-2"},
	} {
		require.NoError(t, store.SaveOperation(seedCtx, op))
	}

	history, err := manager.ListRollbackHistory(tenantScopedContext("root/msp-a/client-1"), rollback.TargetTypeDevice, "123", 10)

	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, "op-own", history[0].ID)
}

func TestRollbackManager_ListRollbackHistory_RootScopeSeesAllOperations(t *testing.T) {
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-1"})

	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	request := tenantRollbackRequest()
	for _, op := range []*rollback.RollbackOperation{
		{ID: "op-a", Request: request, Status: rollback.RollbackStatusCompleted, AuditTrail: []rollback.AuditEntry{}, TargetTenantID: "root/msp-a/client-1"},
		{ID: "op-b", Request: request, Status: rollback.RollbackStatusCompleted, AuditTrail: []rollback.AuditEntry{}, TargetTenantID: "root/msp-b/client-9"},
	} {
		require.NoError(t, store.SaveOperation(seedCtx, op))
	}

	history, err := manager.ListRollbackHistory(rootScopedContext(), rollback.TargetTypeDevice, "123", 10)

	require.NoError(t, err)
	assert.Len(t, history, 2)
}

func TestRollbackManager_CancelRollback_DeniedOutsideTenantScope(t *testing.T) {
	// Seed an operation whose target belongs to a sibling tenant, then attempt to
	// cancel it from a different tenant's scope.
	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-2"})

	op := &rollback.RollbackOperation{
		ID:             "op-tenant-test",
		Request:        tenantRollbackRequest(),
		Status:         rollback.RollbackStatusPending,
		InitiatedBy:    "original-user",
		AuditTrail:     []rollback.AuditEntry{},
		TargetTenantID: "root/msp-a/client-2",
	}
	require.NoError(t, store.SaveOperation(seedCtx, op))

	cancelCtx := tenantScopedContext("root/msp-a/client-1")

	err := manager.CancelRollback(cancelCtx, "op-tenant-test", "attempted cross-tenant cancel")

	require.Error(t, err)
	assert.ErrorIs(t, err, rollback.ErrRollbackOutsideTenantScope)

	// The operation must remain untouched by the denied cancel attempt. The store is
	// read directly so the assertion covers the stored state rather than whatever the
	// manager is willing to hand back to this caller.
	unchanged, getErr := store.GetOperation(seedCtx, "op-tenant-test")
	require.NoError(t, getErr)
	assert.Equal(t, rollback.RollbackStatusPending, unchanged.Status)
}

func TestRollbackManager_CancelRollback_AllowedWithinTenantScope(t *testing.T) {
	seedCtx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "seed-actor")
	manager, store := newTenantScopedManager(t, newFixtureGitManager(t, nil, nil), map[string]string{"123": "root/msp-a/client-1"})

	op := &rollback.RollbackOperation{
		ID:             "op-tenant-ok",
		Request:        tenantRollbackRequest(),
		Status:         rollback.RollbackStatusPending,
		InitiatedBy:    "original-user",
		AuditTrail:     []rollback.AuditEntry{},
		TargetTenantID: "root/msp-a/client-1",
	}
	require.NoError(t, store.SaveOperation(seedCtx, op))

	cancelCtx := tenantScopedContext("root/msp-a/client-1")

	require.NoError(t, manager.CancelRollback(cancelCtx, "op-tenant-ok", "authorized cancel"))

	updated, err := store.GetOperation(cancelCtx, "op-tenant-ok")
	require.NoError(t, err)
	assert.Equal(t, rollback.RollbackStatusCancelled, updated.Status)
}
