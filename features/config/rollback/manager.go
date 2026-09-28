// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rollback

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/config/git"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// DefaultRollbackManager implements the RollbackManager interface
type DefaultRollbackManager struct {
	gitManager git.GitManager
	validator  RollbackValidator
	store      RollbackStore
	notifier   RollbackNotifier
	tenants    TargetTenantResolver
}

// NewRollbackManager creates a new rollback manager.
//
// tenants resolves the tenant that owns a rollback target and is the only input
// to the tenant boundary enforced on every entry point (Issue #4340). It is a
// required parameter rather than an optional setter so that each wiring point
// has to name its ownership authority: passing nil leaves every non-root caller
// refused with ErrRollbackTenantUnverifiable, never served unchecked.
func NewRollbackManager(
	gitManager git.GitManager,
	validator RollbackValidator,
	store RollbackStore,
	notifier RollbackNotifier,
	tenants TargetTenantResolver,
) RollbackManager {
	return &DefaultRollbackManager{
		gitManager: gitManager,
		validator:  validator,
		store:      store,
		notifier:   notifier,
		tenants:    tenants,
	}
}

// ListRollbackPoints returns available rollback points for a target
func (m *DefaultRollbackManager) ListRollbackPoints(ctx context.Context, targetType TargetType, targetID string, limit int) ([]RollbackPoint, error) {
	// Bound the disclosure to the caller's tenant subtree before any history is
	// read (Issue #4340). Each point built below carries the target's commit SHA,
	// commit message, operator name and email, change ID and the configuration
	// paths that commit touched, so the target's owning tenant has to contain the
	// caller first.
	if _, err := m.authorizeTarget(ctx, targetType, targetID); err != nil {
		return nil, err
	}

	// Get the repository for this target
	repoID, err := m.getRepositoryID(ctx, targetType, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	// Get commit history from Git
	commits, err := m.gitManager.GetCommitHistory(ctx, repoID, "", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %w", err)
	}

	// Convert commits to rollback points
	points := make([]RollbackPoint, 0, len(commits))
	for _, commit := range commits {
		// Get affected configurations
		configs := make([]string, 0, len(commit.Files))
		for _, file := range commit.Files {
			if m.isConfigurationFile(file.Path) {
				configs = append(configs, file.Path)
			}
		}

		// Skip if no configuration files affected
		if len(configs) == 0 {
			continue
		}

		// Assess risk level based on changes
		riskLevel := m.assessCommitRisk(commit)

		// Check if we can rollback to this point
		canRollback := m.canRollbackToCommit(commit)

		point := RollbackPoint{
			CommitSHA:      commit.SHA,
			Timestamp:      commit.Timestamp,
			Author:         commit.Author.Name,
			Message:        commit.Message,
			Configurations: configs,
			RiskLevel:      riskLevel,
			CanRollback:    canRollback,
			Metadata: map[string]interface{}{
				"author_email": commit.Author.Email,
				"change_id":    commit.Metadata.ChangeID,
			},
		}

		points = append(points, point)
	}

	return points, nil
}

// PreviewRollback shows what will change in a rollback
func (m *DefaultRollbackManager) PreviewRollback(ctx context.Context, request RollbackRequest) (*RollbackPreview, error) {
	// Validate request
	if err := m.validateRequest(request); err != nil {
		return nil, err
	}

	// Bound preview/execute to the requesting caller's tenant scope (Issue #4340):
	// a caller cannot preview or apply a rollback for a target outside its subtree.
	// The resolved tenant travels onto the preview and from there onto the
	// operation ExecuteRollback records.
	targetTenantID, err := m.authorizeTarget(ctx, request.TargetType, request.TargetID)
	if err != nil {
		return nil, err
	}

	// Get repository
	repoID, err := m.getRepositoryID(ctx, request.TargetType, request.TargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	// Get current commit
	currentCommits, err := m.gitManager.GetCommitHistory(ctx, repoID, "", 1)
	if err != nil || len(currentCommits) == 0 {
		return nil, fmt.Errorf("failed to get current commit: %w", err)
	}
	currentCommit := currentCommits[0].SHA

	// Get diff between current and target
	diffs, err := m.gitManager.GetDiff(ctx, repoID, request.RollbackTo, currentCommit)
	if err != nil {
		return nil, fmt.Errorf("failed to get diff: %w", err)
	}

	// Filter diffs based on rollback type
	changes := m.filterChanges(diffs, request)

	// Extract affected modules
	modules := m.extractAffectedModules(changes)

	// Validate the rollback
	validationResults, err := m.validator.ValidateRollback(ctx, request, nil)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Assess risk
	riskAssessment, err := m.validator.AssessRisk(ctx, request, changes)
	if err != nil {
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}

	// Determine if approval is required
	requiresApproval := m.requiresApproval(request, riskAssessment)

	// Estimate duration
	estimatedDuration := m.estimateDuration(request, len(changes))

	preview := &RollbackPreview{
		Changes:           changes,
		AffectedModules:   modules,
		ValidationResults: *validationResults,
		EstimatedDuration: estimatedDuration,
		RequiresApproval:  requiresApproval,
		RiskAssessment:    *riskAssessment,
		TargetTenantID:    targetTenantID,
	}

	return preview, nil
}

// ExecuteRollback performs the rollback operation
func (m *DefaultRollbackManager) ExecuteRollback(ctx context.Context, request RollbackRequest) (*RollbackOperation, error) {
	userID, err := m.getCurrentUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot execute rollback: %w", err)
	}

	// Bound the request to the caller's tenant before anything about the target is
	// disclosed (Issue #4340) — including whether a rollback is already running for
	// it, which the concurrency check below would otherwise reveal. PreviewRollback
	// repeats the check; running it here keeps the denial unwrapped so the API maps
	// it to 403 rather than to the generic preview failure.
	if _, err := m.authorizeTarget(ctx, request.TargetType, request.TargetID); err != nil {
		return nil, err
	}

	// Check for existing rollback in progress
	if err := m.checkNoRollbackInProgress(ctx, request.TargetType, request.TargetID); err != nil {
		return nil, err
	}

	// Preview the rollback first
	preview, err := m.PreviewRollback(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("preview failed: %w", err)
	}

	// Check validation results
	if !preview.ValidationResults.Passed && !request.Options.Force {
		return nil, validationFailure(&preview.ValidationResults)
	}

	// Check approval if required
	if preview.RequiresApproval && !request.Emergency {
		if request.ApprovalID == "" {
			return nil, &RollbackError{
				Code:    "APPROVAL_REQUIRED",
				Message: "This rollback requires approval",
			}
		}
		// Verify approval is valid
		if err := m.verifyApproval(ctx, request.ApprovalID); err != nil {
			return nil, err
		}
	}

	// Create rollback operation
	operation := &RollbackOperation{
		ID:          uuid.New().String(),
		Request:     request,
		Status:      RollbackStatusPending,
		InitiatedBy: userID,
		InitiatedAt: time.Now(),
		Progress: RollbackProgress{
			Stage:      "initializing",
			Percentage: 0,
		},
		AuditTrail:     []AuditEntry{},
		TargetTenantID: preview.TargetTenantID,
	}

	// Save operation
	if err := m.store.SaveOperation(ctx, operation); err != nil {
		return nil, fmt.Errorf("failed to save operation: %w", err)
	}

	// Add audit entry
	m.addAuditEntry(ctx, operation, "rollback_initiated", "Rollback operation initiated", nil)

	// Notify rollback started
	if err := m.notifier.NotifyRollbackStarted(ctx, operation); err != nil {
		// Log but don't fail
		m.addAuditEntry(ctx, operation, "notification_failed", "Failed to send start notification", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Execute rollback asynchronously
	// #nosec G118 -- rollback is a persisted durable operation that must survive
	// the initiating request; executeRollbackAsync enforces step timeouts/status.
	go m.executeRollbackAsync(context.Background(), operation, preview)

	return operation, nil
}

// GetRollbackStatus returns the current status of a rollback operation
func (m *DefaultRollbackManager) GetRollbackStatus(ctx context.Context, rollbackID string) (*RollbackOperation, error) {
	operation, err := m.store.GetOperation(ctx, rollbackID)
	if err != nil {
		return nil, err
	}

	if operation == nil {
		return nil, ErrRollbackNotFound
	}

	// Bound status reads to the caller's tenant scope (Issue #4340): the operation
	// discloses who initiated it, the original request and the complete audit trail,
	// and the rollback ID is the only thing standing between a tenant-scoped caller
	// and another tenant's copy of all three.
	if err := m.authorizeOperation(ctx, operation); err != nil {
		return nil, err
	}

	return operation, nil
}

// CancelRollback cancels an in-progress rollback
func (m *DefaultRollbackManager) CancelRollback(ctx context.Context, rollbackID string, reason string) error {
	userID, err := m.getCurrentUser(ctx)
	if err != nil {
		return fmt.Errorf("cannot cancel rollback: %w", err)
	}

	operation, err := m.store.GetOperation(ctx, rollbackID)
	if err != nil {
		return err
	}

	if operation == nil {
		return ErrRollbackNotFound
	}

	// Bound cancellation to the requesting caller's tenant scope (Issue #4340):
	// a caller cannot cancel a rollback for a target outside its subtree.
	if err := m.authorizeOperation(ctx, operation); err != nil {
		return err
	}

	// Check if rollback can be cancelled
	if operation.Status != RollbackStatusPending &&
		operation.Status != RollbackStatusValidating &&
		operation.Status != RollbackStatusApprovalRequired {
		return &RollbackError{
			Code:    "CANNOT_CANCEL",
			Message: fmt.Sprintf("Cannot cancel rollback in status: %s", operation.Status),
		}
	}

	// Update status
	operation.Status = RollbackStatusCancelled
	now := time.Now()
	operation.CompletedAt = &now

	// Add audit entry
	m.addAuditEntry(ctx, operation, "rollback_cancelled", reason, map[string]interface{}{
		"cancelled_by": userID,
	})

	// Update operation
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		return fmt.Errorf("failed to update operation: %w", err)
	}

	return nil
}

// ListRollbackHistory returns past rollback operations
func (m *DefaultRollbackManager) ListRollbackHistory(ctx context.Context, targetType TargetType, targetID string, limit int) ([]RollbackOperation, error) {
	filters := RollbackFilters{
		TargetType: targetType,
		TargetID:   targetID,
		Limit:      limit,
	}

	operations, err := m.store.ListOperations(ctx, filters)
	if err != nil {
		return nil, err
	}

	// Bound enumeration to the caller's tenant subtree (Issue #4340). targetID is
	// itself the enumeration key here — unlike GetRollbackStatus no rollback ID has
	// to be guessed — so a caller supplying another tenant's steward or device ID
	// would otherwise receive that tenant's operations with their full audit trails.
	// Operations are filtered rather than the whole call rejected so that a target
	// whose operations span tenants (a device reassigned between clients keeps its
	// earlier operations) returns the caller's own history instead of an error.
	visible := make([]RollbackOperation, 0, len(operations))
	for i := range operations {
		if err := m.authorizeOperation(ctx, &operations[i]); err != nil {
			continue
		}
		visible = append(visible, operations[i])
	}

	return visible, nil
}

// Helper methods

// validationFailure maps failed validation results onto the rollback error that describes
// them. A caller the RBAC manager refused is denied, not malformed, so the refusal keeps
// its own error code (surfaced by the API as 403) instead of collapsing into the generic
// validation failure (422).
func validationFailure(results *ValidationResults) *RollbackError {
	for _, issue := range results.Errors {
		if issue.Type == ValidationIssuePermission {
			return ErrRollbackPermissionDenied
		}
	}

	return ErrRollbackValidationFailed
}

func (m *DefaultRollbackManager) executeRollbackAsync(ctx context.Context, operation *RollbackOperation, preview *RollbackPreview) {
	// Update status to validating
	operation.Status = RollbackStatusValidating
	operation.Progress.Stage = "validating"
	operation.Progress.Percentage = 10
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue - operation state updates are best effort
		_ = err // Explicitly ignore error for best effort operation
	}

	// Perform final validation
	validationResults, err := m.validator.ValidateRollback(ctx, operation.Request, preview)
	if err != nil {
		m.failRollback(ctx, operation, fmt.Errorf("validation failed: %w", err))
		return
	}

	if !validationResults.Passed && !operation.Request.Options.Force {
		m.failRollback(ctx, operation, validationFailure(validationResults))
		return
	}

	// Update status to in progress
	operation.Status = RollbackStatusInProgress
	operation.Progress.Stage = "executing"
	operation.Progress.Percentage = 20
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue - operation state updates are best effort
		_ = err // Explicitly ignore error for best effort operation
	}
	if err := m.notifier.NotifyRollbackProgress(ctx, operation); err != nil {
		// Log error but continue - notifications are best effort
		_ = err // Explicitly ignore error for best effort operation
	}

	// Get repository
	repoID, err := m.getRepositoryID(ctx, operation.Request.TargetType, operation.Request.TargetID)
	if err != nil {
		m.failRollback(ctx, operation, err)
		return
	}

	// Create rollback branch
	branchName := fmt.Sprintf("rollback-%s-%s", operation.ID, time.Now().Format("20060102-150405"))
	if err := m.gitManager.CreateBranch(ctx, repoID, branchName, operation.Request.RollbackTo); err != nil {
		m.failRollback(ctx, operation, fmt.Errorf("failed to create rollback branch: %w", err))
		return
	}

	// Update progress
	operation.Progress.Stage = "applying_changes"
	operation.Progress.Percentage = 40
	operation.Progress.ItemsTotal = len(preview.Changes)
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue - operation state updates are best effort
		_ = err // Explicitly ignore error for best effort operation
	}

	// Apply changes
	failures := []RollbackFailure{}
	successCount := 0

	for i, change := range preview.Changes {
		// Update progress
		operation.Progress.ItemsProcessed = i + 1
		operation.Progress.Percentage = 40 + (40 * (i + 1) / len(preview.Changes))
		operation.Progress.CurrentAction = fmt.Sprintf("Applying %s", change.Path)
		if err := m.store.UpdateOperation(ctx, operation); err != nil {
			// Log error but continue rollback operation
			_ = err // Explicitly ignore store errors during rollback
		}

		// Apply the change
		if err := m.applyChange(ctx, repoID, branchName, change); err != nil {
			failures = append(failures, RollbackFailure{
				Component:   change.Path,
				Error:       err.Error(),
				Timestamp:   time.Now(),
				Recoverable: false,
				RetryCount:  1,
			})

			// If not forcing, fail on first error
			if !operation.Request.Options.Force {
				m.failRollback(ctx, operation, fmt.Errorf("failed to apply change %s: %w", change.Path, err))
				return
			}
		} else {
			successCount++
		}
	}

	// Merge rollback branch
	operation.Progress.Stage = "merging"
	operation.Progress.Percentage = 85
	operation.Progress.CurrentAction = "Merging rollback changes"
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue rollback operation
		_ = err // Explicitly ignore store errors during rollback
	}

	if err := m.gitManager.MergeBranch(ctx, repoID, branchName, "main", fmt.Sprintf("Rollback to %s", operation.Request.RollbackTo)); err != nil {
		m.failRollback(ctx, operation, fmt.Errorf("failed to merge rollback: %w", err))
		return
	}

	// Deploy to devices (would integrate with Steward here)
	operation.Progress.Stage = "deploying"
	operation.Progress.Percentage = 90
	operation.Progress.CurrentAction = "Deploying to devices"
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue rollback operation
		_ = err // Explicitly ignore store errors during rollback
	}

	// Simulate deployment
	time.Sleep(2 * time.Second)

	// Complete rollback
	operation.Status = RollbackStatusCompleted
	now := time.Now()
	operation.CompletedAt = &now
	operation.Progress.Stage = "completed"
	operation.Progress.Percentage = 100

	operation.Result = &RollbackResult{
		Success:                  len(failures) == 0,
		ConfigurationsRolledBack: successCount,
		DevicesAffected:          1, // Would get from actual deployment
		PartialSuccess:           len(failures) > 0 && successCount > 0,
		Failures:                 failures,
		Metrics: RollbackMetrics{
			Duration:           time.Since(operation.InitiatedAt),
			ValidationDuration: 10 * time.Second, // Would measure actual
			DeploymentDuration: 2 * time.Second,  // Would measure actual
		},
	}

	// Final update
	if err := m.store.UpdateOperation(ctx, operation); err != nil {
		// Log error but continue - operation state updates are best effort
		_ = err // Explicitly ignore error for best effort operation
	}
	m.addAuditEntry(ctx, operation, "rollback_completed", "Rollback completed successfully", nil)
	if err := m.notifier.NotifyRollbackCompleted(ctx, operation); err != nil {
		// Log error but continue - notifications are best effort
		_ = err // Explicitly ignore notification errors for best effort operation
	}
}

func (m *DefaultRollbackManager) failRollback(ctx context.Context, operation *RollbackOperation, err error) {
	operation.Status = RollbackStatusFailed
	now := time.Now()
	operation.CompletedAt = &now

	operation.Result = &RollbackResult{
		Success: false,
		Failures: []RollbackFailure{{
			Component:   "rollback_manager",
			Error:       err.Error(),
			Timestamp:   time.Now(),
			Recoverable: false,
		}},
		Metrics: RollbackMetrics{
			Duration: time.Since(operation.InitiatedAt),
		},
	}

	if storeErr := m.store.UpdateOperation(ctx, operation); storeErr != nil {
		// Log error but continue - operation state updates are best effort
		_ = storeErr // Explicitly ignore store errors for best effort operation
	}
	m.addAuditEntry(ctx, operation, "rollback_failed", err.Error(), nil)
	if notifyErr := m.notifier.NotifyRollbackFailed(ctx, operation, err); notifyErr != nil {
		// Log error but continue - notifications are best effort
		_ = notifyErr // Explicitly ignore notification errors for best effort operation
	}
}

func (m *DefaultRollbackManager) getRepositoryID(ctx context.Context, targetType TargetType, targetID string) (string, error) {
	// Repository ID is derived from target type and ID using a standard naming convention.
	switch targetType {
	case TargetTypeDevice:
		return fmt.Sprintf("device-%s-repo", targetID), nil
	case TargetTypeGroup:
		return fmt.Sprintf("group-%s-repo", targetID), nil
	case TargetTypeClient:
		return fmt.Sprintf("client-%s-repo", targetID), nil
	case TargetTypeMSP:
		return "msp-global-repo", nil
	default:
		return "", fmt.Errorf("unknown target type: %s", targetType)
	}
}

func (m *DefaultRollbackManager) isConfigurationFile(path string) bool {
	// Check if file is a configuration file
	return strings.HasSuffix(path, ".yaml") ||
		strings.HasSuffix(path, ".yml") ||
		strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".toml")
}

func (m *DefaultRollbackManager) assessCommitRisk(commit *git.Commit) RiskLevel {
	// Simple risk assessment based on number of files changed
	fileCount := len(commit.Files)

	if fileCount == 1 {
		return RiskLevelLow
	} else if fileCount <= 5 {
		return RiskLevelMedium
	} else if fileCount <= 10 {
		return RiskLevelHigh
	}

	return RiskLevelCritical
}

func (m *DefaultRollbackManager) canRollbackToCommit(commit *git.Commit) bool {
	// Check if commit has rollback info
	if commit.Metadata.RollbackInfo != nil {
		return commit.Metadata.RollbackInfo.CanRollback
	}

	// Design decision: rollback feasibility defaults to true; pre-conditions are validated by the validator, not the feasibility check.
	return true
}

func (m *DefaultRollbackManager) validateRequest(request RollbackRequest) error {
	if request.TargetID == "" {
		return fmt.Errorf("target ID is required")
	}

	if request.RollbackTo == "" {
		return fmt.Errorf("rollback target commit is required")
	}

	if request.Reason == "" && !request.Emergency {
		return fmt.Errorf("reason is required for non-emergency rollbacks")
	}

	return nil
}

func (m *DefaultRollbackManager) filterChanges(diffs []git.ConfigChange, request RollbackRequest) []ConfigurationChange {
	changes := []ConfigurationChange{}

	for _, diff := range diffs {
		// Filter based on rollback type
		switch request.RollbackType {
		case RollbackTypePartial:
			// Only include specified configurations
			include := false
			for _, config := range request.Configurations {
				if diff.Path == config {
					include = true
					break
				}
			}
			if !include {
				continue
			}

		case RollbackTypeModule:
			// Only include specified modules
			module := m.extractModuleFromPath(diff.Path)
			include := false
			for _, mod := range request.Modules {
				if module == mod {
					include = true
					break
				}
			}
			if !include {
				continue
			}
		}

		change := ConfigurationChange{
			Path:            diff.Path,
			CurrentVersion:  "current", // Would get actual SHA
			RollbackVersion: request.RollbackTo,
			Diff:            string(diff.NewContent), // Would generate actual diff
			Risk:            RiskLevelMedium,         // Would assess actual risk
			Module:          m.extractModuleFromPath(diff.Path),
		}

		changes = append(changes, change)
	}

	return changes
}

func (m *DefaultRollbackManager) extractModuleFromPath(path string) string {
	// Extract module name from path
	// e.g., "modules/firewall/config.yaml" -> "firewall"
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "modules" {
		return parts[1]
	}
	return ""
}

func (m *DefaultRollbackManager) extractAffectedModules(changes []ConfigurationChange) []string {
	moduleMap := make(map[string]bool)

	for _, change := range changes {
		if change.Module != "" {
			moduleMap[change.Module] = true
		}
	}

	modules := make([]string, 0, len(moduleMap))
	for module := range moduleMap {
		modules = append(modules, module)
	}

	return modules
}

func (m *DefaultRollbackManager) requiresApproval(request RollbackRequest, risk *RiskAssessment) bool {
	// Emergency rollbacks bypass approval
	if request.Emergency {
		return false
	}

	// High risk always requires approval
	if risk.OverallRisk == RiskLevelHigh || risk.OverallRisk == RiskLevelCritical {
		return true
	}

	// Data loss risk requires approval
	if risk.DataLossRisk {
		return true
	}

	// Large impact requires approval
	if risk.AffectedUsers > 100 {
		return true
	}

	return false
}

func (m *DefaultRollbackManager) estimateDuration(request RollbackRequest, changeCount int) time.Duration {
	// Base duration
	duration := 30 * time.Second

	// Add time per change
	duration += time.Duration(changeCount) * 5 * time.Second

	// Add time for validation
	duration += 10 * time.Second

	// Progressive rollback takes longer
	if request.Options.Progressive {
		duration *= 2
	}

	return duration
}

func (m *DefaultRollbackManager) checkNoRollbackInProgress(ctx context.Context, targetType TargetType, targetID string) error {
	// Check for active rollbacks
	filters := RollbackFilters{
		TargetType: targetType,
		TargetID:   targetID,
		Status:     RollbackStatusInProgress,
		Limit:      1,
	}

	operations, err := m.store.ListOperations(ctx, filters)
	if err != nil {
		return fmt.Errorf("failed to check for active rollbacks: %w", err)
	}

	if len(operations) > 0 {
		return ErrRollbackInProgress
	}

	return nil
}

func (m *DefaultRollbackManager) verifyApproval(ctx context.Context, approvalID string) error {
	if approvalID == "" {
		return &RollbackError{
			Code:    "INVALID_APPROVAL",
			Message: "Invalid approval ID",
		}
	}

	return nil
}

// authorizeTarget answers "may this caller act on (targetType, targetID)" and
// returns the tenant that owns the target (Issue #4340).
//
// The owning tenant comes from the TargetTenantResolver — the controller's
// steward registry — and never from data the caller supplied or from metadata on
// the target's Git history: Git commits carry no tenant, so a check reading them
// would allow every caller. Enforcement is fail-closed in all three directions:
// a caller with no resolver wired is refused, a target the registry does not own
// is refused, and a caller whose scope is unset (never established by the
// authentication middleware) is refused. Root scope always allows and still
// receives the resolved tenant so it is recorded on the operation.
func (m *DefaultRollbackManager) authorizeTarget(ctx context.Context, targetType TargetType, targetID string) (string, error) {
	tenantID, known := m.resolveTargetTenant(ctx, targetType, targetID)

	scope, _ := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if scope.IsRoot() {
		return tenantID, nil
	}
	if m.tenants == nil {
		return "", ErrRollbackTenantUnverifiable
	}
	if !known {
		return "", ErrRollbackOutsideTenantScope
	}
	if err := authorizeTenant(scope, tenantID); err != nil {
		return "", err
	}

	return tenantID, nil
}

// authorizeOperation bounds a recorded operation to the caller's tenant scope.
//
// The tenant recorded on the operation wins: an operation is a historical record
// that belongs to the tenant which owned the target when it ran, so a device
// reassigned between clients does not hand its previous owner's audit trail to
// its new one. Operations written before the tenant was recorded carry an empty
// value and fall back to resolving the target's owner live. With neither
// available the operation stays invisible to every caller but root.
func (m *DefaultRollbackManager) authorizeOperation(ctx context.Context, operation *RollbackOperation) error {
	scope, _ := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if scope.IsRoot() {
		return nil
	}
	if m.tenants == nil {
		return ErrRollbackTenantUnverifiable
	}

	tenantID := operation.TargetTenantID
	if tenantID == "" {
		tenantID, _ = m.resolveTargetTenant(ctx, operation.Request.TargetType, operation.Request.TargetID)
	}

	return authorizeTenant(scope, tenantID)
}

// resolveTargetTenant asks the wired resolver which tenant owns the target.
// known is false when no resolver is wired, when the registry does not hold the
// target, or when it holds the target with no tenant recorded — all three are
// "ownership not established", which authorizeTarget and authorizeOperation
// treat as outside every tenant.
func (m *DefaultRollbackManager) resolveTargetTenant(ctx context.Context, targetType TargetType, targetID string) (string, bool) {
	if m.tenants == nil {
		return "", false
	}

	tenantID, known := m.tenants.TenantForTarget(ctx, targetType, targetID)
	if !known || tenantID == "" {
		return "", false
	}

	return tenantID, true
}

// authorizeTenant reports whether scope contains resourceTenant. An unset scope
// is never treated as unrestricted (ctxkeys.TenantScope semantics, Issue #4316),
// and an empty resourceTenant is never treated as "nothing to enforce": both are
// denied, so a lost caller scope or an unresolved target closes the door instead
// of opening it.
func authorizeTenant(scope ctxkeys.TenantScope, resourceTenant string) error {
	if resourceTenant == "" {
		return ErrRollbackOutsideTenantScope
	}
	if scope.IsRoot() {
		return nil
	}
	if scope.IsTenant() && scope.Path() != "" &&
		(resourceTenant == scope.Path() || strings.HasPrefix(resourceTenant, scope.Path()+"/")) {
		return nil
	}

	return ErrRollbackOutsideTenantScope
}

func (m *DefaultRollbackManager) getCurrentUser(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(ctxkeys.UserIDKey).(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("unauthenticated: no user identity in context")
	}
	return userID, nil
}

func (m *DefaultRollbackManager) addAuditEntry(ctx context.Context, operation *RollbackOperation, eventType, action string, details map[string]interface{}) {
	actor, err := m.getCurrentUser(ctx)
	if err != nil {
		// Async operations run with context.Background(); use the authenticated initiator recorded at operation start.
		actor = operation.InitiatedBy
	}
	entry := AuditEntry{
		Timestamp: time.Now(),
		EventType: eventType,
		Actor:     actor,
		Action:    action,
		Details:   details,
		Result:    "success",
	}

	operation.AuditTrail = append(operation.AuditTrail, entry)
	if err := m.store.AddAuditEntry(ctx, operation.ID, entry); err != nil {
		// Log error but continue - audit entries are best effort
		_ = err // Explicitly ignore audit storage errors for best effort operation
	}
}

func (m *DefaultRollbackManager) applyChange(ctx context.Context, repoID, branch string, change ConfigurationChange) error {
	// Get the configuration at the rollback version
	ref := git.ConfigurationRef{
		RepositoryID: repoID,
		Branch:       branch,
		Path:         change.Path,
		Commit:       change.RollbackVersion,
	}

	config, err := m.gitManager.GetConfiguration(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to get rollback configuration: %w", err)
	}

	// Save it to the current branch
	saveRef := git.ConfigurationRef{
		RepositoryID: repoID,
		Branch:       branch,
		Path:         change.Path,
	}

	message := fmt.Sprintf("Rollback %s to version %s", change.Path, change.RollbackVersion)
	if err := m.gitManager.SaveConfiguration(ctx, saveRef, config, message); err != nil {
		return fmt.Errorf("failed to save rollback configuration: %w", err)
	}

	return nil
}
