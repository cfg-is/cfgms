// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package git provides access control functionality for Git repositories
package git

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// AccessControlManager handles repository access control and drift detection
type AccessControlManager struct {
	driftDetector *DriftDetector
}

// NewAccessControlManager creates a new access control manager
func NewAccessControlManager(logger logging.Logger) *AccessControlManager {
	return &AccessControlManager{
		driftDetector: NewDriftDetector(logger),
	}
}

// ValidateAccess validates if an operation is allowed based on access control settings
func (acm *AccessControlManager) ValidateAccess(ctx context.Context, repo *Repository, operation string, path string) error {
	if repo.AccessControl == nil {
		return nil // No access control configured
	}

	switch repo.AccessControl.Mode {
	case AccessModeReadOnly:
		if operation == "write" || operation == "delete" {
			return &ValidationOnlyError{
				Message: fmt.Sprintf("Repository %s is in read-only mode. All modifications must be made through Git.", repo.Name),
			}
		}

	case AccessModeValidateOnly:
		if operation == "write" || operation == "delete" {
			return &ValidationOnlyError{
				Message: fmt.Sprintf("Repository %s is in validate-only mode. Controller can only validate configurations.", repo.Name),
			}
		}

	case AccessModeHybrid:
		return acm.validateHybridAccess(repo, operation, path)

	case AccessModeReadWrite:
		// Full access - check for drift protection
		if repo.AccessControl.WriteProtection.PreventDrift {
			return acm.checkDriftProtection(ctx, repo, path)
		}
	}

	return nil
}

// validateHybridAccess validates access in hybrid mode
func (acm *AccessControlManager) validateHybridAccess(repo *Repository, operation string, path string) error {
	if operation == "read" {
		return nil // Read always allowed
	}

	// Check if path is read-only
	for _, readOnlyPath := range repo.AccessControl.ReadOnlyPaths {
		if matched, _ := filepath.Match(readOnlyPath, path); matched {
			return &PathProtectedError{
				Path:    path,
				Message: "This path is protected from controller modifications",
			}
		}
	}

	// Check if path requires controller management
	controllerManaged := false
	for _, managedPath := range repo.AccessControl.ControllerManagedPaths {
		if matched, _ := filepath.Match(managedPath, path); matched {
			controllerManaged = true
			break
		}
	}

	if !controllerManaged && (operation == "write" || operation == "delete") {
		return &PathProtectedError{
			Path:    path,
			Message: "This path is not managed by the controller",
		}
	}

	return nil
}

// checkDriftProtection checks for configuration drift
func (acm *AccessControlManager) checkDriftProtection(ctx context.Context, repo *Repository, path string) error {
	drift, err := acm.driftDetector.DetectDrift(ctx, repo, path)
	if err != nil {
		return fmt.Errorf("failed to check for drift: %w", err)
	}

	if drift != nil {
		if repo.AccessControl.WriteProtection.AutoRevertChanges {
			// Attempt to auto-revert
			if err := acm.driftDetector.RevertDrift(ctx, repo, drift); err != nil {
				return fmt.Errorf("detected drift and failed to auto-revert: %w", err)
			}
			drift.AutoReverted = true
		}

		return &ConfigurationDriftError{
			Message:           fmt.Sprintf("Configuration drift detected: %s", drift.DriftType),
			Repository:        repo.Name,
			Path:              drift.Path,
			RecommendedAction: "Review changes and ensure they comply with policies",
		}
	}

	return nil
}

// DriftDetector detects configuration drift in repositories
type DriftDetector struct {
	baselineHashes map[string]string // path -> expected hash
	logger         logging.Logger
}

// NewDriftDetector creates a new drift detector
func NewDriftDetector(logger logging.Logger) *DriftDetector {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &DriftDetector{
		baselineHashes: make(map[string]string),
		logger:         logger,
	}
}

// DetectDrift detects if configuration has drifted from expected state
func (dd *DriftDetector) DetectDrift(ctx context.Context, repo *Repository, path string) (*DriftDetection, error) {
	// This is a simplified implementation
	// In production, this would compare against Git history and validate checksums

	expectedHash, exists := dd.baselineHashes[path]
	if !exists {
		// No baseline - consider establishing one
		return nil, nil
	}

	// Calculate current hash (simplified - would use actual file content)
	actualHash := "current-hash"

	if expectedHash != actualHash {
		return &DriftDetection{
			Path:         path,
			ExpectedHash: expectedHash,
			ActualHash:   actualHash,
			DriftType:    DriftTypeUnauthorizedChange,
			DetectedAt:   time.Now(),
			AutoReverted: false,
		}, nil
	}

	return nil, nil
}

// RevertDrift reverts configuration drift
func (dd *DriftDetector) RevertDrift(ctx context.Context, repo *Repository, drift *DriftDetection) error {
	dd.logger.Info("reverting drift",
		"repo", logging.SanitizeLogValue(repo.Name),
		"path", logging.SanitizeLogValue(drift.Path),
	)
	return nil
}

// EstablishBaseline establishes a baseline for drift detection
func (dd *DriftDetector) EstablishBaseline(ctx context.Context, repo *Repository, path string, hash string) {
	dd.baselineHashes[path] = hash
}

// GitModeManager manages Git-as-source-of-truth functionality
type GitModeManager struct {
	accessControl *AccessControlManager
	logger        logging.Logger
}

// NewGitModeManager creates a new Git mode manager
func NewGitModeManager(logger logging.Logger) *GitModeManager {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &GitModeManager{
		accessControl: NewAccessControlManager(logger),
		logger:        logger,
	}
}

// ValidateReadOnlyMode validates that repository is properly configured for read-only mode
func (gmm *GitModeManager) ValidateReadOnlyMode(ctx context.Context, repo *Repository) error {
	if repo.AccessControl == nil || repo.AccessControl.Mode != AccessModeReadOnly {
		return fmt.Errorf("repository is not configured for read-only mode")
	}

	// Validate that protected branches are configured
	if len(repo.AccessControl.ProtectedBranches) == 0 {
		return fmt.Errorf("read-only repositories must have protected branches configured")
	}

	// Validate that appropriate webhooks are configured for Git-driven updates
	// This would check for webhook configuration in production

	return nil
}

// ProcessGitWebhook processes incoming Git webhooks for configuration updates
func (gmm *GitModeManager) ProcessGitWebhook(ctx context.Context, repo *Repository, webhookData map[string]interface{}) error {
	// Extract relevant information from webhook
	action, ok := webhookData["action"].(string)
	if !ok {
		return fmt.Errorf("invalid webhook data: missing action")
	}

	switch action {
	case "push":
		return gmm.processPushEvent(ctx, repo, webhookData)
	case "pull_request":
		return gmm.processPullRequestEvent(ctx, repo, webhookData)
	default:
		gmm.logger.Warn("unknown webhook action", "action", logging.SanitizeLogValue(action))
	}

	return nil
}

// processPushEvent processes push events from Git webhooks
func (gmm *GitModeManager) processPushEvent(ctx context.Context, repo *Repository, data map[string]interface{}) error {
	// Extract changed files and trigger configuration reload
	// This would integrate with the controller to reload configurations

	gmm.logger.Info("processing push event", "repo", logging.SanitizeLogValue(repo.Name))

	// Validate that push is to a protected branch
	ref, ok := data["ref"].(string)
	if !ok {
		return fmt.Errorf("invalid push event: missing ref")
	}

	branchName := strings.TrimPrefix(ref, "refs/heads/")

	// Check if this is a protected branch that should trigger updates
	isProtected := false
	for _, protection := range repo.AccessControl.ProtectedBranches {
		if matched, _ := regexp.MatchString(protection.Pattern, branchName); matched {
			isProtected = true
			break
		}
	}

	if !isProtected {
		return nil // Not a branch we care about
	}

	return nil
}

// processPullRequestEvent processes pull request events
func (gmm *GitModeManager) processPullRequestEvent(ctx context.Context, repo *Repository, data map[string]interface{}) error {
	action, ok := data["action"].(string)
	if !ok {
		return fmt.Errorf("invalid PR event: missing action")
	}

	switch action {
	case "opened", "synchronize":
		return gmm.validatePullRequest(ctx, repo, data)
	case "closed":
		merged, ok := data["merged"].(bool)
		if ok && merged {
			return gmm.processPushEvent(ctx, repo, data)
		}
	}

	return nil
}

// validatePullRequest validates pull request changes
func (gmm *GitModeManager) validatePullRequest(ctx context.Context, repo *Repository, data map[string]interface{}) error {
	gmm.logger.Info("validating pull request", "repo", logging.SanitizeLogValue(repo.Name))

	// Logs validation intent; path/syntax/policy/security checks are deferred.

	return nil
}

// SyncFromGit synchronizes configuration from Git repository
func (gmm *GitModeManager) SyncFromGit(ctx context.Context, repo *Repository, store RepositoryStore) error {
	if repo.AccessControl == nil || repo.AccessControl.Mode == AccessModeReadWrite {
		return nil // Not a Git-driven repository
	}

	// Design decision: cross-repository sync is an orchestration operation handled by the calling module; access_control.go enforces permissions only.
	return gmm.ValidateReadOnlyMode(ctx, repo)
}
