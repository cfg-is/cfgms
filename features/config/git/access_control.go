// Package git provides access control functionality for Git repositories
package git

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AccessControlManager handles repository access control and drift detection
type AccessControlManager struct {
	driftDetector *DriftDetector
}

// NewAccessControlManager creates a new access control manager
func NewAccessControlManager() *AccessControlManager {
	return &AccessControlManager{
		driftDetector: NewDriftDetector(),
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
}

// NewDriftDetector creates a new drift detector
func NewDriftDetector() *DriftDetector {
	return &DriftDetector{
		baselineHashes: make(map[string]string),
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
	actualHash := "current-hash" // TODO: Calculate actual hash
	
	if expectedHash != actualHash {
		return &DriftDetection{
			Path:           path,
			ExpectedHash:   expectedHash,
			ActualHash:     actualHash,
			DriftType:      DriftTypeUnauthorizedChange,
			DetectedAt:     time.Now(),
			AutoReverted:   false,
		}, nil
	}
	
	return nil, nil
}

// RevertDrift reverts configuration drift
func (dd *DriftDetector) RevertDrift(ctx context.Context, repo *Repository, drift *DriftDetection) error {
	// This would implement the actual revert logic
	// For now, just log the action
	fmt.Printf("Reverting drift in %s at path %s\n", repo.Name, drift.Path)
	return nil
}

// EstablishBaseline establishes a baseline for drift detection
func (dd *DriftDetector) EstablishBaseline(ctx context.Context, repo *Repository, path string, hash string) {
	dd.baselineHashes[path] = hash
}

// GitModeManager manages Git-as-source-of-truth functionality
type GitModeManager struct {
	accessControl *AccessControlManager
}

// NewGitModeManager creates a new Git mode manager
func NewGitModeManager() *GitModeManager {
	return &GitModeManager{
		accessControl: NewAccessControlManager(),
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
		// Log but don't error on unknown actions
		fmt.Printf("Unknown webhook action: %s\n", action)
	}
	
	return nil
}

// processPushEvent processes push events from Git webhooks
func (gmm *GitModeManager) processPushEvent(ctx context.Context, repo *Repository, data map[string]interface{}) error {
	// Extract changed files and trigger configuration reload
	// This would integrate with the controller to reload configurations
	
	fmt.Printf("Processing push event for repository %s\n", repo.Name)
	
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
	
	// TODO: Trigger configuration reload in controller
	// This would notify the controller that configurations have changed
	
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
	// This would validate that PR changes comply with policies
	// For now, just log the validation
	
	fmt.Printf("Validating pull request for repository %s\n", repo.Name)
	
	// TODO: Implement actual validation logic
	// - Check that changes don't modify read-only paths
	// - Validate configuration syntax
	// - Check against policies
	// - Run security scans
	
	return nil
}

// SyncFromGit synchronizes configuration from Git repository
func (gmm *GitModeManager) SyncFromGit(ctx context.Context, repo *Repository, store RepositoryStore) error {
	if repo.AccessControl == nil || repo.AccessControl.Mode == AccessModeReadWrite {
		return nil // Not a Git-driven repository
	}
	
	// This would implement the actual sync logic
	// For now, just validate the mode
	return gmm.ValidateReadOnlyMode(ctx, repo)
}