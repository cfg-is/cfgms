package git

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultSyncManager implements the SyncManager interface
type DefaultSyncManager struct {
	gitManager GitManager
	store      RepositoryStore
}

// NewSyncManager creates a new sync manager
func NewSyncManager(gitManager GitManager, store RepositoryStore) SyncManager {
	return &DefaultSyncManager{
		gitManager: gitManager,
		store:      store,
	}
}

// SyncTemplates synchronizes templates from parent repository to client repository
func (m *DefaultSyncManager) SyncTemplates(ctx context.Context, parentRepo, clientRepo *Repository) error {
	// Read client repository inheritance configuration
	inheritance, err := m.readInheritanceConfig(ctx, clientRepo)
	if err != nil {
		return fmt.Errorf("failed to read inheritance config: %w", err)
	}

	// Check for updates in each inherited template
	updates := []TemplateUpdate{}
	for _, templateRef := range inheritance.Templates {
		// Skip if repository doesn't match
		if !strings.Contains(parentRepo.Name, templateRef.Repository) {
			continue
		}

		// Check if template has updates
		update, hasUpdate, err := m.checkTemplateUpdate(ctx, parentRepo, clientRepo, templateRef)
		if err != nil {
			return fmt.Errorf("failed to check template %s: %w", templateRef.Path, err)
		}

		if hasUpdate {
			updates = append(updates, update)
		}
	}

	// Apply updates if any
	if len(updates) > 0 {
		// Create a feature branch for the updates
		branchName := fmt.Sprintf("template-sync-%s", time.Now().Format("20060102-150405"))
		if err := m.gitManager.CreateBranch(ctx, clientRepo.ID, branchName, ""); err != nil {
			return fmt.Errorf("failed to create sync branch: %w", err)
		}

		// Apply each update
		for _, update := range updates {
			if err := m.applyTemplateUpdate(ctx, parentRepo, clientRepo, update); err != nil {
				return fmt.Errorf("failed to apply template update %s: %w", update.Template.Path, err)
			}
		}

		// Create pull request for review
		prConfig := PullRequestConfig{
			Title:        "Template synchronization from MSP global repository",
			Description:  m.generateSyncDescription(updates),
			SourceBranch: branchName,
			TargetBranch: clientRepo.DefaultBranch,
			Labels:       []string{"template-sync", "automated"},
		}

		_, err = m.gitManager.CreatePullRequest(ctx, clientRepo.ID, prConfig)
		if err != nil {
			return fmt.Errorf("failed to create pull request: %w", err)
		}
	}

	return nil
}

// PropagateChange propagates a change across multiple repositories
func (m *DefaultSyncManager) PropagateChange(ctx context.Context, change ChangeSet, targetRepos []*Repository) error {
	results := make(chan error, len(targetRepos))

	// Process each repository concurrently
	for _, repo := range targetRepos {
		go func(r *Repository) {
			results <- m.propagateToRepository(ctx, change, r)
		}(repo)
	}

	// Collect results
	var errors []error
	for i := 0; i < len(targetRepos); i++ {
		if err := <-results; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("propagation failed in %d repositories", len(errors))
	}

	return nil
}

// CheckTemplateUpdates checks for available template updates
func (m *DefaultSyncManager) CheckTemplateUpdates(ctx context.Context, clientRepo *Repository) ([]TemplateUpdate, error) {
	// Get parent repository
	parentRepos, err := m.gitManager.ListRepositories(ctx, RepositoryFilter{
		Type:  RepositoryTypeMSPGlobal,
		Owner: clientRepo.Owner,
	})
	if err != nil || len(parentRepos) == 0 {
		return nil, fmt.Errorf("parent repository not found")
	}

	parentRepo := parentRepos[0]

	// Read inheritance configuration
	inheritance, err := m.readInheritanceConfig(ctx, clientRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to read inheritance config: %w", err)
	}

	// Check each template for updates
	var updates []TemplateUpdate
	for _, templateRef := range inheritance.Templates {
		update, hasUpdate, err := m.checkTemplateUpdate(ctx, parentRepo, clientRepo, templateRef)
		if err != nil {
			continue // Log but don't fail entire check
		}

		if hasUpdate {
			updates = append(updates, update)
		}
	}

	return updates, nil
}

// ApplyTemplateUpdates applies template updates to a client repository
func (m *DefaultSyncManager) ApplyTemplateUpdates(ctx context.Context, clientRepo *Repository, updates []TemplateUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	// Get parent repository
	parentRepos, err := m.gitManager.ListRepositories(ctx, RepositoryFilter{
		Type:  RepositoryTypeMSPGlobal,
		Owner: clientRepo.Owner,
	})
	if err != nil || len(parentRepos) == 0 {
		return fmt.Errorf("parent repository not found")
	}

	parentRepo := parentRepos[0]

	// Apply each update
	for _, update := range updates {
		if err := m.applyTemplateUpdate(ctx, parentRepo, clientRepo, update); err != nil {
			return fmt.Errorf("failed to apply update for %s: %w", update.Template.Path, err)
		}
	}

	return nil
}

// Helper methods

// InheritanceConfig represents the inheritance configuration
type InheritanceConfig struct {
	Templates []TemplateReference `yaml:"templates"`
	Policies  []PolicyReference   `yaml:"policies"`
}

// PolicyReference references a policy in another repository
type PolicyReference struct {
	Repository    string        `yaml:"repository"`
	Path          string        `yaml:"path"`
	MergeStrategy MergeStrategy `yaml:"merge_strategy"`
}

func (m *DefaultSyncManager) readInheritanceConfig(ctx context.Context, repo *Repository) (*InheritanceConfig, error) {
	// Read the inheritance configuration file
	ref := ConfigurationRef{
		RepositoryID: repo.ID,
		Path:         ".cfgms/inheritance.yaml",
	}

	config, err := m.gitManager.GetConfiguration(ctx, ref)
	if err != nil {
		// No inheritance config is valid - just means no templates to sync
		return &InheritanceConfig{}, nil
	}

	var inheritance InheritanceConfig
	if err := yaml.Unmarshal(config.Content, &inheritance); err != nil {
		return nil, fmt.Errorf("failed to parse inheritance config: %w", err)
	}

	return &inheritance, nil
}

func (m *DefaultSyncManager) checkTemplateUpdate(ctx context.Context, parentRepo, clientRepo *Repository, templateRef TemplateReference) (TemplateUpdate, bool, error) {
	// Get template from parent repository
	parentRef := ConfigurationRef{
		RepositoryID: parentRepo.ID,
		Path:         templateRef.Path,
	}

	parentConfig, err := m.gitManager.GetConfiguration(ctx, parentRef)
	if err != nil {
		return TemplateUpdate{}, false, fmt.Errorf("template not found in parent repository: %w", err)
	}

	// Get current version in client repository
	clientPath := m.getClientTemplatePath(templateRef.Path)
	clientRef := ConfigurationRef{
		RepositoryID: clientRepo.ID,
		Path:         clientPath,
	}

	clientConfig, err := m.gitManager.GetConfiguration(ctx, clientRef)
	if err != nil {
		// Template doesn't exist in client repo - this is an update
		return TemplateUpdate{
			Template:       templateRef,
			CurrentVersion: "",
			NewVersion:     parentConfig.Metadata.Checksum,
			Changes:        "New template",
			Breaking:       false,
		}, true, nil
	}

	// Compare checksums
	if parentConfig.Metadata.Checksum != clientConfig.Metadata.Checksum {
		// Get diff to determine changes
		changes := m.summarizeChanges(clientConfig.Content, parentConfig.Content)

		return TemplateUpdate{
			Template:       templateRef,
			CurrentVersion: clientConfig.Metadata.Checksum,
			NewVersion:     parentConfig.Metadata.Checksum,
			Changes:        changes,
			Breaking:       m.isBreakingChange(clientConfig.Content, parentConfig.Content),
		}, true, nil
	}

	return TemplateUpdate{}, false, nil
}

func (m *DefaultSyncManager) applyTemplateUpdate(ctx context.Context, parentRepo, clientRepo *Repository, update TemplateUpdate) error {
	// Get template content from parent repository
	parentRef := ConfigurationRef{
		RepositoryID: parentRepo.ID,
		Path:         update.Template.Path,
	}

	parentConfig, err := m.gitManager.GetConfiguration(ctx, parentRef)
	if err != nil {
		return fmt.Errorf("failed to get template from parent: %w", err)
	}

	// Determine client path
	clientPath := m.getClientTemplatePath(update.Template.Path)

	// Apply based on merge strategy
	var finalContent []byte

	if update.Template.MergeStrategy == MergeStrategyDeep && update.CurrentVersion != "" {
		// Get current client content for merging
		clientRef := ConfigurationRef{
			RepositoryID: clientRepo.ID,
			Path:         clientPath,
		}

		clientConfig, err := m.gitManager.GetConfiguration(ctx, clientRef)
		if err == nil {
			// Perform deep merge
			finalContent, err = m.deepMergeConfigs(clientConfig.Content, parentConfig.Content, parentConfig.Format)
			if err != nil {
				return fmt.Errorf("failed to merge configurations: %w", err)
			}
		} else {
			// Fallback to replace if can't read current
			finalContent = parentConfig.Content
		}
	} else {
		// Replace strategy or new file
		finalContent = parentConfig.Content
	}

	// Save the updated configuration
	newConfig := &Configuration{
		Path:     clientPath,
		Content:  finalContent,
		Format:   parentConfig.Format,
		Metadata: parentConfig.Metadata,
	}

	clientRef := ConfigurationRef{
		RepositoryID: clientRepo.ID,
		Path:         clientPath,
	}

	message := fmt.Sprintf("Sync template %s from MSP global repository", update.Template.Path)
	return m.gitManager.SaveConfiguration(ctx, clientRef, newConfig, message)
}

func (m *DefaultSyncManager) propagateToRepository(ctx context.Context, change ChangeSet, repo *Repository) error {
	// Create a branch for the change
	branchName := fmt.Sprintf("propagate-%s", change.ID)
	if err := m.gitManager.CreateBranch(ctx, repo.ID, branchName, ""); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	// Apply each change in the changeset
	for _, ch := range change.Changes {
		if ch.Repository != repo.ID {
			continue
		}

		ref := ConfigurationRef{
			RepositoryID: repo.ID,
			Path:         ch.Path,
			Branch:       branchName,
		}

		switch ch.Action {
		case "create", "update":
			config := &Configuration{
				Path:    ch.Path,
				Content: ch.NewContent,
				Format:  m.getConfigFormat(ch.Path),
			}

			if err := m.gitManager.SaveConfiguration(ctx, ref, config, change.Description); err != nil {
				return fmt.Errorf("failed to save configuration: %w", err)
			}

		case "delete":
			if err := m.gitManager.DeleteConfiguration(ctx, ref, change.Description); err != nil {
				return fmt.Errorf("failed to delete configuration: %w", err)
			}
		}
	}

	// Create pull request
	prConfig := PullRequestConfig{
		Title:        fmt.Sprintf("Propagate: %s", change.Description),
		Description:  m.generatePropagateDescription(change),
		SourceBranch: branchName,
		TargetBranch: repo.DefaultBranch,
		Labels:       []string{"propagated", "automated"},
		AutoMerge:    true, // Auto-merge if all checks pass
	}

	_, err := m.gitManager.CreatePullRequest(ctx, repo.ID, prConfig)
	return err
}

func (m *DefaultSyncManager) getClientTemplatePath(templatePath string) string {
	// Templates are synced to the same relative path in client repos
	// but we could add path transformation logic here if needed
	return templatePath
}

func (m *DefaultSyncManager) summarizeChanges(oldContent, newContent []byte) string {
	// Simple line count comparison - in production this would be more sophisticated
	oldLines := strings.Split(string(oldContent), "\n")
	newLines := strings.Split(string(newContent), "\n")

	added := len(newLines) - len(oldLines)
	if added > 0 {
		return fmt.Sprintf("+%d lines", added)
	} else if added < 0 {
		return fmt.Sprintf("%d lines", added)
	}

	return "Content updated"
}

func (m *DefaultSyncManager) isBreakingChange(oldContent, newContent []byte) bool {
	// Simplified breaking change detection
	// In production, this would analyze the actual configuration schema

	// Check if any required fields were removed
	// Check if any field types changed
	// Check if any validation rules became stricter

	return false // Default to non-breaking
}

func (m *DefaultSyncManager) deepMergeConfigs(current, template []byte, format string) ([]byte, error) {
	// This is a simplified implementation
	// In production, you'd use proper YAML/JSON merging libraries

	switch format {
	case "yaml":
		var currentData, templateData map[string]interface{}

		if err := yaml.Unmarshal(current, &currentData); err != nil {
			return nil, fmt.Errorf("failed to parse current config: %w", err)
		}

		if err := yaml.Unmarshal(template, &templateData); err != nil {
			return nil, fmt.Errorf("failed to parse template config: %w", err)
		}

		// Deep merge template into current
		merged := m.deepMergeMap(currentData, templateData)

		// Marshal back to YAML
		result, err := yaml.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal merged config: %w", err)
		}

		return result, nil

	default:
		// For other formats, fall back to replace
		return template, nil
	}
}

func (m *DefaultSyncManager) deepMergeMap(current, template map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy all current values
	for k, v := range current {
		result[k] = v
	}

	// Merge template values
	for k, templateVal := range template {
		if currentVal, exists := result[k]; exists {
			// Both have the key - need to merge
			currentMap, currentIsMap := currentVal.(map[string]interface{})
			templateMap, templateIsMap := templateVal.(map[string]interface{})

			if currentIsMap && templateIsMap {
				// Both are maps - recurse
				result[k] = m.deepMergeMap(currentMap, templateMap)
			} else {
				// Not both maps - template wins
				result[k] = templateVal
			}
		} else {
			// Only template has the key
			result[k] = templateVal
		}
	}

	return result
}

func (m *DefaultSyncManager) generateSyncDescription(updates []TemplateUpdate) string {
	var lines []string
	lines = append(lines, "This pull request synchronizes templates from the MSP global repository.")
	lines = append(lines, "")
	lines = append(lines, "## Updates")

	for _, update := range updates {
		status := "Updated"
		if update.CurrentVersion == "" {
			status = "Added"
		}
		if update.Breaking {
			status += " ⚠️ BREAKING"
		}

		lines = append(lines, fmt.Sprintf("- **%s**: %s - %s", update.Template.Path, status, update.Changes))
	}

	lines = append(lines, "")
	lines = append(lines, "Please review these changes carefully before merging.")

	return strings.Join(lines, "\n")
}

func (m *DefaultSyncManager) generatePropagateDescription(change ChangeSet) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Change ID: %s", change.ID))
	lines = append(lines, fmt.Sprintf("Author: %s <%s>", change.Author.Name, change.Author.Email))
	lines = append(lines, "")
	lines = append(lines, "## Changes")

	for _, ch := range change.Changes {
		lines = append(lines, fmt.Sprintf("- %s: %s", ch.Action, ch.Path))
	}

	return strings.Join(lines, "\n")
}

func (m *DefaultSyncManager) getConfigFormat(path string) string {
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	default:
		return "unknown"
	}
}
