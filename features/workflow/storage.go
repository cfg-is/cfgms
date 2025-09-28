package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"gopkg.in/yaml.v3"
)

// WorkflowStore handles workflow storage using the global storage provider system
type WorkflowStore struct {
	configStore interfaces.ConfigStore
	tenantID    string
}

// NewWorkflowStore creates a new workflow store
func NewWorkflowStore(configStore interfaces.ConfigStore, tenantID string) *WorkflowStore {
	return &WorkflowStore{
		configStore: configStore,
		tenantID:    tenantID,
	}
}

// Namespace constants for different workflow storage types
const (
	WorkflowNamespace         = "workflows"
	WorkflowTemplateNamespace = "workflow_templates"
	WorkflowInstanceNamespace = "workflow_instances"
)

// StoreWorkflow stores a versioned workflow
func (ws *WorkflowStore) StoreWorkflow(ctx context.Context, workflow *VersionedWorkflow) error {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		Name:      workflow.Name,
		Scope:     workflow.SemanticVersion.String(),
	}

	data, err := yaml.Marshal(workflow)
	if err != nil {
		return fmt.Errorf("failed to marshal workflow: %w", err)
	}

	entry := &interfaces.ConfigEntry{
		Key:       key,
		Data:      data,
		Format:    interfaces.ConfigFormatYAML,
		Metadata: map[string]interface{}{
			"workflow_version": workflow.SemanticVersion.String(),
			"workflow_name":    workflow.Name,
			"deprecated":       workflow.Deprecated,
			"version_tags":     workflow.VersionTags,
		},
		Tags:   append(workflow.VersionTags, "workflow", "version:"+workflow.SemanticVersion.String()),
		Source: "workflow_engine",
	}

	return ws.configStore.StoreConfig(ctx, entry)
}

// GetWorkflow retrieves a specific version of a workflow
func (ws *WorkflowStore) GetWorkflow(ctx context.Context, name string, version SemanticVersion) (*VersionedWorkflow, error) {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		Name:      name,
		Scope:     version.String(),
	}

	entry, err := ws.configStore.GetConfig(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow: %w", err)
	}

	var workflow VersionedWorkflow
	if err := yaml.Unmarshal(entry.Data, &workflow); err != nil {
		return nil, fmt.Errorf("failed to unmarshal workflow: %w", err)
	}

	return &workflow, nil
}

// GetLatestWorkflow retrieves the latest version of a workflow
func (ws *WorkflowStore) GetLatestWorkflow(ctx context.Context, name string) (*VersionedWorkflow, error) {
	versions, err := ws.ListWorkflowVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for workflow: %s", name)
	}

	// Get the latest non-deprecated version
	for _, version := range versions {
		if !version.Deprecated {
			return ws.GetWorkflow(ctx, name, version.SemanticVersion)
		}
	}

	// If all versions are deprecated, return the latest one
	return ws.GetWorkflow(ctx, name, versions[0].SemanticVersion)
}

// ListWorkflowVersions lists all versions of a workflow, sorted by version (latest first)
func (ws *WorkflowStore) ListWorkflowVersions(ctx context.Context, name string) ([]*VersionedWorkflow, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		Names:     []string{name},
		SortBy:    "created_at",
		Order:     "desc",
	}

	entries, err := ws.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflow versions: %w", err)
	}

	var workflows []*VersionedWorkflow
	for _, entry := range entries {
		var workflow VersionedWorkflow
		if err := yaml.Unmarshal(entry.Data, &workflow); err != nil {
			continue // Skip invalid entries
		}
		workflows = append(workflows, &workflow)
	}

	// Sort by semantic version (latest first)
	sort.Slice(workflows, func(i, j int) bool {
		return workflows[i].SemanticVersion.Compare(workflows[j].SemanticVersion) > 0
	})

	return workflows, nil
}

// ListWorkflows lists all workflows (latest version of each)
func (ws *WorkflowStore) ListWorkflows(ctx context.Context) ([]*VersionedWorkflow, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		SortBy:    "updated_at",
		Order:     "desc",
	}

	entries, err := ws.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows: %w", err)
	}

	// Group by workflow name and keep latest version
	workflowMap := make(map[string]*VersionedWorkflow)
	for _, entry := range entries {
		var workflow VersionedWorkflow
		if err := yaml.Unmarshal(entry.Data, &workflow); err != nil {
			continue // Skip invalid entries
		}

		existing, exists := workflowMap[workflow.Name]
		if !exists || workflow.SemanticVersion.Compare(existing.SemanticVersion) > 0 {
			workflowMap[workflow.Name] = &workflow
		}
	}

	var workflows []*VersionedWorkflow
	for _, workflow := range workflowMap {
		workflows = append(workflows, workflow)
	}

	return workflows, nil
}

// DeleteWorkflow deletes a specific version of a workflow
func (ws *WorkflowStore) DeleteWorkflow(ctx context.Context, name string, version SemanticVersion) error {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		Name:      name,
		Scope:     version.String(),
	}

	return ws.configStore.DeleteConfig(ctx, key)
}

// ForkWorkflow creates a new version by forking an existing workflow
func (ws *WorkflowStore) ForkWorkflow(ctx context.Context, name string, fromVersion, toVersion SemanticVersion) (*VersionedWorkflow, error) {
	// Get the source workflow
	sourceWorkflow, err := ws.GetWorkflow(ctx, name, fromVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get source workflow: %w", err)
	}

	// Validate version upgrade
	if err := ValidateVersionUpgrade(fromVersion, toVersion); err != nil {
		return nil, fmt.Errorf("invalid version upgrade: %w", err)
	}

	// Create new version
	newWorkflow := &VersionedWorkflow{
		Workflow:        sourceWorkflow.Workflow,
		SemanticVersion: toVersion,
		VersionTags:     append([]string{}, sourceWorkflow.VersionTags...), // Copy tags
		Deprecated:      false,
		Changelog:       append([]ChangelogEntry{}, sourceWorkflow.Changelog...), // Copy changelog
	}

	// Add changelog entry for the fork
	newWorkflow.Changelog = append([]ChangelogEntry{{
		Version:     toVersion,
		Date:        time.Now().Format("2006-01-02"),
		Description: fmt.Sprintf("Forked from version %s", fromVersion.String()),
		Changes: []Change{{
			Type:        ChangeTypeAdded,
			Description: "Forked from previous version",
		}},
	}}, newWorkflow.Changelog...)

	// Store the new version
	if err := ws.StoreWorkflow(ctx, newWorkflow); err != nil {
		return nil, fmt.Errorf("failed to store forked workflow: %w", err)
	}

	return newWorkflow, nil
}

// DeprecateWorkflow marks a workflow version as deprecated
func (ws *WorkflowStore) DeprecateWorkflow(ctx context.Context, name string, version SemanticVersion, note string) error {
	workflow, err := ws.GetWorkflow(ctx, name, version)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	workflow.Deprecated = true
	workflow.DeprecationNote = note

	return ws.StoreWorkflow(ctx, workflow)
}

// Template Storage Methods

// StoreTemplate stores a workflow template
func (ws *WorkflowStore) StoreTemplate(ctx context.Context, template *WorkflowTemplate) error {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowTemplateNamespace,
		Name:      template.ID,
		Scope:     template.Version.String(),
	}

	data, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	entry := &interfaces.ConfigEntry{
		Key:    key,
		Data:   data,
		Format: interfaces.ConfigFormatYAML,
		Metadata: map[string]interface{}{
			"template_id":      template.ID,
			"template_name":    template.Name,
			"template_version": template.Version.String(),
			"abstract":         template.Abstract,
			"extends":          template.Extends,
			"category":         template.Category,
		},
		Tags:   append(template.Tags, "template", "version:"+template.Version.String()),
		Source: "workflow_engine",
	}

	return ws.configStore.StoreConfig(ctx, entry)
}

// GetTemplate retrieves a workflow template
func (ws *WorkflowStore) GetTemplate(ctx context.Context, id string, version SemanticVersion) (*WorkflowTemplate, error) {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowTemplateNamespace,
		Name:      id,
		Scope:     version.String(),
	}

	entry, err := ws.configStore.GetConfig(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	var template WorkflowTemplate
	if err := yaml.Unmarshal(entry.Data, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	return &template, nil
}

// GetLatestTemplate retrieves the latest version of a template
func (ws *WorkflowStore) GetLatestTemplate(ctx context.Context, id string) (*WorkflowTemplate, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  ws.tenantID,
		Namespace: WorkflowTemplateNamespace,
		Names:     []string{id},
		SortBy:    "created_at",
		Order:     "desc",
		Limit:     1,
	}

	entries, err := ws.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest template: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("template not found: %s", id)
	}

	var template WorkflowTemplate
	if err := yaml.Unmarshal(entries[0].Data, &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	return &template, nil
}

// ListTemplates lists all workflow templates
func (ws *WorkflowStore) ListTemplates(ctx context.Context) ([]*WorkflowTemplate, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  ws.tenantID,
		Namespace: WorkflowTemplateNamespace,
		SortBy:    "updated_at",
		Order:     "desc",
	}

	entries, err := ws.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	// Group by template ID and keep latest version
	templateMap := make(map[string]*WorkflowTemplate)
	for _, entry := range entries {
		var template WorkflowTemplate
		if err := yaml.Unmarshal(entry.Data, &template); err != nil {
			continue // Skip invalid entries
		}

		existing, exists := templateMap[template.ID]
		if !exists || template.Version.Compare(existing.Version) > 0 {
			templateMap[template.ID] = &template
		}
	}

	var templates []*WorkflowTemplate
	for _, template := range templateMap {
		templates = append(templates, template)
	}

	return templates, nil
}

// Instance Storage Methods

// StoreInstance stores a workflow template instance
func (ws *WorkflowStore) StoreInstance(ctx context.Context, instance *TemplateInstance) error {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowInstanceNamespace,
		Name:      instance.ID,
	}

	data, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("failed to marshal instance: %w", err)
	}

	entry := &interfaces.ConfigEntry{
		Key:    key,
		Data:   data,
		Format: interfaces.ConfigFormatJSON,
		Metadata: map[string]interface{}{
			"instance_id":     instance.ID,
			"template_id":     instance.TemplateID,
			"template_name":   instance.TemplateName,
			"workflow_name":   instance.Workflow.Name,
		},
		Tags:   []string{"instance", "template:" + instance.TemplateID},
		Source: "workflow_engine",
	}

	return ws.configStore.StoreConfig(ctx, entry)
}

// GetInstance retrieves a workflow template instance
func (ws *WorkflowStore) GetInstance(ctx context.Context, id string) (*TemplateInstance, error) {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowInstanceNamespace,
		Name:      id,
	}

	entry, err := ws.configStore.GetConfig(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance: %w", err)
	}

	var instance TemplateInstance
	if err := json.Unmarshal(entry.Data, &instance); err != nil {
		return nil, fmt.Errorf("failed to unmarshal instance: %w", err)
	}

	return &instance, nil
}

// ListInstances lists all workflow template instances
func (ws *WorkflowStore) ListInstances(ctx context.Context, templateID string) ([]*TemplateInstance, error) {
	filter := &interfaces.ConfigFilter{
		TenantID:  ws.tenantID,
		Namespace: WorkflowInstanceNamespace,
		SortBy:    "created_at",
		Order:     "desc",
	}

	if templateID != "" {
		filter.Tags = []string{"template:" + templateID}
	}

	entries, err := ws.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}

	var instances []*TemplateInstance
	for _, entry := range entries {
		var instance TemplateInstance
		if err := json.Unmarshal(entry.Data, &instance); err != nil {
			continue // Skip invalid entries
		}
		instances = append(instances, &instance)
	}

	return instances, nil
}

// Version Management Methods

// GetWorkflowHistory returns the complete version history of a workflow
func (ws *WorkflowStore) GetWorkflowHistory(ctx context.Context, name string, limit int) ([]*VersionedWorkflow, error) {
	key := &interfaces.ConfigKey{
		TenantID:  ws.tenantID,
		Namespace: WorkflowNamespace,
		Name:      name,
	}

	entries, err := ws.configStore.GetConfigHistory(ctx, key, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow history: %w", err)
	}

	var workflows []*VersionedWorkflow
	for _, entry := range entries {
		var workflow VersionedWorkflow
		if err := yaml.Unmarshal(entry.Data, &workflow); err != nil {
			continue // Skip invalid entries
		}
		workflows = append(workflows, &workflow)
	}

	return workflows, nil
}

// FindCompatibleVersions finds all versions that are compatible with a given version range
func (ws *WorkflowStore) FindCompatibleVersions(ctx context.Context, name string, versionRange *VersionRange) ([]*VersionedWorkflow, error) {
	versions, err := ws.ListWorkflowVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	var compatible []*VersionedWorkflow
	for _, workflow := range versions {
		if versionRange.Satisfies(workflow.SemanticVersion) && !workflow.Deprecated {
			compatible = append(compatible, workflow)
		}
	}

	return compatible, nil
}