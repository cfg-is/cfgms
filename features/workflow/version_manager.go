// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// VersionManager manages workflow versions and templates
type VersionManager struct {
	store          *WorkflowStore
	templateEngine *TemplateEngine
}

// NewVersionManager creates a new version manager
func NewVersionManager(configStore interfaces.ConfigStore, tenantID string) *VersionManager {
	return &VersionManager{
		store:          NewWorkflowStore(configStore, tenantID),
		templateEngine: NewTemplateEngine(),
	}
}

// CreateWorkflow creates a new workflow with initial version
func (vm *VersionManager) CreateWorkflow(ctx context.Context, workflow Workflow, initialVersion string) (*VersionedWorkflow, error) {
	version, err := ParseSemanticVersion(initialVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid initial version: %w", err)
	}

	// Check if workflow already exists
	existing, _ := vm.store.GetLatestWorkflow(ctx, workflow.Name)
	if existing != nil {
		return nil, fmt.Errorf("workflow already exists: %s", workflow.Name)
	}

	versionedWorkflow := &VersionedWorkflow{
		Workflow:        workflow,
		SemanticVersion: *version,
		Changelog: []ChangelogEntry{{
			Version:     *version,
			Date:        time.Now().Format("2006-01-02"),
			Description: "Initial version",
			Changes: []Change{{
				Type:        ChangeTypeAdded,
				Description: "Initial workflow creation",
			}},
		}},
	}

	// Set the semantic version in the base workflow version field for compatibility
	versionedWorkflow.Version = version.String()

	if err := vm.store.StoreWorkflow(ctx, versionedWorkflow); err != nil {
		return nil, fmt.Errorf("failed to store workflow: %w", err)
	}

	return versionedWorkflow, nil
}

// UpdateWorkflow creates a new version of an existing workflow
func (vm *VersionManager) UpdateWorkflow(ctx context.Context, name string, workflow Workflow, newVersion string, changes []Change) (*VersionedWorkflow, error) {
	version, err := ParseSemanticVersion(newVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	// Get current latest version
	latest, err := vm.store.GetLatestWorkflow(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest workflow: %w", err)
	}

	// Validate version upgrade
	if err := ValidateVersionUpgrade(latest.SemanticVersion, *version); err != nil {
		return nil, fmt.Errorf("invalid version upgrade: %w", err)
	}

	// Create new version
	newWorkflow := &VersionedWorkflow{
		Workflow:        workflow,
		SemanticVersion: *version,
		VersionTags:     append([]string{}, latest.VersionTags...),       // Copy tags
		Changelog:       append([]ChangelogEntry{}, latest.Changelog...), // Copy existing changelog
	}

	// Set the semantic version in the base workflow version field for compatibility
	newWorkflow.Version = version.String()

	// Add new changelog entry
	changelogEntry := ChangelogEntry{
		Version:     *version,
		Date:        time.Now().Format("2006-01-02"),
		Description: fmt.Sprintf("Updated to version %s", version.String()),
		Changes:     changes,
	}
	newWorkflow.Changelog = append([]ChangelogEntry{changelogEntry}, newWorkflow.Changelog...)

	if err := vm.store.StoreWorkflow(ctx, newWorkflow); err != nil {
		return nil, fmt.Errorf("failed to store updated workflow: %w", err)
	}

	return newWorkflow, nil
}

// GetWorkflow retrieves a specific version of a workflow
func (vm *VersionManager) GetWorkflow(ctx context.Context, name, version string) (*VersionedWorkflow, error) {
	if version == "latest" || version == "" {
		return vm.store.GetLatestWorkflow(ctx, name)
	}

	semanticVersion, err := ParseSemanticVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	return vm.store.GetWorkflow(ctx, name, *semanticVersion)
}

// ListWorkflowVersions lists all versions of a workflow
func (vm *VersionManager) ListWorkflowVersions(ctx context.Context, name string) ([]*VersionedWorkflow, error) {
	return vm.store.ListWorkflowVersions(ctx, name)
}

// ListWorkflows lists all workflows (latest versions)
func (vm *VersionManager) ListWorkflows(ctx context.Context) ([]*VersionedWorkflow, error) {
	return vm.store.ListWorkflows(ctx)
}

// ForkWorkflow creates a new version by forking an existing version
func (vm *VersionManager) ForkWorkflow(ctx context.Context, name, fromVersion, toVersion string) (*VersionedWorkflow, error) {
	from, err := ParseSemanticVersion(fromVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid from version: %w", err)
	}

	to, err := ParseSemanticVersion(toVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid to version: %w", err)
	}

	return vm.store.ForkWorkflow(ctx, name, *from, *to)
}

// DeprecateWorkflow marks a workflow version as deprecated
func (vm *VersionManager) DeprecateWorkflow(ctx context.Context, name, version, note string) error {
	semanticVersion, err := ParseSemanticVersion(version)
	if err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}

	return vm.store.DeprecateWorkflow(ctx, name, *semanticVersion, note)
}

// DeleteWorkflow deletes a specific version of a workflow
func (vm *VersionManager) DeleteWorkflow(ctx context.Context, name, version string) error {
	semanticVersion, err := ParseSemanticVersion(version)
	if err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}

	return vm.store.DeleteWorkflow(ctx, name, *semanticVersion)
}

// FindCompatibleWorkflows finds workflow versions compatible with a version range
func (vm *VersionManager) FindCompatibleWorkflows(ctx context.Context, name, versionRange string) ([]*VersionedWorkflow, error) {
	vr, err := ParseVersionRange(versionRange)
	if err != nil {
		return nil, fmt.Errorf("invalid version range: %w", err)
	}

	return vm.store.FindCompatibleVersions(ctx, name, vr)
}

// Template Management Methods

// CreateTemplate creates a new workflow template
func (vm *VersionManager) CreateTemplate(ctx context.Context, template *WorkflowTemplate) error {
	if err := vm.templateEngine.ValidateTemplate(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	template.CreatedAt = time.Now()
	template.UpdatedAt = template.CreatedAt

	if err := vm.store.StoreTemplate(ctx, template); err != nil {
		return fmt.Errorf("failed to store template: %w", err)
	}

	return vm.templateEngine.RegisterTemplate(template)
}

// GetTemplate retrieves a workflow template
func (vm *VersionManager) GetTemplate(ctx context.Context, id, version string) (*WorkflowTemplate, error) {
	if version == "latest" || version == "" {
		return vm.store.GetLatestTemplate(ctx, id)
	}

	semanticVersion, err := ParseSemanticVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	return vm.store.GetTemplate(ctx, id, *semanticVersion)
}

// ListTemplates lists all workflow templates
func (vm *VersionManager) ListTemplates(ctx context.Context) ([]*WorkflowTemplate, error) {
	return vm.store.ListTemplates(ctx)
}

// InstantiateTemplate creates a workflow instance from a template
func (vm *VersionManager) InstantiateTemplate(ctx context.Context, templateID, version string, parameters map[string]interface{}) (*TemplateInstance, error) {
	// Get the template
	template, err := vm.GetTemplate(ctx, templateID, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Ensure template is registered in the engine
	if err := vm.templateEngine.RegisterTemplate(template); err != nil {
		return nil, fmt.Errorf("failed to register template: %w", err)
	}

	// Instantiate the template
	instance, err := vm.templateEngine.InstantiateTemplate(ctx, templateID, parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate template: %w", err)
	}

	// Store the instance
	if err := vm.store.StoreInstance(ctx, instance); err != nil {
		return nil, fmt.Errorf("failed to store instance: %w", err)
	}

	return instance, nil
}

// GetInstance retrieves a workflow template instance
func (vm *VersionManager) GetInstance(ctx context.Context, instanceID string) (*TemplateInstance, error) {
	return vm.store.GetInstance(ctx, instanceID)
}

// ListInstances lists workflow template instances
func (vm *VersionManager) ListInstances(ctx context.Context, templateID string) ([]*TemplateInstance, error) {
	return vm.store.ListInstances(ctx, templateID)
}

// Version Comparison and Analysis

// CompareVersions compares two workflow versions and returns differences
func (vm *VersionManager) CompareVersions(ctx context.Context, name, version1, version2 string) (*VersionComparison, error) {
	v1, err := vm.GetWorkflow(ctx, name, version1)
	if err != nil {
		return nil, fmt.Errorf("failed to get version %s: %w", version1, err)
	}

	v2, err := vm.GetWorkflow(ctx, name, version2)
	if err != nil {
		return nil, fmt.Errorf("failed to get version %s: %w", version2, err)
	}

	return vm.compareWorkflows(v1, v2), nil
}

// GetVersionHistory returns the complete version history of a workflow
func (vm *VersionManager) GetVersionHistory(ctx context.Context, name string, limit int) ([]*VersionedWorkflow, error) {
	return vm.store.GetWorkflowHistory(ctx, name, limit)
}

// Helper methods

func (vm *VersionManager) compareWorkflows(v1, v2 *VersionedWorkflow) *VersionComparison {
	comparison := &VersionComparison{
		Version1: v1.SemanticVersion,
		Version2: v2.SemanticVersion,
		Changes:  []VersionDifference{},
	}

	// Compare basic properties
	if v1.Name != v2.Name {
		comparison.Changes = append(comparison.Changes, VersionDifference{
			Type:     DifferenceTypeModified,
			Path:     "name",
			OldValue: v1.Name,
			NewValue: v2.Name,
		})
	}

	if v1.Description != v2.Description {
		comparison.Changes = append(comparison.Changes, VersionDifference{
			Type:     DifferenceTypeModified,
			Path:     "description",
			OldValue: v1.Description,
			NewValue: v2.Description,
		})
	}

	// Compare steps (simplified - in practice would need deep comparison)
	if len(v1.Steps) != len(v2.Steps) {
		comparison.Changes = append(comparison.Changes, VersionDifference{
			Type:     DifferenceTypeModified,
			Path:     "steps.length",
			OldValue: len(v1.Steps),
			NewValue: len(v2.Steps),
		})
	}

	// Determine if changes are breaking
	comparison.IsBreaking = vm.isBreakingChange(v1.SemanticVersion, v2.SemanticVersion)

	return comparison
}

func (vm *VersionManager) isBreakingChange(v1, v2 SemanticVersion) bool {
	// Major version change is always breaking
	return v2.Major > v1.Major
}

// VersionComparison represents the differences between two workflow versions
type VersionComparison struct {
	Version1   SemanticVersion     `json:"version1"`
	Version2   SemanticVersion     `json:"version2"`
	Changes    []VersionDifference `json:"changes"`
	IsBreaking bool                `json:"is_breaking"`
}

// VersionDifference represents a single difference between versions
type VersionDifference struct {
	Type     DifferenceType `json:"type"`
	Path     string         `json:"path"`
	OldValue interface{}    `json:"old_value,omitempty"`
	NewValue interface{}    `json:"new_value,omitempty"`
}

// DifferenceType defines the type of difference
type DifferenceType string

const (
	DifferenceTypeAdded    DifferenceType = "added"
	DifferenceTypeRemoved  DifferenceType = "removed"
	DifferenceTypeModified DifferenceType = "modified"
)
