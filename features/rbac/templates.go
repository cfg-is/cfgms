// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/api/proto/common"
)

// TemplateManager handles permission template operations
type TemplateManager struct {
	templates   map[string]*common.PermissionTemplate
	mutex       sync.RWMutex
	rbacManager RBACManager
}

// NewTemplateManager creates a new permission template manager
func NewTemplateManager(rbacManager RBACManager) *TemplateManager {
	return &TemplateManager{
		templates:   make(map[string]*common.PermissionTemplate),
		rbacManager: rbacManager,
	}
}

// Initialize loads default permission templates
func (t *TemplateManager) Initialize(ctx context.Context) error {
	// Load system templates
	systemTemplates := t.getSystemTemplates()

	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, template := range systemTemplates {
		t.templates[template.Id] = template
	}

	return nil
}

// CreateTemplate creates a new permission template
func (t *TemplateManager) CreateTemplate(ctx context.Context, req *TemplateCreateRequest) (*common.PermissionTemplate, error) {
	if err := t.validateTemplateRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("invalid template request: %w", err)
	}

	template := &common.PermissionTemplate{
		Id:                     uuid.New().String(),
		Name:                   req.Name,
		Description:            req.Description,
		Category:               req.Category,
		PermissionIds:          req.PermissionIDs,
		ConditionalPermissions: req.ConditionalPermissions,
		DefaultConditions:      req.DefaultConditions,
		IsSystemTemplate:       false,
		TenantId:               req.TenantID,
		CreatedAt:              time.Now().Unix(),
		UpdatedAt:              time.Now().Unix(),
	}

	t.mutex.Lock()
	t.templates[template.Id] = template
	t.mutex.Unlock()

	return template, nil
}

// GetTemplate retrieves a template by ID
func (t *TemplateManager) GetTemplate(ctx context.Context, templateID string) (*common.PermissionTemplate, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	template, exists := t.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateID)
	}

	return template, nil
}

// ListTemplates lists available templates, optionally filtered by category and tenant
func (t *TemplateManager) ListTemplates(ctx context.Context, tenantID, category string) ([]*common.PermissionTemplate, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	var result []*common.PermissionTemplate

	for _, template := range t.templates {
		// Include system templates and templates for the specific tenant
		if template.IsSystemTemplate || template.TenantId == tenantID {
			if category == "" || template.Category == category {
				result = append(result, template)
			}
		}
	}

	return result, nil
}

// ApplyTemplate applies a template to create roles and assign permissions to a subject
func (t *TemplateManager) ApplyTemplate(ctx context.Context, templateID, subjectID, tenantID string, customizations map[string]string) error {
	template, err := t.GetTemplate(ctx, templateID)
	if err != nil {
		return err
	}

	// Create a role based on the template
	subjectSuffix := subjectID
	if len(subjectSuffix) > 8 {
		subjectSuffix = subjectSuffix[:8]
	}
	roleName := fmt.Sprintf("%s-%s", template.Name, subjectSuffix)
	role := &common.Role{
		Id:            uuid.New().String(),
		Name:          roleName,
		Description:   fmt.Sprintf("Role created from template: %s", template.Description),
		PermissionIds: template.PermissionIds,
		IsSystemRole:  false,
		TenantId:      tenantID,
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}

	// Create the role
	if err := t.rbacManager.CreateRole(ctx, role); err != nil {
		return fmt.Errorf("failed to create role from template: %w", err)
	}

	// Assign the role to the subject
	assignment := &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    role.Id,
		TenantId:  tenantID,
	}

	if err := t.rbacManager.AssignRole(ctx, assignment); err != nil {
		// Cleanup: delete the created role if assignment fails
		_ = t.rbacManager.DeleteRole(ctx, role.Id)
		return fmt.Errorf("failed to assign template role: %w", err)
	}

	// Handle conditional permissions if any
	// In the current implementation, conditional permissions are not stored with role assignments
	// This is a limitation that would need to be addressed in a future version
	// For now, we acknowledge but do not process conditional permissions from templates

	return nil
}

// UpdateTemplate updates an existing template
func (t *TemplateManager) UpdateTemplate(ctx context.Context, templateID string, req *TemplateUpdateRequest) (*common.PermissionTemplate, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	template, exists := t.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateID)
	}

	if template.IsSystemTemplate {
		return nil, fmt.Errorf("cannot update system template")
	}

	// Update fields
	if req.Name != "" {
		template.Name = req.Name
	}
	if req.Description != "" {
		template.Description = req.Description
	}
	if req.Category != "" {
		template.Category = req.Category
	}
	if len(req.PermissionIDs) > 0 {
		template.PermissionIds = req.PermissionIDs
	}
	if len(req.ConditionalPermissions) > 0 {
		template.ConditionalPermissions = req.ConditionalPermissions
	}
	if len(req.DefaultConditions) > 0 {
		template.DefaultConditions = req.DefaultConditions
	}

	template.UpdatedAt = time.Now().Unix()

	return template, nil
}

// DeleteTemplate deletes a template
func (t *TemplateManager) DeleteTemplate(ctx context.Context, templateID string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	template, exists := t.templates[templateID]
	if !exists {
		return fmt.Errorf("template %s not found", templateID)
	}

	if template.IsSystemTemplate {
		return fmt.Errorf("cannot delete system template")
	}

	delete(t.templates, templateID)
	return nil
}

// GetTemplatesByCategory returns templates grouped by category
func (t *TemplateManager) GetTemplatesByCategory(ctx context.Context, tenantID string) (map[string][]*common.PermissionTemplate, error) {
	templates, err := t.ListTemplates(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}

	result := make(map[string][]*common.PermissionTemplate)
	for _, template := range templates {
		category := template.Category
		if category == "" {
			category = "uncategorized"
		}
		result[category] = append(result[category], template)
	}

	return result, nil
}

// ValidateTemplate validates that a template is well-formed
func (t *TemplateManager) ValidateTemplate(ctx context.Context, template *common.PermissionTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name cannot be empty")
	}

	// Validate that all referenced permissions exist
	for _, permID := range template.PermissionIds {
		_, err := t.rbacManager.GetPermission(ctx, permID)
		if err != nil {
			return fmt.Errorf("referenced permission %s does not exist", permID)
		}
	}

	// Validate conditional permissions
	scopeEngine := NewScopeEngine()

	for _, condPerm := range template.ConditionalPermissions {
		// Validate base permission exists
		_, err := t.rbacManager.GetPermission(ctx, condPerm.PermissionId)
		if err != nil {
			return fmt.Errorf("conditional permission references non-existent permission %s", condPerm.PermissionId)
		}

		// Validate conditions
		for _, condition := range condPerm.Conditions {
			if condition.Type == "" {
				return fmt.Errorf("condition type cannot be empty")
			}
			if len(condition.Values) == 0 {
				return fmt.Errorf("condition must have at least one value")
			}
		}

		// Validate scope
		if condPerm.Scope != nil {
			if err := scopeEngine.ValidateScope(ctx, condPerm.Scope); err != nil {
				return fmt.Errorf("invalid conditional permission scope: %w", err)
			}
		}
	}

	return nil
}

// getSystemTemplates returns built-in system templates
func (t *TemplateManager) getSystemTemplates() []*common.PermissionTemplate {
	return []*common.PermissionTemplate{
		{
			Id:               "system.read-only",
			Name:             "Read-Only Access",
			Description:      "Basic read-only permissions for viewing system information",
			Category:         "system",
			PermissionIds:    []string{"steward.read", "configuration.read", "tenant.read"},
			IsSystemTemplate: true,
			CreatedAt:        time.Now().Unix(),
			UpdatedAt:        time.Now().Unix(),
		},
		{
			Id:               "system.operator",
			Name:             "System Operator",
			Description:      "Standard operator permissions for system management",
			Category:         "system",
			PermissionIds:    []string{"steward.read", "steward.update", "configuration.read", "configuration.update"},
			IsSystemTemplate: true,
			CreatedAt:        time.Now().Unix(),
			UpdatedAt:        time.Now().Unix(),
		},
		{
			Id:            "compliance.hipaa",
			Name:          "HIPAA Compliance",
			Description:   "HIPAA-compliant access controls with audit requirements",
			Category:      "compliance",
			PermissionIds: []string{"audit.read", "configuration.read"},
			ConditionalPermissions: []*common.ConditionalPermission{
				{
					Id:           "hipaa-mfa-required",
					PermissionId: "configuration.update",
					Conditions: []*common.Condition{
						{
							Type:     "mfa_verified",
							Operator: common.ConditionOperator_CONDITION_OPERATOR_EQUALS,
							Values:   []string{"true"},
						},
					},
				},
			},
			DefaultConditions: map[string]string{
				"audit_required": "true",
			},
			IsSystemTemplate: true,
			CreatedAt:        time.Now().Unix(),
			UpdatedAt:        time.Now().Unix(),
		},
		{
			Id:            "emergency.break-glass",
			Name:          "Emergency Break-Glass Access",
			Description:   "Emergency access template with time-limited full privileges",
			Category:      "emergency",
			PermissionIds: []string{"*"}, // All permissions
			ConditionalPermissions: []*common.ConditionalPermission{
				{
					Id:           "emergency-time-limited",
					PermissionId: "*",
					Conditions: []*common.Condition{
						{
							Type:     "time",
							Operator: common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN,
							Values:   []string{time.Now().Add(4 * time.Hour).Format(time.RFC3339)},
						},
					},
				},
			},
			IsSystemTemplate: true,
			CreatedAt:        time.Now().Unix(),
			UpdatedAt:        time.Now().Unix(),
		},
	}
}

// validateTemplateRequest validates a template creation request
func (t *TemplateManager) validateTemplateRequest(ctx context.Context, req *TemplateCreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("template name cannot be empty")
	}

	if req.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	if len(req.PermissionIDs) == 0 && len(req.ConditionalPermissions) == 0 {
		return fmt.Errorf("template must include at least one permission or conditional permission")
	}

	// Create a temporary template for validation
	tempTemplate := &common.PermissionTemplate{
		Name:                   req.Name,
		Description:            req.Description,
		Category:               req.Category,
		PermissionIds:          req.PermissionIDs,
		ConditionalPermissions: req.ConditionalPermissions,
		DefaultConditions:      req.DefaultConditions,
		TenantId:               req.TenantID,
	}

	return t.ValidateTemplate(ctx, tempTemplate)
}

// TemplateCreateRequest represents a request to create a permission template
type TemplateCreateRequest struct {
	Name                   string                          `json:"name"`
	Description            string                          `json:"description"`
	Category               string                          `json:"category"`
	PermissionIDs          []string                        `json:"permission_ids"`
	ConditionalPermissions []*common.ConditionalPermission `json:"conditional_permissions"`
	DefaultConditions      map[string]string               `json:"default_conditions"`
	TenantID               string                          `json:"tenant_id"`
}

// TemplateUpdateRequest represents a request to update a permission template
type TemplateUpdateRequest struct {
	Name                   string                          `json:"name,omitempty"`
	Description            string                          `json:"description,omitempty"`
	Category               string                          `json:"category,omitempty"`
	PermissionIDs          []string                        `json:"permission_ids,omitempty"`
	ConditionalPermissions []*common.ConditionalPermission `json:"conditional_permissions,omitempty"`
	DefaultConditions      map[string]string               `json:"default_conditions,omitempty"`
}
