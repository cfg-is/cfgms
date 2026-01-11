// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// CustomTemplateManager implements the CustomTemplateManager interface
type CustomTemplateManager struct {
	store  interfaces.CustomTemplateStore
	logger logging.Logger
}

// NewCustomTemplateManager creates a new custom template manager
func NewCustomTemplateManager(
	store interfaces.CustomTemplateStore,
	logger logging.Logger,
) *CustomTemplateManager {
	return &CustomTemplateManager{
		store:  store,
		logger: logger,
	}
}

// SaveTemplate saves a custom report template
func (m *CustomTemplateManager) SaveTemplate(ctx context.Context, template *interfaces.CustomReportTemplate) (*interfaces.CustomReportTemplate, error) {
	m.logger.Info("Saving custom template", "name", template.Name, "tenant_id", template.TenantID)

	// Validate template
	if err := m.validateTemplate(template); err != nil {
		return nil, fmt.Errorf("template validation failed: %w", err)
	}

	// Set metadata if creating new template
	if template.ID == "" {
		template.ID = uuid.New().String()
		template.CreatedAt = time.Now()
	}
	template.UpdatedAt = time.Now()

	// Save to store
	savedTemplate, err := m.store.Save(ctx, template)
	if err != nil {
		return nil, fmt.Errorf("failed to save template: %w", err)
	}

	m.logger.Info("Template saved successfully", "template_id", savedTemplate.ID)
	return savedTemplate, nil
}

// GetTemplate retrieves a template by ID with tenant access validation
func (m *CustomTemplateManager) GetTemplate(ctx context.Context, templateID, tenantID string) (*interfaces.CustomReportTemplate, error) {
	m.logger.Debug("Getting template", "template_id", templateID, "tenant_id", tenantID)

	template, err := m.store.GetByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Check access permissions
	if !m.hasTemplateAccess(template, tenantID) {
		return nil, ErrTemplateAccessDenied
	}

	return template, nil
}

// GetAccessibleTemplates returns all templates accessible to a tenant
func (m *CustomTemplateManager) GetAccessibleTemplates(ctx context.Context, tenantID string) ([]*interfaces.CustomReportTemplate, error) {
	m.logger.Debug("Getting accessible templates", "tenant_id", tenantID)

	// Get templates owned by tenant
	ownedTemplates, err := m.store.GetByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get owned templates: %w", err)
	}

	// Get templates shared with tenant
	sharedTemplates, err := m.store.GetSharedTemplates(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared templates: %w", err)
	}

	// Combine and return
	allTemplates := make([]*interfaces.CustomReportTemplate, 0, len(ownedTemplates)+len(sharedTemplates))
	allTemplates = append(allTemplates, ownedTemplates...)
	allTemplates = append(allTemplates, sharedTemplates...)

	m.logger.Debug("Found accessible templates", "count", len(allTemplates), "tenant_id", tenantID)
	return allTemplates, nil
}

// ShareTemplate shares a template with other tenants
func (m *CustomTemplateManager) ShareTemplate(ctx context.Context, req interfaces.ShareTemplateRequest) error {
	m.logger.Info("Sharing template", "template_id", req.TemplateID, "shared_by", req.SharedBy)

	// Get the template to verify it exists
	_, err := m.store.GetByID(ctx, req.TemplateID)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	// Create shares
	shares := make([]interfaces.TemplateShare, len(req.SharedWithTenants))
	for i, tenantID := range req.SharedWithTenants {
		shares[i] = interfaces.TemplateShare{
			TenantID:    tenantID,
			SharedBy:    req.SharedBy,
			SharedAt:    time.Now(),
			Permissions: req.Permissions,
			ExpiresAt:   req.ExpiresAt,
		}
	}

	// Update sharing in store
	err = m.store.UpdateSharing(ctx, req.TemplateID, shares)
	if err != nil {
		return fmt.Errorf("failed to update sharing: %w", err)
	}

	m.logger.Info("Template shared successfully",
		"template_id", req.TemplateID,
		"tenant_count", len(req.SharedWithTenants))
	return nil
}

// DeleteTemplate deletes a template (only by owner)
func (m *CustomTemplateManager) DeleteTemplate(ctx context.Context, templateID, tenantID string) error {
	m.logger.Info("Deleting template", "template_id", templateID, "tenant_id", tenantID)

	// Verify ownership before deletion
	template, err := m.store.GetByID(ctx, templateID)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	if template.TenantID != tenantID {
		return ErrTemplateAccessDenied
	}

	// Delete from store
	err = m.store.Delete(ctx, templateID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	m.logger.Info("Template deleted successfully", "template_id", templateID)
	return nil
}

// Helper methods

func (m *CustomTemplateManager) validateTemplate(template *interfaces.CustomReportTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if template.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}
	if len(template.Query.DataSources) == 0 {
		return fmt.Errorf("at least one data source is required")
	}

	// Validate parameters
	for i, param := range template.Parameters {
		if param.Name == "" {
			return fmt.Errorf("parameter %d: name is required", i)
		}
		if param.Type == "" {
			return fmt.Errorf("parameter %d: type is required", i)
		}
	}

	return nil
}

func (m *CustomTemplateManager) hasTemplateAccess(template *interfaces.CustomReportTemplate, tenantID string) bool {
	// Owner has access
	if template.TenantID == tenantID {
		return true
	}

	// Check if shared with tenant
	for _, share := range template.SharedWith {
		if share.TenantID == tenantID {
			// Check if share has expired
			if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
				continue
			}
			return true
		}
	}

	return false
}
