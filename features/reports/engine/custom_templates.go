// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ShareScopeFunc reports whether ownerTenant may share a template with targetTenant. It
// must return false for an empty, equal, nonexistent or out-of-subtree target; an error
// is treated as a denial.
type ShareScopeFunc func(ctx context.Context, ownerTenant, targetTenant string) (bool, error)

const (
	permRead    = "read"
	permExecute = "execute"
	permModify  = "modify"
)

// CustomTemplateManager implements interfaces.CustomTemplateManager over the durable
// business.ReportTemplateStore.
type CustomTemplateManager struct {
	store business.ReportTemplateStore
	now   func() time.Time
	scope ShareScopeFunc
	cfg   interfaces.CustomReportConfig
}

var _ interfaces.CustomTemplateManager = (*CustomTemplateManager)(nil)

// NewCustomTemplateManager builds a manager. The store, clock and share-scope function are
// all required; a nil scope function is refused so sharing fails closed.
func NewCustomTemplateManager(store business.ReportTemplateStore, now func() time.Time, scope ShareScopeFunc) (*CustomTemplateManager, error) {
	if store == nil {
		return nil, errors.New("custom template manager requires a template store")
	}
	if now == nil {
		return nil, errors.New("custom template manager requires a clock")
	}
	if scope == nil {
		return nil, errors.New("custom template manager requires a share scope function")
	}
	return &CustomTemplateManager{store: store, now: now, scope: scope, cfg: interfaces.DefaultCustomReportConfig()}, nil
}

var errEmptyTenant = errors.New("tenant ID is required")

type templateDefinition struct {
	Query      interfaces.CustomQuery       `json:"query"`
	Parameters []interfaces.CustomParameter `json:"parameters"`
}

// SaveTemplate creates a template owned by template.TenantID, or updates one that tenant
// already owns. Sharing and creation metadata of an existing template are preserved.
func (m *CustomTemplateManager) SaveTemplate(ctx context.Context, template *interfaces.CustomReportTemplate) (*interfaces.CustomReportTemplate, error) {
	if template == nil {
		return nil, errors.New("template is required")
	}
	tenant := template.TenantID
	if tenant == "" {
		return nil, errEmptyTenant
	}
	if template.Name == "" {
		return nil, errors.New("template name is required")
	}
	if len(template.Query.DataSources) == 0 {
		return nil, errors.New("template requires at least one data source")
	}
	if len(template.Parameters) > m.cfg.MaxParameters {
		return nil, fmt.Errorf("template has %d parameters, maximum is %d", len(template.Parameters), m.cfg.MaxParameters)
	}

	now := m.now()
	rec := toRecord(template)
	if template.ID == "" {
		rec.ID = uuid.NewString()
		rec.CreatedAt = now
		rec.SharedWith = nil
		rec.IsShared = false
	} else {
		existing, err := m.store.GetByID(ctx, tenant, template.ID)
		if err != nil {
			if errors.Is(err, business.ErrReportTemplateNotFound) {
				return nil, interfaces.ErrTemplateNotFound
			}
			return nil, fmt.Errorf("failed to load template: %w", err)
		}
		if existing.TenantID != tenant {
			return nil, interfaces.ErrTemplateAccessDenied
		}
		rec.CreatedAt = existing.CreatedAt
		rec.CreatedBy = existing.CreatedBy
		rec.SharedWith = existing.SharedWith
		rec.IsShared = existing.IsShared
		rec.UsageCount = existing.UsageCount
		rec.LastUsed = existing.LastUsed
	}
	rec.UpdatedAt = now

	def, err := json.Marshal(templateDefinition{Query: template.Query, Parameters: template.Parameters})
	if err != nil {
		return nil, fmt.Errorf("failed to encode template definition: %w", err)
	}
	rec.Definition = def

	if err := m.store.Save(ctx, tenant, rec); err != nil {
		if errors.Is(err, business.ErrReportTemplateExists) {
			return nil, interfaces.ErrTemplateAccessDenied
		}
		return nil, fmt.Errorf("failed to save template: %w", err)
	}
	return fromRecord(rec, tenant)
}

// GetTemplate returns a template to its owner or to a tenant holding a non-expired share
// with read permission. The store reports a template the tenant cannot see as not found,
// so a missing template and another tenant's template are indistinguishable.
func (m *CustomTemplateManager) GetTemplate(ctx context.Context, templateID, tenantID string) (*interfaces.CustomReportTemplate, error) {
	if tenantID == "" {
		return nil, errEmptyTenant
	}
	rec, err := m.store.GetByID(ctx, tenantID, templateID)
	if err != nil {
		if errors.Is(err, business.ErrReportTemplateNotFound) {
			return nil, interfaces.ErrTemplateNotFound
		}
		return nil, fmt.Errorf("failed to load template: %w", err)
	}
	if rec.TenantID != tenantID {
		share := m.activeShare(rec, tenantID)
		if share == nil {
			return nil, interfaces.ErrTemplateNotFound
		}
		if !hasPermission(share.Permissions, permRead) {
			return nil, interfaces.ErrTemplateAccessDenied
		}
	}
	return fromRecord(rec, tenantID)
}

// GetAccessibleTemplates returns the templates the tenant owns plus those shared with it
// by a share that has not expired and grants read permission. A share carrying only
// execute or modify does not expose the template body through the list, matching
// GetTemplate.
func (m *CustomTemplateManager) GetAccessibleTemplates(ctx context.Context, tenantID string) ([]*interfaces.CustomReportTemplate, error) {
	if tenantID == "" {
		return nil, errEmptyTenant
	}
	owned, err := m.store.ListOwned(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}
	shared, err := m.store.ListSharedWith(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list shared templates: %w", err)
	}
	out := make([]*interfaces.CustomReportTemplate, 0, len(owned)+len(shared))
	for _, rec := range owned {
		t, err := fromRecord(rec, tenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	for _, rec := range shared {
		if rec.TenantID == tenantID {
			continue
		}
		share := m.activeShare(rec, tenantID)
		if share == nil || !hasPermission(share.Permissions, permRead) {
			continue
		}
		t, err := fromRecord(rec, tenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// ShareTemplate shares a template owned by req.TenantID with the target tenants. Valid
// permissions are read, execute and modify. The modify permission is accepted for forward
// compatibility but grants nothing today: SaveTemplate is owner-only. Every target must
// pass the ShareScopeFunc; a refused target (or a scope error) fails the whole request
// with ErrShareTargetInvalid and writes nothing.
func (m *CustomTemplateManager) ShareTemplate(ctx context.Context, req interfaces.ShareTemplateRequest) error {
	if req.TenantID == "" {
		return errEmptyTenant
	}
	if len(req.SharedWithTenants) == 0 {
		return errors.New("at least one target tenant is required")
	}
	if len(req.Permissions) == 0 {
		return errors.New("at least one permission is required")
	}
	for _, p := range req.Permissions {
		if p != permRead && p != permExecute && p != permModify {
			return fmt.Errorf("invalid permission %q", p)
		}
	}

	rec, err := m.store.GetByID(ctx, req.TenantID, req.TemplateID)
	if err != nil {
		if errors.Is(err, business.ErrReportTemplateNotFound) {
			return interfaces.ErrTemplateNotFound
		}
		return fmt.Errorf("failed to load template: %w", err)
	}
	if rec.TenantID != req.TenantID {
		return interfaces.ErrTemplateAccessDenied
	}

	for _, target := range req.SharedWithTenants {
		if target == "" || target == req.TenantID {
			return interfaces.ErrShareTargetInvalid
		}
		ok, err := m.scope(ctx, req.TenantID, target)
		if err != nil || !ok {
			return interfaces.ErrShareTargetInvalid
		}
	}

	now := m.now()
	perms := append([]string(nil), req.Permissions...)
	replaced := make(map[string]bool, len(req.SharedWithTenants))
	shares := make([]business.ReportTemplateShare, 0, len(rec.SharedWith)+len(req.SharedWithTenants))
	for _, s := range rec.SharedWith {
		if !contains(req.SharedWithTenants, s.TenantID) {
			shares = append(shares, s)
		}
	}
	for _, target := range req.SharedWithTenants {
		if replaced[target] {
			continue
		}
		replaced[target] = true
		share := business.ReportTemplateShare{
			TenantID:    target,
			SharedBy:    req.SharedBy,
			SharedAt:    now,
			Permissions: append([]string(nil), perms...),
		}
		if req.ExpiresAt != nil {
			exp := *req.ExpiresAt
			share.ExpiresAt = &exp
		}
		shares = append(shares, share)
	}
	if err := m.store.UpdateSharing(ctx, req.TenantID, req.TemplateID, shares); err != nil {
		if errors.Is(err, business.ErrReportTemplateNotFound) {
			return interfaces.ErrTemplateNotFound
		}
		return fmt.Errorf("failed to update sharing: %w", err)
	}
	return nil
}

// DeleteTemplate deletes a template; only the owner may.
func (m *CustomTemplateManager) DeleteTemplate(ctx context.Context, templateID, tenantID string) error {
	if tenantID == "" {
		return errEmptyTenant
	}
	rec, err := m.store.GetByID(ctx, tenantID, templateID)
	if err != nil {
		if errors.Is(err, business.ErrReportTemplateNotFound) {
			return interfaces.ErrTemplateNotFound
		}
		return fmt.Errorf("failed to load template: %w", err)
	}
	if rec.TenantID != tenantID {
		return interfaces.ErrTemplateAccessDenied
	}
	if err := m.store.Delete(ctx, tenantID, templateID); err != nil {
		if errors.Is(err, business.ErrReportTemplateNotFound) {
			return interfaces.ErrTemplateNotFound
		}
		return fmt.Errorf("failed to delete template: %w", err)
	}
	return nil
}

// activeShare returns tenantID's share of rec that has not expired by the injected clock.
func (m *CustomTemplateManager) activeShare(rec *business.ReportTemplate, tenantID string) *business.ReportTemplateShare {
	now := m.now()
	for i := range rec.SharedWith {
		s := &rec.SharedWith[i]
		if s.TenantID != tenantID {
			continue
		}
		if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
			return nil
		}
		return s
	}
	return nil
}

func hasPermission(perms []string, want string) bool { return contains(perms, want) }

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func toRecord(t *interfaces.CustomReportTemplate) *business.ReportTemplate {
	rec := &business.ReportTemplate{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		TenantID:    t.TenantID,
		CreatedBy:   t.CreatedBy,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		Tags:        append([]string(nil), t.Tags...),
		Category:    t.Category,
		Version:     t.Version,
		UsageCount:  t.UsageCount,
		LastUsed:    t.LastUsed,
		IsShared:    t.IsShared,
	}
	for _, s := range t.SharedWith {
		rec.SharedWith = append(rec.SharedWith, business.ReportTemplateShare{
			TenantID: s.TenantID, SharedBy: s.SharedBy, SharedAt: s.SharedAt,
			Permissions: append([]string(nil), s.Permissions...), ExpiresAt: s.ExpiresAt,
		})
	}
	return rec
}

// fromRecord converts a stored record into a fresh template for viewer. A non-owner sees
// only its own share entry; the stored record is never modified.
func fromRecord(rec *business.ReportTemplate, viewer string) (*interfaces.CustomReportTemplate, error) {
	var def templateDefinition
	if len(rec.Definition) > 0 {
		if err := json.Unmarshal(rec.Definition, &def); err != nil {
			return nil, fmt.Errorf("failed to decode template definition: %w", err)
		}
	}
	t := &interfaces.CustomReportTemplate{
		ID:          rec.ID,
		Name:        rec.Name,
		Description: rec.Description,
		Query:       def.Query,
		Parameters:  def.Parameters,
		TenantID:    rec.TenantID,
		CreatedBy:   rec.CreatedBy,
		CreatedAt:   rec.CreatedAt,
		UpdatedAt:   rec.UpdatedAt,
		IsShared:    rec.IsShared,
		Tags:        append([]string(nil), rec.Tags...),
		Category:    rec.Category,
		Version:     rec.Version,
		UsageCount:  rec.UsageCount,
		LastUsed:    rec.LastUsed,
	}
	for _, s := range rec.SharedWith {
		if rec.TenantID != viewer && s.TenantID != viewer {
			continue
		}
		t.SharedWith = append(t.SharedWith, interfaces.TemplateShare{
			TenantID: s.TenantID, SharedBy: s.SharedBy, SharedAt: s.SharedAt,
			Permissions: append([]string(nil), s.Permissions...), ExpiresAt: s.ExpiresAt,
		})
	}
	return t, nil
}
