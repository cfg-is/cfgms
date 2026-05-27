// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// cacheInvalidator is the minimal interface required by Manager to invalidate cached
// config source resolutions after a tenant update. Implemented by ConfigSourceRouter.
type cacheInvalidator interface {
	InvalidateTenantCache(tenantID string)
}

// Manager handles tenant operations and integrates with RBAC
type Manager struct {
	store        Store
	rbacManager  *rbac.Manager
	router       cacheInvalidator           // optional; invalidates config source cache on UpdateTenant
	validator    cfgpkg.MountPointValidator // optional; validates git mount points on create/update
	secretStore  secretsiface.SecretStore   // optional; provides credentials to validator
	auditManager *audit.Manager             // optional; records config source lifecycle events
}

// NewManager creates a new tenant manager
func NewManager(store Store, rbacManager *rbac.Manager) *Manager {
	return &Manager{
		store:       store,
		rbacManager: rbacManager,
	}
}

// WithConfigRouter wires a ConfigSourceRouter into the manager so that
// UpdateTenant can invalidate the per-tenant config source cache immediately
// after a successful store update.
func (m *Manager) WithConfigRouter(r cacheInvalidator) *Manager {
	m.router = r
	return m
}

// WithMountPointValidator wires a MountPointValidator and its required SecretStore
// into the manager. When set, CreateTenant and UpdateTenant call ValidateMountPoint
// for requests that set config_source_type to "git". Passing nil skips validation.
func (m *Manager) WithMountPointValidator(v cfgpkg.MountPointValidator, ss secretsiface.SecretStore) *Manager {
	m.validator = v
	m.secretStore = ss
	return m
}

// WithAuditManager wires an audit.Manager so that config source lifecycle transitions
// (created, updated, deleted) are recorded as audit events.
func (m *Manager) WithAuditManager(a *audit.Manager) *Manager {
	m.auditManager = a
	return m
}

// CreateTenant creates a new tenant with validation and RBAC setup
func (m *Manager) CreateTenant(ctx context.Context, req *TenantRequest) (*business.TenantData, error) {
	// Validate the request
	if err := m.validateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Validate git mount point when config_source_type is "git"
	if req.Metadata[cfgpkg.MetaKeyConfigSourceType] == string(cfgpkg.ConfigSourceTypeGit) {
		if err := m.validateGitMountPoint(ctx, req.Metadata); err != nil {
			return nil, err
		}
	}

	// Generate tenant ID from name
	tenantID := m.generateTenantID(req.Name)

	// Create tenant object
	now := time.Now()
	td := &business.TenantData{
		ID:          tenantID,
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
		Metadata:    req.Metadata,
		Status:      business.TenantStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Create the tenant in storage
	if err := m.store.CreateTenant(ctx, td); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Emit audit event when a git config source is set on creation
	if req.Metadata[cfgpkg.MetaKeyConfigSourceType] == string(cfgpkg.ConfigSourceTypeGit) {
		m.recordConfigSourceEvent(ctx, tenantID,
			req.Metadata[cfgpkg.MetaKeyConfigSourceURL],
			"config_source_created")
	}

	// Create default RBAC roles for the tenant (if RBAC is enabled)
	if m.rbacManager != nil {
		if err := m.rbacManager.CreateTenantDefaultRoles(ctx, tenantID); err != nil {
			// Rollback tenant creation if RBAC setup fails
			_ = m.store.DeleteTenant(ctx, tenantID)
			return nil, fmt.Errorf("failed to create tenant RBAC roles: %w", err)
		}
	}

	return td, nil
}

// GetTenant retrieves a tenant by ID
func (m *Manager) GetTenant(ctx context.Context, tenantID string) (*business.TenantData, error) {
	return m.store.GetTenant(ctx, tenantID)
}

// UpdateTenant updates an existing tenant
func (m *Manager) UpdateTenant(ctx context.Context, tenantID string, req *TenantRequest) (*business.TenantData, error) {
	// Get existing tenant
	existing, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Validate the request
	if err := m.validateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Validate git mount point when config_source_type is "git"
	if req.Metadata[cfgpkg.MetaKeyConfigSourceType] == string(cfgpkg.ConfigSourceTypeGit) {
		if err := m.validateGitMountPoint(ctx, req.Metadata); err != nil {
			return nil, err
		}
	}

	// Determine which config source audit event to emit before updating metadata.
	oldType := existing.Metadata[cfgpkg.MetaKeyConfigSourceType]
	newType := req.Metadata[cfgpkg.MetaKeyConfigSourceType]
	auditAction, auditURL := m.resolveConfigSourceAuditAction(oldType, newType, existing.Metadata, req.Metadata)

	// Update fields
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Metadata = req.Metadata
	// Note: ParentID cannot be changed after creation to maintain hierarchy integrity

	// Update in storage
	if err := m.store.UpdateTenant(ctx, existing); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	// Emit audit event for config source lifecycle transition
	if auditAction != "" {
		m.recordConfigSourceEvent(ctx, tenantID, auditURL, auditAction)
	}

	// Invalidate the config source cache so the next resolution reflects the new metadata.
	if m.router != nil {
		m.router.InvalidateTenantCache(tenantID)
	}

	return existing, nil
}

// DeleteTenant deletes a tenant
func (m *Manager) DeleteTenant(ctx context.Context, tenantID string) error {
	// Cannot delete default tenant
	if tenantID == "default" {
		return fmt.Errorf("cannot delete default tenant")
	}

	// Check if tenant has child tenants
	children, err := m.store.GetChildTenants(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return ErrTenantHasChildren
	}

	// Cascade RBAC cleanup: remove subjects then roles scoped to this tenant.
	// Subjects first — they reference roles. Both loops are best-effort: a single
	// child failure is logged and the cascade continues rather than aborting.
	if m.rbacManager != nil {
		if err := m.rbacManager.DeleteSubjectsByTenant(ctx, tenantID); err != nil {
			slog.Warn("tenant: failed to list subjects for RBAC cascade cleanup",
				"tenant_id", tenantID,
				"error", err,
			)
		}
		if err := m.rbacManager.DeleteRolesByTenant(ctx, tenantID); err != nil {
			slog.Warn("tenant: failed to list roles for RBAC cascade cleanup",
				"tenant_id", tenantID,
				"error", err,
			)
		}
	}

	// Delete the tenant (soft delete)
	return m.store.DeleteTenant(ctx, tenantID)
}

// ListTenants lists tenants with optional filtering
func (m *Manager) ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error) {
	return m.store.ListTenants(ctx, filter)
}

// GetTenantHierarchy retrieves the hierarchical structure for a tenant
func (m *Manager) GetTenantHierarchy(ctx context.Context, tenantID string) (*business.TenantHierarchy, error) {
	return m.store.GetTenantHierarchy(ctx, tenantID)
}

// GetChildTenants returns all direct child tenants
func (m *Manager) GetChildTenants(ctx context.Context, parentID string) ([]*business.TenantData, error) {
	return m.store.GetChildTenants(ctx, parentID)
}

// GetTenantPath returns the full path from root to the specified tenant
func (m *Manager) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return m.store.GetTenantPath(ctx, tenantID)
}

// IsTenantAncestor checks if one tenant is an ancestor of another
func (m *Manager) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return m.store.IsTenantAncestor(ctx, ancestorID, descendantID)
}

// validateTenantRequest validates a tenant creation/update request
func (m *Manager) validateTenantRequest(req *TenantRequest) error {
	if req.Name == "" {
		return fmt.Errorf("tenant name is required")
	}

	// Validate name format (alphanumeric, hyphens, underscores)
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !nameRegex.MatchString(req.Name) {
		return fmt.Errorf("tenant name must contain only alphanumeric characters, hyphens, and underscores")
	}

	if len(req.Name) > 64 {
		return fmt.Errorf("tenant name must be 64 characters or less")
	}

	if len(req.Description) > 255 {
		return fmt.Errorf("tenant description must be 255 characters or less")
	}

	return nil
}

// validateGitMountPoint calls the MountPointValidator when one is configured.
// Returns a user-facing error (HTTP 422 equivalent) if validation fails.
// When no validator is configured, validation is skipped silently.
func (m *Manager) validateGitMountPoint(ctx context.Context, metadata map[string]string) error {
	if m.validator == nil {
		return nil
	}
	info, err := cfgpkg.ParseConfigSource(metadata)
	if err != nil {
		return fmt.Errorf("invalid config source metadata: %w", err)
	}
	if err := m.validator.ValidateMountPoint(ctx, info, m.secretStore); err != nil {
		return fmt.Errorf("config source validation failed: %w", err)
	}
	return nil
}

// resolveConfigSourceAuditAction determines which audit action to emit (if any)
// based on the old and new config_source_type values and metadata fields.
// Returns ("", "") when no audit event is warranted.
func (m *Manager) resolveConfigSourceAuditAction(oldType, newType string, oldMeta, newMeta map[string]string) (action, url string) {
	const git = string(cfgpkg.ConfigSourceTypeGit)
	newURL := newMeta[cfgpkg.MetaKeyConfigSourceURL]

	switch {
	case oldType != git && newType == git:
		// Transition: no git source → git source
		return "config_source_created", newURL

	case oldType == git && newType != git:
		// Transition: git source → no git source / controller
		return "config_source_deleted", oldMeta[cfgpkg.MetaKeyConfigSourceURL]

	case oldType == git && newType == git:
		// Both are git; emit updated only if URL, branch, or credential changed.
		if oldMeta[cfgpkg.MetaKeyConfigSourceURL] != newURL ||
			oldMeta[cfgpkg.MetaKeyConfigSourceBranch] != newMeta[cfgpkg.MetaKeyConfigSourceBranch] ||
			oldMeta[cfgpkg.MetaKeyConfigSourceCredential] != newMeta[cfgpkg.MetaKeyConfigSourceCredential] {
			return "config_source_updated", newURL
		}
	}
	return "", ""
}

// recordConfigSourceEvent emits a config source audit event. It is fire-and-forget:
// audit failures are logged but do not surface as errors to the caller.
func (m *Manager) recordConfigSourceEvent(ctx context.Context, tenantID, rawURL, action string) {
	if m.auditManager == nil {
		return
	}

	// Extract actor from authenticated context; fall back to "system".
	actor := audit.SystemUserID
	if uid, ok := ctx.Value(ctxkeys.UserIDKey).(string); ok && uid != "" {
		actor = uid
	}

	// Sanitize the URL before including it in any log or audit record.
	sanitizedURL := sanitizeAuditURL(rawURL)

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(actor, business.AuditUserTypeHuman).
		Resource("config_source", tenantID, "").
		Detail("tenant_id", tenantID).
		Detail("url", sanitizedURL).
		Detail("actor", actor)

	if err := m.auditManager.RecordEvent(ctx, event); err != nil {
		slog.Warn("tenant: failed to record config source audit event",
			"action", action,
			"tenant_id", tenantID,
			"error", err,
		)
	}
}

// sanitizeAuditURL removes all userinfo from a URL before including it in audit records.
// Strips username and password entirely — Redacted() only masks passwords, not usernames.
// Returns the raw URL unchanged if parsing fails (URLs are validated before this function).
func sanitizeAuditURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.User = nil
	return parsed.String()
}

// generateTenantID generates a tenant ID from the name
func (m *Manager) generateTenantID(name string) string {
	// Convert to lowercase and replace spaces with hyphens
	id := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(name, "-")
	id = regexp.MustCompile(`-+`).ReplaceAllString(id, "-")
	id = regexp.MustCompile(`^-|-$`).ReplaceAllString(id, "")

	// Add timestamp suffix to ensure uniqueness
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%d", id, timestamp)
}
