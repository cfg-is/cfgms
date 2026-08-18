// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
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

// InvalidateConfigCache evicts the cached source resolution for tenantID.
// Called by the steward-move handler to invalidate both source and destination tenants
// after a move, so the next config resolution picks up the correct tenant path.
// No-op when no config router is wired (single-node dev/test setups).
func (m *Manager) InvalidateConfigCache(tenantID string) {
	if m.router != nil {
		m.router.InvalidateTenantCache(tenantID)
	}
}

// CreateTenant creates a new tenant with validation and RBAC setup
func (m *Manager) CreateTenant(ctx context.Context, req *TenantRequest) (*business.TenantData, error) {
	// When an explicit ID is provided without a name, use the ID as the display name.
	if req.ID != "" && req.Name == "" {
		req.Name = req.ID
	}

	// Validate the request
	if err := m.validateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Generate tenant ID from name, or use the explicit ID when provided.
	// Resolved before any config source validation because the credential
	// reference is checked against this ID, and that check must run before
	// validateGitMountPoint dereferences the reference against the secret store.
	tenantID := m.generateTenantID(req.Name)
	if req.ID != "" {
		if err := validateExplicitTenantID(req.ID); err != nil {
			return nil, fmt.Errorf("invalid explicit tenant ID: %w", err)
		}
		tenantID = req.ID
	}

	if err := validateCredentialRefOwnership(tenantID, req.Metadata); err != nil {
		return nil, err
	}

	// Validate git mount point when config_source_type is "git"
	if req.Metadata[cfgpkg.MetaKeyConfigSourceType] == string(cfgpkg.ConfigSourceTypeGit) {
		if err := m.validateGitMountPoint(ctx, req.Metadata); err != nil {
			return nil, err
		}
	}

	// Reject tenant creation under a suspended parent or a parent with a pending deletion.
	// Defense-in-depth: prevents subtree membership from growing under an in-flight deletion hold.
	// If the parent does not yet exist, the storage layer's constraints enforce that;
	// we only need to check the state of parents that do exist.
	if req.ParentID != "" {
		parent, err := m.store.GetTenant(ctx, req.ParentID)
		if err != nil && !errors.Is(err, business.ErrTenantDoesNotExist) {
			return nil, fmt.Errorf("failed to look up parent tenant: %w", err)
		}
		if err == nil {
			if parent.Status == business.TenantStatusSuspended {
				return nil, fmt.Errorf("cannot create tenant under a suspended parent (%s)", req.ParentID)
			}
			if _, err := m.store.GetPendingDeletion(ctx, req.ParentID); err == nil {
				return nil, fmt.Errorf("cannot create tenant under a parent with a pending deletion (%s)", req.ParentID)
			}
		}
	}

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
			// Rollback tenant creation if RBAC setup fails. If the rollback itself
			// fails the tenant record is orphaned in storage, so surface the error
			// loudly for operators to reconcile rather than swallowing it.
			if delErr := m.store.DeleteTenant(ctx, tenantID); delErr != nil {
				slog.Error("tenant: failed to roll back tenant after RBAC setup failure; orphaned tenant record left in storage",
					"tenant_id", logging.SanitizeLogValue(tenantID),
					"rbac_error", logging.SanitizeLogValue(err.Error()),
					"rollback_error", logging.SanitizeLogValue(delErr.Error()),
				)
			}
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

	// A tenant may only point at credentials in its own secret namespace.
	// Checked before validateGitMountPoint, which dereferences the reference
	// against the secret store and hands the value to the caller-chosen host.
	if err := validateCredentialRefOwnership(tenantID, req.Metadata); err != nil {
		return nil, err
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

// CascadeSuspendResult describes the outcome of a cascading suspend operation.
type CascadeSuspendResult struct {
	// Target is the tenant ID that was directly suspended.
	Target string `json:"target"`
	// NewlyCascadeSuspended lists descendant IDs that were not already independently
	// suspended and are now cascade-suspended as a side effect.
	NewlyCascadeSuspended []string `json:"newly_cascade_suspended"`
	// AlreadySuspended lists descendant IDs that were already independently
	// (DirectlySuspended) suspended; they now also carry CascadeSuspendedFrom.
	AlreadySuspended []string `json:"already_suspended"`
}

// CascadeRestoreResult describes the outcome of a cascading restore operation.
type CascadeRestoreResult struct {
	// Target is the tenant ID whose direct suspension was cleared.
	Target string `json:"target"`
	// Restored lists descendant IDs whose only suspension reason was the ancestor
	// cascade; they are now fully active.
	Restored []string `json:"restored"`
	// StillSuspended lists descendant IDs whose cascade from the target was lifted but
	// that remain suspended for another reason: either their own DirectlySuspended flag,
	// or an intermediate ancestor between them and the target that is itself still
	// suspended. Their cascade provenance is re-pointed at that ancestor so a later
	// restore of it reactivates them.
	StillSuspended []string `json:"still_suspended"`
}

// SuspendTenant suspends the target tenant and its entire subtree (ADR-027 Decision 1).
// The target gains DirectlySuspended=true; each descendant gains CascadeSuspendedFrom
// set to tenantID, keeping any pre-existing DirectlySuspended flag (ADR-027 Decision 2).
//
// CascadeSuspendedFrom holds the OUTERMOST suspended ancestor, so a descendant already
// cascade-suspended by a tenant above the target keeps that provenance instead of being
// re-pointed at the (deeper) target. Overwriting it would let a restore of the target lift
// a containment imposed higher in the hierarchy.
//
// A cycle in the tenant hierarchy (data corruption) causes an error rather than an
// infinite loop. An audit event is recorded on success (fire-and-forget).
func (m *Manager) SuspendTenant(ctx context.Context, tenantID string) (*CascadeSuspendResult, error) {
	if tenantID == "default" {
		return nil, ErrCannotSuspendDefault
	}

	result := &CascadeSuspendResult{
		Target:                tenantID,
		NewlyCascadeSuspended: []string{},
		AlreadySuspended:      []string{},
	}

	// BFS walk of the subtree. visited tracks IDs to detect data-corruption cycles.
	visited := map[string]bool{tenantID: true}
	queue := []string{tenantID}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		current, err := m.store.GetTenant(ctx, currentID)
		if err != nil {
			return nil, err
		}

		if currentID == tenantID {
			current.DirectlySuspended = true
			current.Status = business.TenantStatusSuspended
		} else {
			// Descendant: record cascade provenance. Keep DirectlySuspended if already set.
			//
			// Only claim provenance when the existing value names a tenant inside this
			// subtree (BFS is level-order, so every already-visited ID is the target or a
			// node above `current` within the target's subtree). Such a value is deeper
			// than the target and is therefore superseded by it. A value naming a tenant
			// outside the subtree is a strict ancestor of the target — a broader
			// suspension — and must survive, otherwise restoring the target would
			// reactivate a tenant contained by that outer suspension.
			if current.CascadeSuspendedFrom == nil || visited[*current.CascadeSuspendedFrom] {
				ancestorID := tenantID
				current.CascadeSuspendedFrom = &ancestorID
			}
			if current.DirectlySuspended {
				result.AlreadySuspended = append(result.AlreadySuspended, currentID)
			} else {
				current.Status = business.TenantStatusSuspended
				result.NewlyCascadeSuspended = append(result.NewlyCascadeSuspended, currentID)
			}
		}

		if err := m.store.UpdateTenant(ctx, current); err != nil {
			return nil, err
		}

		children, err := m.store.GetChildTenants(ctx, currentID)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if visited[child.ID] {
				return nil, fmt.Errorf("cycle detected in tenant hierarchy at %s", child.ID)
			}
			visited[child.ID] = true
			queue = append(queue, child.ID)
		}
	}

	// Retrieve tenant name for the audit event (the GetTenant above fetched it, but
	// we only have it within the loop; re-fetch is fine — audit is best-effort).
	if t, err := m.store.GetTenant(ctx, tenantID); err == nil {
		m.recordTenantLifecycleEvent(ctx, tenantID, t.Name, "tenant_suspended")
	}

	return result, nil
}

// restoreWalkNode is one work item of RestoreTenant's BFS. suspendedAncestor is the ID
// of the outermost ancestor of this node's CHILDREN that is still suspended once the
// restore has been applied to this node, or nil when no such ancestor remains. It is the
// containment carrier: a child may only become active when it is nil.
type restoreWalkNode struct {
	id                string
	suspendedAncestor *string
}

// childProvenanceAfterRestore computes the value restoreWalkNode.suspendedAncestor must
// carry for td's children, given td's post-restore state. If td is still cascade-suspended,
// its children are contained by the same outer ancestor; if td itself remains suspended for
// any other reason, td is that ancestor; otherwise the subtree below td is unconstrained.
func childProvenanceAfterRestore(td *business.TenantData) *string {
	if td.CascadeSuspendedFrom != nil {
		ancestorID := *td.CascadeSuspendedFrom
		return &ancestorID
	}
	if td.Status == business.TenantStatusSuspended {
		ancestorID := td.ID
		return &ancestorID
	}
	return nil
}

// RestoreTenant clears the target tenant's own suspension and lifts only the cascade
// component on descendants (ADR-027 Decision 2). Descendants that carry their own
// DirectlySuspended flag remain suspended — the cascade effect is removed but the
// independent suspension is not.
//
// A descendant is reactivated only when every tenant between it and the restore target —
// and the target itself — comes out of the restore active. Where an ancestor stays
// suspended (its own DirectlySuspended flag, or a cascade from above the target), the
// descendant's cascade provenance is re-pointed at that ancestor and it stays suspended.
// Reactivating it instead would let an operator holding tenant:manage inside a contained
// subtree escape a suspension imposed above them (ADR-027 Decision 1 containment).
//
// An audit event is recorded on success (fire-and-forget).
func (m *Manager) RestoreTenant(ctx context.Context, tenantID string) (*CascadeRestoreResult, error) {
	result := &CascadeRestoreResult{
		Target:         tenantID,
		Restored:       []string{},
		StillSuspended: []string{},
	}

	// Clear the target's own direct suspension.
	existing, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	existing.DirectlySuspended = false
	// Keep cascade flag if it exists (target may be cascade-suspended by its own ancestor).
	if existing.CascadeSuspendedFrom == nil {
		existing.Status = business.TenantStatusActive
	}
	if err := m.store.UpdateTenant(ctx, existing); err != nil {
		return nil, err
	}

	// BFS walk: lift CascadeSuspendedFrom == tenantID on all descendants, carrying the
	// containment state of each node down to its children.
	visited := map[string]bool{tenantID: true}
	queue := []restoreWalkNode{{id: tenantID, suspendedAncestor: childProvenanceAfterRestore(existing)}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		children, err := m.store.GetChildTenants(ctx, current.id)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if visited[child.ID] {
				return nil, fmt.Errorf("cycle detected in tenant hierarchy at %s", child.ID)
			}
			visited[child.ID] = true

			if child.CascadeSuspendedFrom == nil || *child.CascadeSuspendedFrom != tenantID {
				// Not part of this cascade: its provenance names a tenant above the
				// target, which this restore does not touch. Its own state is unchanged,
				// so it carries its own containment onwards.
				queue = append(queue, restoreWalkNode{id: child.ID, suspendedAncestor: childProvenanceAfterRestore(child)})
				continue
			}

			// The target's cascade is lifted; any suspension still standing between the
			// target and this child takes its place as the provenance. The pointer is
			// copied rather than shared so sibling records never alias one string.
			child.CascadeSuspendedFrom = nil
			if current.suspendedAncestor != nil {
				ancestorID := *current.suspendedAncestor
				child.CascadeSuspendedFrom = &ancestorID
			}
			switch {
			case child.DirectlySuspended || child.CascadeSuspendedFrom != nil:
				child.Status = business.TenantStatusSuspended
				result.StillSuspended = append(result.StillSuspended, child.ID)
			default:
				child.Status = business.TenantStatusActive
				result.Restored = append(result.Restored, child.ID)
			}
			if err := m.store.UpdateTenant(ctx, child); err != nil {
				return nil, err
			}
			queue = append(queue, restoreWalkNode{id: child.ID, suspendedAncestor: childProvenanceAfterRestore(child)})
		}
	}

	m.recordTenantLifecycleEvent(ctx, tenantID, existing.Name, "tenant_restored")

	return result, nil
}

// recordTenantLifecycleEvent emits a tenant lifecycle audit event. It is
// fire-and-forget: audit failures are logged but do not surface to the caller.
func (m *Manager) recordTenantLifecycleEvent(ctx context.Context, tenantID, tenantName, action string) {
	if m.auditManager == nil {
		return
	}

	actor := audit.SystemUserID
	if uid, ok := ctx.Value(ctxkeys.UserIDKey).(string); ok && uid != "" {
		actor = uid
	}

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(actor, business.AuditUserTypeHuman).
		Resource("tenant", tenantID, tenantName).
		Detail("tenant_id", tenantID).
		Detail("actor", actor)

	if err := m.auditManager.RecordEvent(ctx, event); err != nil {
		slog.Warn("tenant: failed to record tenant lifecycle audit event",
			"action", action,
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
	}
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

	// Hard-delete the tenant row from storage.
	return m.store.DeleteTenant(ctx, tenantID)
}

// RequestTenantDeletion begins the ADR-027 Decision 3 deletion pipeline for
// tenantID's subtree. The entire subtree must already be suspended; if any
// descendant (including the root) is not fully suspended, an error wrapping
// ErrTenantNotFullySuspended is returned naming the first unsuspended tenant
// found. On success the hold-period timer starts and a PendingDeletion record
// is written with the pinned member set.
func (m *Manager) RequestTenantDeletion(ctx context.Context, tenantID, requesterID string, holdPeriod time.Duration) (*business.PendingDeletion, error) {
	if tenantID == "default" {
		return nil, fmt.Errorf("cannot delete default tenant")
	}

	// BFS walk of the subtree; collect member IDs and reject any unsuspended tenant.
	visited := map[string]bool{tenantID: true}
	queue := []string{tenantID}
	var memberIDs []string

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		current, err := m.store.GetTenant(ctx, currentID)
		if err != nil {
			return nil, err
		}

		if current.Status != business.TenantStatusSuspended {
			return nil, fmt.Errorf("%w: first unsuspended tenant: %s", ErrTenantNotFullySuspended, currentID)
		}

		memberIDs = append(memberIDs, currentID)

		children, err := m.store.GetChildTenants(ctx, currentID)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if visited[child.ID] {
				return nil, fmt.Errorf("cycle detected in tenant hierarchy at %s", child.ID)
			}
			visited[child.ID] = true
			queue = append(queue, child.ID)
		}
	}

	now := time.Now()
	pending := &business.PendingDeletion{
		SubtreeRootID:   tenantID,
		RequestedBy:     requesterID,
		RequestedAt:     now,
		EligibleAt:      now.Add(holdPeriod),
		State:           business.DeletionStateHold,
		PinnedMemberIDs: memberIDs,
	}

	if err := m.store.RequestDeletion(ctx, pending); err != nil {
		return nil, err
	}

	m.recordTenantLifecycleEvent(ctx, tenantID, tenantID, "tenant_deletion_requested")
	return pending, nil
}

// CancelTenantDeletion cancels a pending Hold/Eligible deletion, returning the
// subtree to plain Suspended state (ADR-027 Decision 4). Never partial, never Active.
func (m *Manager) CancelTenantDeletion(ctx context.Context, tenantID string) error {
	if err := m.store.CancelDeletion(ctx, tenantID); err != nil {
		return err
	}
	m.recordTenantLifecycleEvent(ctx, tenantID, tenantID, "tenant_deletion_cancelled")
	return nil
}

// ApproveTenantDeletion executes the dual-control terminal step (ADR-027 Decision 4).
// The store atomically verifies hold-period elapsed, dual-control (when required), and
// membership match, then hard-deletes the entire subtree. RBAC cleanup runs afterward
// on the returned IDs (best-effort, fire-and-forget on individual tenant failures).
func (m *Manager) ApproveTenantDeletion(ctx context.Context, tenantID, approverID string, requireDualControl bool) ([]string, error) {
	if tenantID == "default" {
		return nil, fmt.Errorf("cannot delete default tenant")
	}

	deleted, err := m.store.ApproveDeletion(ctx, tenantID, approverID, requireDualControl, time.Now())
	if err != nil {
		return nil, err
	}

	// RBAC cleanup for each deleted tenant (best-effort).
	if m.rbacManager != nil {
		for _, id := range deleted {
			if err := m.rbacManager.DeleteSubjectsByTenant(ctx, id); err != nil {
				slog.Warn("tenant: failed to delete subjects for deleted tenant",
					"tenant_id", logging.SanitizeLogValue(id),
					"error", logging.SanitizeLogValue(err.Error()),
				)
			}
			if err := m.rbacManager.DeleteRolesByTenant(ctx, id); err != nil {
				slog.Warn("tenant: failed to delete roles for deleted tenant",
					"tenant_id", logging.SanitizeLogValue(id),
					"error", logging.SanitizeLogValue(err.Error()),
				)
			}
		}
	}

	m.recordTenantLifecycleEvent(ctx, tenantID, tenantID, "tenant_deletion_approved")
	return deleted, nil
}

// GetPendingDeletion returns the current pending-deletion record for tenantID, if any.
// Returns ErrPendingDeletionNotFound when none exists.
func (m *Manager) GetPendingDeletion(ctx context.Context, tenantID string) (*business.PendingDeletion, error) {
	return m.store.GetPendingDeletion(ctx, tenantID)
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

// validateCredentialRefOwnership enforces that a tenant's config_source_credential
// names a secret inside that tenant's own namespace.
//
// The reference is a secret-store key in "<tenant_id>/<secret_key>" form (see
// pkg/secrets/providers/sops and pkg/secrets/providers/openbao splitKey), and the
// consuming sinks — pkg/config's MountPointValidator and the configrouting git
// store — fetch it and send the value as HTTP Basic auth to the host named by
// config_source_url. Without this constraint a tenant-scoped principal holding
// tenant:update could write "victim-tenant/git-token" into its own tenant
// alongside an attacker-controlled HTTPS URL and have the controller deliver
// another tenant's credential to that host: the scope check on which tenant row
// is mutated says nothing about the contents written into it, and the SSRF guard
// in validateSourceURL deliberately permits public HTTPS hosts.
//
// Ownership is exact: a parent may not reference a child's secret and vice versa,
// so a compromised tenant at any depth cannot reach outside its own namespace.
// The secret key itself must be a single path segment, otherwise a reference such
// as "self/../victim/git-token" would satisfy the prefix while resolving into
// another tenant's storage path.
//
// The reference is checked on every write that carries it, not only when
// config_source_type is "git": metadata is persisted wholesale, and a value
// stored under a non-git type is live the moment the type changes.
func validateCredentialRefOwnership(tenantID string, metadata map[string]string) error {
	ref, ok := metadata[cfgpkg.MetaKeyConfigSourceCredential]
	if !ok || ref == "" {
		return nil
	}

	owner, key, found := strings.Cut(ref, "/")
	if !found || owner == "" || key == "" {
		return fmt.Errorf("invalid config source metadata: %s must be in \"<tenant_id>/<secret_key>\" form",
			cfgpkg.MetaKeyConfigSourceCredential)
	}
	if owner != tenantID {
		return fmt.Errorf("invalid config source metadata: %s references tenant %q, but a tenant may only reference secrets in its own namespace (%q)",
			cfgpkg.MetaKeyConfigSourceCredential, owner, tenantID)
	}
	if strings.ContainsAny(key, "/\\") || key == "." || key == ".." {
		return fmt.Errorf("invalid config source metadata: %s secret key %q must be a single path segment",
			cfgpkg.MetaKeyConfigSourceCredential, key)
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
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
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

// k8sNameRegex matches Kubernetes-compatible DNS label names per RFC 1123.
var k8sNameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// validateExplicitTenantID validates a caller-supplied tenant ID against
// Kubernetes RFC 1123 DNS label rules: lowercase alphanumeric and hyphens only,
// no leading/trailing hyphens, max 63 characters.
func validateExplicitTenantID(id string) error {
	if id == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	if len(id) > 63 {
		return fmt.Errorf("tenant ID must be 63 characters or less (Kubernetes DNS label limit), got %d", len(id))
	}
	if !k8sNameRegex.MatchString(id) {
		return fmt.Errorf("tenant ID %q is not Kubernetes-compatible: must contain only lowercase alphanumeric characters and hyphens, must not start or end with a hyphen", id)
	}
	return nil
}
