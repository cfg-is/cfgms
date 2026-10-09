// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// rootTenantCacheTTL bounds how long a resolved root tenant ID is reused. The
// top-level tenant changes only at bootstrap, so staleness across controller
// nodes is bounded and harmless; this node invalidates immediately on its own
// create/delete.
const rootTenantCacheTTL = 30 * time.Second

// RootTenantID resolves the deployment's root tenant (ADR-025 Decision 1's
// "root"; ADR-032: exactly one root tenant per deployment). The root is
// identified by position, not name: it is the single tenant with no parent,
// whatever its ID (Issue #4542). Fresh deployments name it "root" by convention
// only; a deployment seeded with a top tenant named "default" or "team-root"
// resolves that tenant, with no tenant moved or renamed.
//
// It returns "" — no root — when there are no tenants, and when several tenants
// have no parent (logged as an error). Callers treat "" as fail-closed.
func (m *Manager) RootTenantID(ctx context.Context) string {
	m.rootMu.Lock()
	defer m.rootMu.Unlock()
	if m.rootResolved && time.Since(m.rootResolvedAt) < rootTenantCacheTTL {
		return m.rootID
	}

	id, err := m.resolveRootTenantID(ctx)
	if err != nil {
		// A store error is not cached: the next call retries.
		slog.Error("tenant: failed to resolve the root tenant; treating no tenant as root",
			"error", logging.SanitizeLogValue(err.Error()))
		return ""
	}
	m.rootID, m.rootResolved, m.rootResolvedAt = id, true, time.Now()
	return id
}

func (m *Manager) resolveRootTenantID(ctx context.Context) (string, error) {
	topLevel, err := m.topLevelTenantIDs(ctx)
	if err != nil {
		return "", err
	}
	switch len(topLevel) {
	case 0:
		return "", nil
	case 1:
		return topLevel[0], nil
	default:
		slog.Error("tenant: root tenant is ambiguous — several tenants have no parent; root-scoped access is denied until one remains",
			"top_level_tenants", len(topLevel))
		return "", nil
	}
}

// topLevelTenantIDs returns the IDs of every tenant with no parent.
func (m *Manager) topLevelTenantIDs(ctx context.Context) ([]string, error) {
	tenants, err := m.store.ListTenants(ctx, nil)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, t := range tenants {
		if t.ParentID == "" {
			ids = append(ids, t.ID)
		}
	}
	return ids, nil
}

// isProtectedRootTenant reports whether tenantID is the deployment root, which
// cannot be suspended or deleted. When the root is ambiguous or cannot be
// resolved it fails closed and protects every tenant with no parent, since any
// of them may be the intended root (Issue #4542).
func (m *Manager) isProtectedRootTenant(ctx context.Context, tenantID string) bool {
	if root := m.RootTenantID(ctx); root != "" {
		return tenantID == root
	}
	t, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		// Unknown tenant: the caller's own lookup reports not-found. A store
		// error protects (fail closed).
		return !errors.Is(err, business.ErrTenantDoesNotExist)
	}
	return t.ParentID == ""
}

// checkTopLevelCreatable refuses a tenant with no parent when one already
// exists: a deployment has exactly one root (ADR-032), and a second parentless
// tenant would make the root ambiguous (Issue #4542). This is a fast path that
// spares a write in the common refusal; it is not the guarantee. Two nodes can
// both pass it, so the store's CreateTopLevelTenant is what enforces the
// invariant atomically (Issue #4547).
func (m *Manager) checkTopLevelCreatable(ctx context.Context) error {
	topLevel, err := m.topLevelTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}
	if len(topLevel) > 0 {
		return ErrTopLevelTenantExists
	}
	return nil
}

// invalidateRootTenant drops the cached root so the next call re-resolves.
func (m *Manager) invalidateRootTenant() {
	m.rootMu.Lock()
	m.rootResolved = false
	m.rootMu.Unlock()
}
