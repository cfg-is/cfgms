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

// RootTenantID resolves the deployment's top-level tenant (ADR-025 Decision 1's
// "root"; ADR-032: exactly one root tenant per deployment) — Issue #4542.
//
//   - A top-level tenant whose ID is RootTenantID ("root") is the root when it
//     exists. New deployments create it at bootstrap. A "root" with a parent is
//     never the root (CreateTenant refuses one; this guards rows written by other
//     paths).
//   - Otherwise the single tenant with no parent is the root. Deployments seeded
//     before "root" was standardised (e.g. a top-level "team-root") keep their
//     existing tree: re-parenting would shift every tenant's config-inheritance
//     level, which is its index in the tenant path.
//   - With no tenants at all, RootTenantID is returned, so the first top-level
//     tenant a fresh deployment creates should be "root".
//   - With several parentless tenants and none named "root" the root is
//     ambiguous: "" is returned and an error is logged. Callers treat "" as "no
//     tenant is root" and fail closed.
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
	if t, err := m.store.GetTenant(ctx, RootTenantID); err == nil {
		if t.ParentID == "" {
			return RootTenantID, nil
		}
	} else if !errors.Is(err, business.ErrTenantDoesNotExist) {
		return "", err
	}

	tenants, err := m.store.ListTenants(ctx, nil)
	if err != nil {
		return "", err
	}
	var topLevel []string
	for _, t := range tenants {
		if t.ParentID == "" {
			topLevel = append(topLevel, t.ID)
		}
	}
	switch len(topLevel) {
	case 0:
		return RootTenantID, nil
	case 1:
		return topLevel[0], nil
	default:
		slog.Error("tenant: root tenant is ambiguous — several top-level tenants and none named root; root-scoped access is denied until one root exists",
			"top_level_tenants", len(topLevel))
		return "", nil
	}
}

// isProtectedRootTenant reports whether tenantID is the deployment root, which
// cannot be suspended or deleted: the top-level "root", or the resolved root of a
// deployment seeded before "root" was standardised (Issue #4542). When the root is
// ambiguous or cannot be resolved it fails closed and protects every top-level
// tenant, since any of them may be the intended root.
func (m *Manager) isProtectedRootTenant(ctx context.Context, tenantID string) bool {
	root := m.RootTenantID(ctx)
	if root != "" {
		return tenantID == root
	}
	if tenantID == RootTenantID {
		return true
	}
	t, err := m.store.GetTenant(ctx, tenantID)
	if err != nil {
		// Unknown tenant: the caller's own lookup reports not-found; a store error
		// protects (fail closed).
		return !errors.Is(err, business.ErrTenantDoesNotExist)
	}
	return t.ParentID == ""
}

// checkRootCreatable refuses to create a top-level "root" beside an existing
// top-level tenant. "root" would win RootTenantID resolution and leave the
// existing tree outside root's subtree, cutting root-scoped principals off from
// every tenant in it (Issue #4542). A deployment seeded before "root" was
// standardised keeps its existing top tenant as root.
func (m *Manager) checkRootCreatable(ctx context.Context) error {
	tenants, err := m.store.ListTenants(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}
	for _, t := range tenants {
		if t.ParentID == "" && t.ID != RootTenantID {
			return ErrRootTenantConflict
		}
	}
	return nil
}

// invalidateRootTenant drops the cached root so the next call re-resolves.
func (m *Manager) invalidateRootTenant() {
	m.rootMu.Lock()
	m.rootResolved = false
	m.rootMu.Unlock()
}
