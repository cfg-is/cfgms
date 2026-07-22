// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the AssurancePolicyStore interface for per-tenant
// identity-assurance policy overrides (ADR-021, Issue #2845).
package business

import "context"

// AssurancePolicyOverride configures a per-permission assurance floor override
// for a given tenant.
//
// MinOverride mirrors the underlying integer values of session.AssuranceLevel
// (0=Machine, 1=Basic, 2=Strong). Callers in features/controller/api are
// responsible for converting between the two; this package does not import
// pkg/session to avoid adding a cross-package dependency for a single int type.
type AssurancePolicyOverride struct {
	// PermissionID is the RBAC permission identifier this override applies to.
	PermissionID string

	// MinOverride, when non-nil, replaces the global permissionAssurance floor
	// for PermissionID within this tenant. Values mirror session.AssuranceLevel
	// (0=Machine, 1=Basic, 2=Strong); callers convert before storage.
	MinOverride *int

	// RequireUserPresence, when true, mandates user-presence verification for
	// PermissionID within this tenant regardless of the assurance level.
	RequireUserPresence bool
}

// AssurancePolicy is the full set of per-permission overrides for a single tenant.
type AssurancePolicy struct {
	// TenantID identifies the tenant this policy applies to.
	TenantID string

	// Overrides is the list of per-permission overrides. A nil or empty slice
	// means no overrides are in effect for this tenant (global defaults apply).
	Overrides []AssurancePolicyOverride
}

// AssurancePolicyStore defines the storage interface for per-tenant assurance-policy
// overrides (ADR-021, Issue #2845).
type AssurancePolicyStore interface {
	// GetPolicy returns the assurance-policy overrides for the given tenant.
	// When no record exists, it returns {TenantID: tenantID, Overrides: nil}
	// without error — "no override" and "no data" are equivalent here.
	GetPolicy(ctx context.Context, tenantID string) (*AssurancePolicy, error)

	// SetPolicy replaces the tenant's full override set in one call.
	// A nil policy or empty TenantID returns an error.
	// A SetPolicy call with an empty Overrides slice clears all overrides for
	// the tenant (full-replace semantics).
	SetPolicy(ctx context.Context, policy *AssurancePolicy) error
}
