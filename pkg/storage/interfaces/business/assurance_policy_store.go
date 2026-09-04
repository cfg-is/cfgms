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

// BlastRadiusPolicy is the per-tenant maximum-target-count override for operator
// payload dispatch (Issue #3698, epic #3571). It is a sibling to AssurancePolicy
// rather than an extra field on it — the two are resolved by the identical
// root-to-leaf override walk (see resolveMaxTargetsForTenant,
// features/controller/api/handlers_runs.go, which copies the walk shape of
// resolveAssuranceRequirement/resolveAssuranceRequirementForPath), but AssurancePolicy's
// per-permission Overrides list has no natural slot for a single per-tenant scalar,
// and the two existing AssurancePolicyStore providers (database, sqlite) persist
// Overrides as one row per permission — bolting a scalar onto that shape would mean
// a schema change to unrelated assurance-policy code for a concept it doesn't own.
type BlastRadiusPolicy struct {
	// TenantID identifies the tenant this override applies to.
	TenantID string

	// MaxTargets, when non-nil, bounds the number of resolved dispatch targets a
	// caller in this tenant may address in a single operator payload. nil means
	// "no override at this tenant" — an ancestor's value, or the resolver's global
	// default if no tenant in the path has one, applies instead.
	MaxTargets *int
}

// BlastRadiusPolicyStore defines the storage interface for per-tenant blast-radius
// overrides (Issue #3698). A conforming implementation is read via the same
// root-to-leaf override walk as AssurancePolicyStore — a parent tenant's MaxTargets
// is the default, and a child tenant's own value narrows it — rather than a new
// resolution algorithm.
type BlastRadiusPolicyStore interface {
	// GetPolicy returns the blast-radius override for the given tenant. When no
	// record exists, it returns {TenantID: tenantID, MaxTargets: nil} without
	// error — "no override" and "no data" are equivalent here.
	GetPolicy(ctx context.Context, tenantID string) (*BlastRadiusPolicy, error)

	// SetPolicy replaces the tenant's MaxTargets override. A nil policy or empty
	// TenantID returns an error. MaxTargets == nil clears the override.
	SetPolicy(ctx context.Context, policy *BlastRadiusPolicy) error
}
