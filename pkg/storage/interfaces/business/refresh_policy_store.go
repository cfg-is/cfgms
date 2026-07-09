// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the RefreshPolicyStore interface for per-tenant
// registration-refresh policy (ADR-010 §4, Issue #2093).
package business

import "context"

// RefreshPolicy describes how the controller handles registration-refresh
// requests from archived or dormant stewards within a given tenant.
type RefreshPolicy struct {
	// TenantID is the tenant this policy applies to.
	TenantID string

	// Mode controls the default disposition for incoming refresh requests:
	//   "auto_accept"      — approve automatically when provenance score is sufficient
	//   "require_approval" — queue for manual operator review (default, ADR-010 §4)
	//   "reject"           — deny all refresh requests for this tenant
	Mode string

	// MaxDormancyDays is the maximum number of days a steward may remain in the
	// archived state before being transitioned to dormant and auto-rejected.
	// Nil means the dormancy backstop is disabled (default OFF, ADR-010 §4).
	MaxDormancyDays *int
}

// RefreshPolicyStore defines the storage interface for per-tenant refresh policies.
type RefreshPolicyStore interface {
	// GetPolicy returns the refresh policy for the given tenant.
	// When no record exists, it returns a default policy of
	// {Mode: "require_approval", MaxDormancyDays: nil} without error.
	GetPolicy(ctx context.Context, tenantID string) (*RefreshPolicy, error)

	// SetPolicy creates or replaces the refresh policy for the tenant identified
	// by policy.TenantID. A nil policy returns an error.
	SetPolicy(ctx context.Context, policy *RefreshPolicy) error
}
