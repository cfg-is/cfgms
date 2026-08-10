// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"time"
)

// ErrTenantCrossingNotFound indicates no tenant-crossing record exists for the given ID.
var ErrTenantCrossingNotFound = errors.New("tenant crossing not found")

// TenantCrossingKind distinguishes ADR-025 Decision 2's two crossing mechanisms.
type TenantCrossingKind string

const (
	// TenantCrossingKindGrant is client-granted, time-boxed, revocable support access
	// (ADR-025 Decision 2(a)). Created by an MSP administrator for their own tenant;
	// no justification required.
	TenantCrossingKindGrant TenantCrossingKind = "grant"
	// TenantCrossingKindBreakGlass is a SaaS-operator-invoked, justified, time-boxed
	// emergency elevation (ADR-025 Decision 2(b)). Distinct from the system-resource-only
	// emergency.break-glass RBAC template (features/rbac/templates.go) — that template
	// grants emergency.access on system resources only and must never be reused here.
	TenantCrossingKindBreakGlass TenantCrossingKind = "break-glass"
)

// TenantCrossing is a time-boxed, revocable authorization for PrincipalID (a root-scoped
// caller per ADR-025 Amendment 1 A1.3) to act within TenantID and its descendants,
// despite the ADR-025 Decision 1 root<->MSP boundary that would otherwise apply.
type TenantCrossing struct {
	ID            string
	TenantID      string // the MSP subtree root this crossing covers
	PrincipalID   string // the root-scoped principal granted temporary access
	Kind          TenantCrossingKind
	GrantedBy     string // principal ID that created the record (MSP admin for grants, self for break-glass)
	Justification string // required by the handler for break-glass; optional for grants
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time // nil while active
}

// TenantCrossingStore persists ADR-025 Decision 2 grant and break-glass records. Both
// crossing kinds share one store: they are the same shape (a time-boxed, revocable,
// auditable authorization record), differing only in Kind, GrantedBy and justification
// requirements — which the calling handler enforces, not the store.
type TenantCrossingStore interface {
	CreateTenantCrossing(ctx context.Context, c *TenantCrossing) error
	GetTenantCrossing(ctx context.Context, id string) (*TenantCrossing, error)
	// ListTenantCrossings returns every crossing (active, expired, and revoked) scoped
	// to tenantID, newest first — the MSP's own tenant-crossing activity view (ADR-025
	// Decision 2: both crossing kinds must be visible to the affected MSP).
	ListTenantCrossings(ctx context.Context, tenantID string) ([]*TenantCrossing, error)
	// HasActiveTenantCrossing reports whether principalID currently holds a non-expired,
	// non-revoked crossing whose TenantID is exactly tenantID. Callers resolve ancestry
	// themselves (via TenantStore.GetTenantPath) and probe each candidate tenantID in the
	// caller's path — this keeps the store free of a cross-package dependency on TenantStore.
	HasActiveTenantCrossing(ctx context.Context, principalID, tenantID string) (bool, error)
	RevokeTenantCrossing(ctx context.Context, id string) error

	Initialize(ctx context.Context) error
	Close() error
}
