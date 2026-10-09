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

// ErrTenantCrossingNotPending indicates ApproveTenantCrossing was called on a crossing
// that is not pending, unexpired and unrevoked (already approved, expired, or revoked).
var ErrTenantCrossingNotPending = errors.New("tenant crossing is not pending approval")

// ErrTenantCrossingPrincipalRequired indicates a break-glass crossing was created
// without the PrincipalID it admits.
var ErrTenantCrossingPrincipalRequired = errors.New("break-glass tenant crossing requires a principal ID")

// ErrGrantPrincipalNotAllowed indicates a grant crossing was created naming a principal;
// a grant admits any root principal and names none.
var ErrGrantPrincipalNotAllowed = errors.New("grant tenant crossing must not name a principal")

// TenantCrossingReasonCategory classifies why a break-glass crossing was invoked
// (ADR-025 Amendment 8). Empty for grants.
type TenantCrossingReasonCategory string

const (
	TenantCrossingReasonAccountRecovery  TenantCrossingReasonCategory = "account_recovery"
	TenantCrossingReasonSecurityIncident TenantCrossingReasonCategory = "security_incident"
	TenantCrossingReasonLegalRequest     TenantCrossingReasonCategory = "legal_request"
	TenantCrossingReasonBillingDispute   TenantCrossingReasonCategory = "billing_dispute"
)

// ValidTenantCrossingReasonCategory reports whether c is one of the defined, non-empty
// reason categories.
func ValidTenantCrossingReasonCategory(c TenantCrossingReasonCategory) bool {
	switch c {
	case TenantCrossingReasonAccountRecovery,
		TenantCrossingReasonSecurityIncident,
		TenantCrossingReasonLegalRequest,
		TenantCrossingReasonBillingDispute:
		return true
	}
	return false
}

// TenantCrossingApprovalState is the approval state of a crossing. Only approved
// crossings admit requests.
type TenantCrossingApprovalState string

const (
	TenantCrossingApprovalApproved TenantCrossingApprovalState = "approved"
	TenantCrossingApprovalPending  TenantCrossingApprovalState = "pending"
)

// ValidateTenantCrossingForCreate applies the rules every provider enforces on create:
// a break-glass names its principal, a grant names none. It returns the approval state
// to persist (an unset state is stored as approved).
func ValidateTenantCrossingForCreate(c *TenantCrossing) (TenantCrossingApprovalState, error) {
	if c == nil {
		return "", errors.New("tenant crossing cannot be nil")
	}
	if c.ID == "" || c.TenantID == "" {
		return "", errors.New("tenant crossing ID and tenant ID are required")
	}
	switch c.Kind {
	case TenantCrossingKindGrant:
		if c.PrincipalID != "" {
			return "", ErrGrantPrincipalNotAllowed
		}
	case TenantCrossingKindBreakGlass:
		if c.PrincipalID == "" {
			return "", ErrTenantCrossingPrincipalRequired
		}
	default:
		return "", errors.New("tenant crossing kind must be grant or break-glass")
	}
	if c.ReasonCategory != "" && !ValidTenantCrossingReasonCategory(c.ReasonCategory) {
		return "", errors.New("tenant crossing reason category is not recognised")
	}
	switch c.ApprovalState {
	case "":
		return TenantCrossingApprovalApproved, nil
	case TenantCrossingApprovalApproved, TenantCrossingApprovalPending:
		return c.ApprovalState, nil
	}
	return "", errors.New("tenant crossing approval state must be approved or pending")
}

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
	PrincipalID   string // break-glass: the root-scoped principal admitted; grant: always empty (a grant admits any root principal)
	Kind          TenantCrossingKind
	GrantedBy     string // principal ID that created the record (MSP admin for grants, self for break-glass)
	Justification string // required by the handler for break-glass; optional for grants
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time // nil while active

	ReasonCategory TenantCrossingReasonCategory // break-glass reason; empty for grants
	ApprovalState  TenantCrossingApprovalState  // approved or pending; unset on create is stored as approved
	ApprovedBy     string                       // approver principal ID; empty until approved via ApproveTenantCrossing
	ApprovedAt     *time.Time                   // nil until approved via ApproveTenantCrossing
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
	// HasActiveTenantCrossing reports whether principalID currently holds an approved,
	// non-expired, non-revoked crossing whose TenantID is exactly tenantID. An active
	// approved grant on tenantID satisfies it for any principalID; a break-glass only for
	// its own principal. Pending crossings never satisfy it. Callers resolve ancestry
	// themselves (via TenantStore.GetTenantPath) and probe each candidate tenantID in the
	// caller's path — this keeps the store free of a cross-package dependency on TenantStore.
	HasActiveTenantCrossing(ctx context.Context, principalID, tenantID string) (bool, error)
	RevokeTenantCrossing(ctx context.Context, id string) error
	// ApproveTenantCrossing atomically moves a pending, unexpired, unrevoked crossing to
	// approved, recording approverID and at, and resetting ExpiresAt to newExpiresAt. It
	// returns ErrTenantCrossingNotPending when the crossing is in any other state and
	// ErrTenantCrossingNotFound when absent.
	ApproveTenantCrossing(ctx context.Context, id, approverID string, at, newExpiresAt time.Time) error
	// ListActiveTenantCrossings returns every approved, unexpired, unrevoked crossing as of
	// now. Pending crossings are not included.
	ListActiveTenantCrossings(ctx context.Context, now time.Time) ([]*TenantCrossing, error)

	Initialize(ctx context.Context) error
	Close() error
}
