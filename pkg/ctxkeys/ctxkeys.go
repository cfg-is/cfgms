// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package ctxkeys is the shared context-key registry usable from platform and feature packages —
// defined here to avoid cross-feature imports.
package ctxkeys

// tenantIDKeyType is unexported to prevent external construction and key aliasing.
type tenantIDKeyType struct{}

// TenantID is the canonical context key for the authenticated tenant ID.
// Set by the auth middleware after validating an API key and read by
// config handlers, service methods, and terminal session managers to enforce tenant isolation.
var TenantID = tenantIDKeyType{}

// correlationIDKeyType is unexported so no external package can construct a value of this type,
// preventing key aliasing across package boundaries (the standard Go "opaque key" idiom).
type correlationIDKeyType struct{}

// CorrelationIDKey is the single canonical context key for correlation IDs.
// Both pkg/logging and pkg/telemetry store and read correlation IDs under this key,
// so that logging.WithCorrelation and telemetry.GetCorrelationID share the same slot.
var CorrelationIDKey = correlationIDKeyType{}

// userIDKeyType is unexported to prevent external construction and key aliasing.
type userIDKeyType struct{}

// UserIDKey is the canonical context key for the authenticated user ID.
var UserIDKey = userIDKeyType{}

// authClaimsKeyType is unexported to prevent external construction and key aliasing.
type authClaimsKeyType struct{}

// AuthClaimsKey is the canonical context key for authentication claims (e.g., JWT claims map).
var AuthClaimsKey = authClaimsKeyType{}

// tenantScopeKeyType is unexported to prevent external construction and key aliasing.
type tenantScopeKeyType struct{}

// TenantScopeKey is the canonical context key for the authenticated caller's TenantScope
// (Issue #4316). Set by the authentication middleware alongside TenantID.
var TenantScopeKey = tenantScopeKeyType{}

// tenantScopeKind enumerates the three distinguishable caller-scope states used for
// tenant authorization decisions (Issue #4316).
type tenantScopeKind int

const (
	// tenantScopeUnset is the zero value: no scope has been explicitly established for
	// this caller. Every authorization check must treat this as deny, never as root —
	// this is the state a plumbing bug (wrong context key, a dropped context.Background()
	// call, a forgotten propagation) produces, and it must fail closed rather than being
	// silently indistinguishable from a genuine unrestricted admin.
	tenantScopeUnset tenantScopeKind = iota
	// tenantScopeTenant marks a caller confined to a tenant subtree (TenantScope.Path()).
	tenantScopeTenant
	// tenantScopeRoot marks a caller with unrestricted, cross-tenant access. Only
	// NewRootScope can produce this state — see its doc comment for the restriction.
	tenantScopeRoot
)

// TenantScope is the explicit, three-state representation of a caller's tenant
// authorization scope (Issue #4316): unset (the zero value), tenant-scoped with a
// path, or root-scoped. It replaces the historical convention of an empty tenant
// string meaning "root, allow everything" — a convention that made a genuine root
// admin indistinguishable from a plumbing bug that lost the caller's tenant somewhere
// in the request path. Because the zero value is TenantScopeUnset, a context that was
// never explicitly scoped fails closed instead of defaulting to unrestricted access.
//
// Fields are unexported: construct a non-zero TenantScope only through NewTenantScope
// or NewRootScope.
type TenantScope struct {
	kind tenantScopeKind
	path string
}

// NewTenantScope returns a TenantScope confined to path's subtree. Any package may
// call this — tenant confinement is a narrowing operation, never a privileged one.
//
// path must be a real, non-empty tenant path. A TenantScope built from an empty path
// is indistinguishable, to callers that only check Path(), from "no restriction" —
// exactly the ambiguity this type exists to remove — so isAuthorizedForTenant treats
// an empty-path tenant scope as unset (deny), never as root. Use NewRootScope for a
// genuinely unrestricted caller.
func NewTenantScope(path string) TenantScope {
	return TenantScope{kind: tenantScopeTenant, path: path}
}

// NewRootScope returns a TenantScope with unrestricted, cross-tenant access.
//
// Restricted caller (Issue #4316): only features/controller/api/middleware.go's
// authentication middleware may call this, and only after it has independently
// verified the caller's mTLS certificate carries the CFGMS admin marker (see
// pkg/cert.HasAdminMarker / extractAdminPrincipal). This is enforced by
// TestNewRootScope_RestrictedCaller in architecture_linux_test.go, following the same
// restricted-caller pattern as pkg/cert's TestSetAdminMarker_Architecture and
// TestSetRootScopeMarker_Architecture. Do not call this from any other package, and do
// not add a new call site to that test's allow-list without an equivalent
// verified-certificate check guarding it — the allow-list is the enforcement, not a
// formality.
func NewRootScope() TenantScope {
	return TenantScope{kind: tenantScopeRoot}
}

// IsUnset reports whether s is the zero value — no scope was ever established.
func (s TenantScope) IsUnset() bool {
	return s.kind == tenantScopeUnset
}

// IsRoot reports whether s carries unrestricted, cross-tenant access.
func (s TenantScope) IsRoot() bool {
	return s.kind == tenantScopeRoot
}

// IsTenant reports whether s is confined to a tenant subtree.
func (s TenantScope) IsTenant() bool {
	return s.kind == tenantScopeTenant
}

// Path returns the tenant subtree s is confined to. Meaningful only when
// IsTenant() is true; returns "" for the unset and root states.
func (s TenantScope) Path() string {
	if s.kind != tenantScopeTenant {
		return ""
	}
	return s.path
}
