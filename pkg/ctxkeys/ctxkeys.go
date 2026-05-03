// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package ctxkeys is the shared context-key registry usable from platform and feature packages —
// defined here to avoid cross-feature imports.
package ctxkeys

// ContextKey is the type for shared context keys. Using a named type
// prevents accidental collisions with keys from other packages.
type ContextKey string

const (
	// TenantID is the context key for the authenticated tenant ID.
	// Set by the auth middleware after validating an API key and read by
	// config handlers, service methods, and terminal session managers to enforce tenant isolation.
	TenantID ContextKey = "tenant_id"
)

// correlationIDKeyType is unexported so no external package can construct a value of this type,
// preventing key aliasing across package boundaries (the standard Go "opaque key" idiom).
type correlationIDKeyType struct{}

// CorrelationIDKey is the single canonical context key for correlation IDs.
// Both pkg/logging and pkg/telemetry store and read correlation IDs under this key,
// so that logging.WithCorrelation and telemetry.GetCorrelationID share the same slot.
var CorrelationIDKey = correlationIDKeyType{}
