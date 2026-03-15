// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package ctxkeys defines shared context key types for the controller feature.
// Using a typed key prevents collisions with plain string keys and enables
// safe sharing across the api and service packages without circular imports.
package ctxkeys

// ContextKey is the type for controller context keys. Using a named type
// prevents accidental collisions with keys from other packages.
type ContextKey string

const (
	// TenantID is the context key for the authenticated tenant ID.
	// Set by the auth middleware after validating an API key and read by
	// config handlers and service methods to enforce tenant isolation.
	TenantID ContextKey = "tenant_id"
)
