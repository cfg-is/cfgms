// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

// Shared context keys used by logging manager and injection functions
// to ensure consistency across the global logging provider system

// tenantIDKey is the context key for tenant IDs
type tenantIDKey struct{}

// sessionIDKey is the context key for session IDs
type sessionIDKey struct{}

// operationKey is the context key for operations
type operationKey struct{}
