// SPDX-License-Identifier: Apache-2.0
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

// correlationIDKey is the context key for correlation IDs
type correlationIDKey struct{}
