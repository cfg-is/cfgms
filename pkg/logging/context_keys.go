// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

// Shared context keys used by logging manager and injection functions
// to ensure consistency across the global logging provider system
//
// The tenant ID is not among these: it is read from ctxkeys.TenantID, the
// single canonical key the authentication middleware sets (Issue #4326). A
// package-local tenant key here would create a second tenant-context
// namespace that context.Value's == comparison can never match against the
// middleware's key, silently returning "" for every real request.

// sessionIDKey is the context key for session IDs
type sessionIDKey struct{}

// operationKey is the context key for operations
type operationKey struct{}
