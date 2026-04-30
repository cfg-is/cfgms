// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package security provides input validation and security utilities for CFGMS.
//
// # Input Validation Policy
//
// Input validation in this package is allowlist-based: callers pass an explicit
// charset: rule to ValidateString for every field, and only characters in the
// named allowlist are accepted. There is no shared blocklist of injection patterns.
//
// # XSS Prevention
//
// XSS prevention is the responsibility of the output-encoding layer. HTML
// templates must use context-aware auto-escaping; JSON marshaling must use
// encoding/json (which escapes < > & by default). The validator does not scan
// for HTML or JavaScript tokens.
//
// # SQL Injection Prevention
//
// SQL injection prevention is the responsibility of parameterized queries in
// pkg/storage. The validator does not scan for SQL keywords or comment sequences.
//
// # Command Injection Prevention
//
// Command injection prevention for values interpolated into shell or PowerShell
// commands (e.g. Active Directory object IDs) is the responsibility of the
// feature's own allowlist regex applied before interpolation. See
// features/modules/activedirectory for an example.
package security
