// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package audit

// Export bridges for package audit_test — compiled exclusively by go test.

// GenerateChecksum exposes (*Manager).generateChecksum for integrity verification tests.
var GenerateChecksum = (*Manager).generateChecksum

// BuildEntry exposes (*AuditEventBuilder).build for builder unit tests.
var BuildEntry = (*AuditEventBuilder).build
