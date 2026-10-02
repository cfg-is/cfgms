// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

// Storage-provider registration for tests in this package.
// The audit tests build a real flat-file business.AuditStore through
// pkg/storage/interfaces (see newRecordingAuditStore); resolving the provider by
// name requires its init() registration. Isolated to this file so no other test
// file imports a concrete provider package directly (per epic #731 and
// scripts/check-providers.sh).
import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
