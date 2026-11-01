// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package dispatcher test-only provider wiring. The blank flatfile import
// registers the "flatfile" provider the action-audit tests build their audit
// store from. The concrete provider import is confined to this allowlisted
// */providers_test.go path (see scripts/check-providers.sh).
package dispatcher

import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // registers the "flatfile" provider
)
