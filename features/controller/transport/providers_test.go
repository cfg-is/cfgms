// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

// Storage-provider registration for this package's tests. It lives in
// providers_test.go because that is the one test-file name the provider-import
// check (scripts/check-providers.sh) allows to import pkg/storage/providers/*.

import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
