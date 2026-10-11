// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package moduleserver_test

import (
	// newControllerSecretStore opens the sops secret store over a flatfile root
	// through interfaces.GetStorageProvider; this blank import registers the
	// flatfile storage provider for this package's tests.
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)
