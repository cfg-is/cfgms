// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api test-only provider registrations.
// The blank import triggers init() to register the filesystem blob provider so that
// handlers_installer_test.go can use blob.CreateBlobStoreFromConfig("filesystem", ...).
package api

import (
	_ "github.com/cfgis/cfgms/pkg/storage/providers/blobstore/filesystem" // register filesystem blob provider for installer tests
)
