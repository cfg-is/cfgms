// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package moduleserver_test

// Registers the flatfile storage provider that newControllerSecretStore
// (server_test.go) names as the sops secret store's backing storage.
import _ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
