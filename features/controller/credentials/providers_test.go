// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credentials

// Registers the real SOPS secrets provider; the credential store is exercised
// against the encrypted store, never a stand-in. The flatfile storage provider
// it sits on is registered by pkg/testing.
import (
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
)
