// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

import "embed"

// StdlibManifests contains the embedded module.yaml files for all stdlib modules.
// The controller's DNA integrity guard reads required_fields declarations from
// these manifests to build its per-configuration-type required-field table
// (ADR-020, implemented by issue #2642).
//
//go:embed stdlib/*/module.yaml
var StdlibManifests embed.FS
