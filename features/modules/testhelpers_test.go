// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

// newTestMetadata returns a ModuleMetadata with the minimum valid fields for use in tests
// that are not testing metadata validation itself. Kind is empty until Validate() or
// ParseModuleMetadata() is called — callers that need Kind set should call m.Validate() first.
func newTestMetadata(name, version string) *ModuleMetadata {
	return &ModuleMetadata{
		Name:      name,
		Version:   version,
		Publisher: "cfgms",
		Executors: []string{"steward"},
	}
}
