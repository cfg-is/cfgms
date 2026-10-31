// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package moduleset names the CFGMS-published M365 controller-kind modules
// (executors: [controller]). It is a leaf package with no CFGMS imports so that
// both the workflow engine and the controller configuration service can consult
// the set without either importing the other.
package moduleset

import "sort"

// names is the fixed set of CFGMS-published M365 modules. The workflow engine
// issues a controller-held Microsoft Graph access token only to these modules,
// and the controller never delivers their resources to a steward.
// features/workflow TestM365ModuleSet_MatchesShippedModules keeps it in step
// with the shipped module manifests.
var names = map[string]struct{}{
	"m365-conditional-access": {},
	"m365-entra-admin-unit":   {},
	"m365-entra-application":  {},
	"m365-entra-group":        {},
	"m365-entra-user":         {},
	"m365-intune-policy":      {},
}

// Contains reports whether name is one of the CFGMS-published M365
// controller-kind modules.
func Contains(name string) bool {
	_, ok := names[name]
	return ok
}

// Names returns the module names in the set, sorted. The returned slice is a
// fresh copy; callers may modify it.
func Names() []string {
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
