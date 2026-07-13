// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	common "github.com/cfgis/cfgms/api/proto/common"
)

// configType identifies the configuration type of a managed device.
// The per-type required-field table is seeded here for full-OS devices;
// #2618 will extend it for additional device kinds without rewriting the guard.
type configType string

const configTypeFullOSDevice configType = "full-os-device"

// dnaRequiredFields maps each configuration type to the Attributes keys that
// must be present and non-empty for a valid DNA snapshot.
// Seed: only full-os-device (all current stewards). #2618 adds further entries.
var dnaRequiredFields = map[configType][]string{
	configTypeFullOSDevice: {"hostname", "os"},
}

// dnaIntegrityResult is the outcome of a DNA integrity check.
type dnaIntegrityResult struct {
	valid         bool
	missingFields []string
}

// checkDNAIntegrity returns whether the DNA snapshot satisfies the required-field
// contract for the given configuration type. A nil DNA, or any required Attributes
// key that is absent or empty, fails the check and lists the offending fields.
//
// The check is table-driven: to seed the required set for a new device kind,
// add an entry to dnaRequiredFields (see #2618). An unregistered config type
// passes by default (conservative: unknown contracts cannot be violated).
func checkDNAIntegrity(dna *common.DNA, ct configType) dnaIntegrityResult {
	if dna == nil {
		return dnaIntegrityResult{missingFields: []string{"(nil DNA)"}}
	}
	required, ok := dnaRequiredFields[ct]
	if !ok {
		return dnaIntegrityResult{valid: true}
	}
	var missing []string
	for _, field := range required {
		if dna.Attributes[field] == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		return dnaIntegrityResult{missingFields: missing}
	}
	return dnaIntegrityResult{valid: true}
}
