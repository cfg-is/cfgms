// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"fmt"
	"io/fs"
	"os"
	"sort"

	common "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
)

// configType identifies the configuration type of a managed device.
type configType string

const configTypeFullOSDevice configType = "full-os-device"

// dnaRequiredFields is the active required-field table built from the embedded
// stdlib module manifests at package init. All steward-kind modules' required_fields
// are unioned into configTypeFullOSDevice per ADR-020 Path A (steward-hosted entities
// inferred from active module set). Tests may pass a custom table to
// checkDNAIntegrityWithTable to probe different declaration states.
var dnaRequiredFields map[configType][]string

func init() {
	var err error
	dnaRequiredFields, err = buildRequiredFieldsFromManifestFS(modules.StdlibManifests, "stdlib")
	if err != nil {
		// StdlibManifests is compiled in — this path should not be reached in
		// practice. An empty table (conservative default: unknown contracts cannot
		// be violated) keeps the guard from falsely rejecting snapshots.
		dnaRequiredFields = map[configType][]string{}
	}
}

// buildRequiredFieldsFromManifests reads all module.yaml files rooted at dir
// and returns the required-field table. Steward-kind modules contribute their
// required_fields to configTypeFullOSDevice (ADR-020 Path A). The result is the
// union of all declared fields; duplicates are eliminated.
//
// This function is used by tests to build tables from test-fixture manifests.
// Production code uses buildRequiredFieldsFromManifestFS with the embedded FS.
func buildRequiredFieldsFromManifests(dir string) (map[configType][]string, error) {
	return buildRequiredFieldsFromManifestFS(os.DirFS(dir), ".")
}

// buildRequiredFieldsFromManifestFS is the canonical loader: walks fsys under
// root, parses every module.yaml, and unions required_fields from all steward
// modules into configTypeFullOSDevice.
func buildRequiredFieldsFromManifestFS(fsys fs.FS, root string) (map[configType][]string, error) {
	seen := map[configType]map[string]struct{}{}
	table := map[configType][]string{}

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "module.yaml" {
			return nil
		}

		f, openErr := fsys.Open(path)
		if openErr != nil {
			return fmt.Errorf("open %s: %w", path, openErr)
		}
		defer func() { _ = f.Close() }()

		meta, parseErr := modules.ParseModuleMetadata(f)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}

		if meta.Kind != "steward" {
			return nil
		}

		ct := configTypeFullOSDevice
		if _, ok := seen[ct]; !ok {
			seen[ct] = map[string]struct{}{}
		}
		for _, own := range meta.Owns {
			for _, field := range own.RequiredFields {
				if _, dup := seen[ct][field]; !dup {
					seen[ct][field] = struct{}{}
					table[ct] = append(table[ct], field)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort each slice for deterministic ordering in tests and logs.
	for ct := range table {
		sort.Strings(table[ct])
	}
	return table, nil
}

// dnaIntegrityResult is the outcome of a DNA integrity check.
type dnaIntegrityResult struct {
	valid         bool
	missingFields []string
}

// checkDNAIntegrity returns whether the DNA snapshot satisfies the required-field
// contract for the given configuration type. The required-set is read from the
// package-level dnaRequiredFields table, which is built from the embedded stdlib
// module manifests at init time (ADR-020).
//
// Call sites in AcceptRegistration and SyncDNA are unchanged from #2617.
func checkDNAIntegrity(dna *common.DNA, ct configType) dnaIntegrityResult {
	return checkDNAIntegrityWithTable(dna, ct, dnaRequiredFields)
}

// FlattenDNAFragments decodes each fragment in frags and merges their string
// key-value pairs into a single map. Keys with empty or non-string values are
// omitted. Fragments with malformed canonical bytes are silently skipped —
// hostile input from a compromised steward must not prevent checking the
// well-formed ones.
func FlattenDNAFragments(frags []*common.Fragment) map[string]string {
	flat := make(map[string]string)
	for _, frag := range frags {
		if len(frag.CanonicalBytes) == 0 {
			continue
		}
		decoded, err := sdna.DecodeCanonicalFragment(frag.CanonicalBytes)
		if err != nil {
			continue
		}
		for k, v := range decoded {
			if s, ok := v.(string); ok && s != "" {
				flat[k] = s
			}
		}
	}
	return flat
}

// checkDNAIntegrityWithTable is the table-parameterised implementation. Tests
// call this directly with a table built from test-fixture manifests to prove
// that the required-set drives the guard without any code change to guard logic.
//
// Field presence is checked against the flattened fragment set (Issue #3319):
// all fragment canonical payloads are merged into a single map and each declared
// required field is looked up there. A field absent from every fragment, or
// present only with an empty value, is reported as missing.
func checkDNAIntegrityWithTable(dna *common.DNA, ct configType, table map[configType][]string) dnaIntegrityResult {
	if dna == nil {
		return dnaIntegrityResult{missingFields: []string{"(nil DNA)"}}
	}
	required, ok := table[ct]
	if !ok {
		// Conservative default: unknown config types have no declared contract.
		return dnaIntegrityResult{valid: true}
	}
	flat := FlattenDNAFragments(dna.Fragments)
	var missing []string
	for _, field := range required {
		if flat[field] == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		return dnaIntegrityResult{missingFields: missing}
	}
	return dnaIntegrityResult{valid: true}
}
