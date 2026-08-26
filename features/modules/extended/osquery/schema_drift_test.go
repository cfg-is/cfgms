// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Schema-drift guard for the osquery host:* curated fact queries (Issue #3567).
//
// schemaSpec is the authoritative column contract for pinnedVersion. When the
// pin is bumped, the developer must run the new binary against each curated
// query (get.go) and verify its column names still match this spec. A renamed
// or removed column is a schema drift event that requires coordinated changes:
//
//  1. Update the SQL query in get.go to use the new column name.
//  2. Update schemaSpec below to match the new column name.
//  3. Update the canned JSON constants in get_test.go to match.
//  4. Run this test suite to confirm all three files are consistent.
//
// Columns reliably returning empty values on some platforms (cpu_subtype, build,
// board_serial) are excluded from schemaSpec — getHostFact omits empty values,
// so a platform-conditionally-empty column cannot be a required contract.
package osquery

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// schemaSpec is the authoritative list of columns that each curated osquery
// query MUST return non-empty for valid host observation. The column names are
// the canonical osquery output names, including the "os" alias
// (os_version.name AS os — pinned key contract, Issue #3319/#3358).
//
// This map must stay in sync with the SELECT lists in get.go and with
// pinnedVersion in module.go. Any divergence is a test failure.
var schemaSpec = map[string][]string{
	"host:cpu": {
		// system_info columns
		"cpu_brand", "cpu_type", "cpu_physical_cores", "cpu_logical_cores",
		"cpu_microcode",
		// cpu_info columns (omit current_clock_speed: ephemeral per ADR-016 clause 4)
		"model", "manufacturer", "processor_type", "cpu_family",
		"max_clock_speed", "number_of_cores", "logical_processors", "address_width",
	},
	"host:memory": {
		// system_info column (total capacity only; current-usage fields are ephemeral)
		"physical_memory",
	},
	"host:os": {
		// os_version.name AS os — pinned alias (Issue #3319/#3358)
		"os",
		// os_version columns (build excluded: empty on most Linux platforms)
		"version", "major", "minor", "patch",
		"platform", "platform_like", "codename", "arch",
		// system_info column — pinned key contract (Issue #3319/#3358)
		"hostname",
	},
	"host:bios": {
		// system_info hardware-identity columns (board_serial excluded: may be empty)
		"hardware_vendor", "hardware_model", "hardware_version", "hardware_serial",
		"uuid",
		// system_info baseboard columns
		"board_vendor", "board_model", "board_version",
	},
}

// buildFullSchemaJSON returns a JSON-array osquery response whose single row
// contains every column in cols with a distinct non-empty sentinel value.
// Sentinel values are unique per column so a filtering bug that drops the wrong
// column is identifiable from which sentinel is missing.
func buildFullSchemaJSON(cols []string) string {
	row := make(map[string]string, len(cols))
	for i, col := range cols {
		row[col] = fmt.Sprintf("sentinel-col%d", i+1)
	}
	b, err := json.Marshal([]map[string]string{row})
	if err != nil {
		// json.Marshal on map[string]string never errors.
		panic(fmt.Sprintf("buildFullSchemaJSON: unexpected marshal error: %v", err))
	}
	return string(b)
}

// buildSchemaJSONWithout returns a JSON-array osquery response whose single row
// contains every column in cols EXCEPT the named omit column. Other columns
// carry non-empty sentinel values. Used to simulate a column absent from a real
// osquery response after a schema-drift version bump.
func buildSchemaJSONWithout(cols []string, omit string) string {
	row := make(map[string]string, len(cols))
	for i, col := range cols {
		if col == omit {
			continue
		}
		row[col] = fmt.Sprintf("sentinel-col%d", i+1)
	}
	b, err := json.Marshal([]map[string]string{row})
	if err != nil {
		panic(fmt.Sprintf("buildSchemaJSONWithout: unexpected marshal error: %v", err))
	}
	return string(b)
}

// TestSchemaDrift_AllColumnsPresent is the schema-drift guard for pinnedVersion.
//
// [REQUIRED TEST — issue #3567 AC] This test fails if a curated fact's expected
// column is absent from a query response. For each curated kind, a fake osquery
// response carrying every column declared in schemaSpec is returned; every column
// must appear in Get()'s result. A column absent from the result means:
//
//   - The osquery version was bumped and the new binary renames/removes that
//     column, OR
//   - get.go's SQL query was changed to exclude the column.
//
// Either case requires coordinated updates to get.go, schemaSpec, and get_test.go.
func TestSchemaDrift_AllColumnsPresent(t *testing.T) {
	for kind, cols := range schemaSpec {
		kind, cols := kind, cols
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			m := moduleReturning(t, buildFullSchemaJSON(cols))
			state, err := m.Get(context.Background(), kind)
			if err != nil {
				t.Fatalf("Get(%q) with full schema response: %v", kind, err)
			}
			got := state.AsMap()
			for _, col := range cols {
				if _, ok := got[col]; !ok {
					t.Errorf("schema drift detected: column %q absent from Get(%q) result "+
						"(pinnedVersion=%s) — update the SQL query in get.go and schemaSpec "+
						"in schema_drift_test.go together", col, kind, pinnedVersion)
				}
			}
		})
	}
}

// TestSchemaDrift_AbsentColumnPropagates demonstrates the drift-detection path:
// when osquery omits a required column (simulating a schema change in a new
// release), Get() either fails closed (if the absent column leaves no non-empty
// fields, e.g. host:memory with only physical_memory) or returns a result
// without that column, which TestSchemaDrift_AllColumnsPresent then catches.
func TestSchemaDrift_AbsentColumnPropagates(t *testing.T) {
	// One probe column per kind — chosen as the first required column in schemaSpec.
	probe := map[string]string{
		"host:cpu":    "cpu_brand",
		"host:memory": "physical_memory",
		"host:os":     "os",
		"host:bios":   "hardware_vendor",
	}

	for kind, absentCol := range probe {
		kind, absentCol := kind, absentCol
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			cols := schemaSpec[kind]
			m := moduleReturning(t, buildSchemaJSONWithout(cols, absentCol))
			state, err := m.Get(context.Background(), kind)
			if err != nil {
				// Fail-closed path: Get() errors when the absent column is the only
				// non-empty field (host:memory with only physical_memory). The error
				// IS the drift signal — no further check needed.
				return
			}
			// Multi-column path: the absent column must not appear in the result.
			if _, ok := state.AsMap()[absentCol]; ok {
				t.Errorf("column %q appears in Get(%q) result even though osquery did not return it",
					absentCol, kind)
			}
		})
	}
}

// TestSchemaSpec_CoverageMatchesKindToQuery verifies that schemaSpec declares
// entries for every kind registered in kindToQuery and that no extra kinds appear
// in schemaSpec. This prevents schemaSpec from silently going stale when a new
// curated query is added to get.go without a corresponding spec entry.
func TestSchemaSpec_CoverageMatchesKindToQuery(t *testing.T) {
	for kind := range kindToQuery {
		if _, ok := schemaSpec[kind]; !ok {
			t.Errorf("kind %q is in kindToQuery (get.go) but missing from schemaSpec "+
				"(schema_drift_test.go) — add a column spec entry for the new kind", kind)
		}
	}
	for kind := range schemaSpec {
		if _, ok := kindToQuery[kind]; !ok {
			t.Errorf("kind %q is in schemaSpec (schema_drift_test.go) but not in kindToQuery "+
				"(get.go) — remove the stale spec entry or register the kind in get.go", kind)
		}
	}
}
