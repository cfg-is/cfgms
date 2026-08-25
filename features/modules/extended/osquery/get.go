// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Platform-agnostic query definitions and result mapping for the four curated
// host:* fact domains (host:cpu, host:memory, host:os, host:bios).
//
// osquery's system_info, os_version, and cpu_info tables expose identical
// column names and types on every platform osquery supports — by design. The
// mapping logic here is therefore platform-agnostic.
//
// Binary path resolution is platform-agnostic too, and deliberately so: the
// executed path comes from the installed publisher-signed bundle, whose
// Binaries map is already keyed by GOOS-GOARCH (see integrity.go). There is no
// per-platform hardcoded install path — see the package comment in module.go
// for why a host-install fallback is not offered.
//
// Ephemeral field exclusions follow hostFactFragmentSpecs in
// features/steward/dna/fragments.go (ADR-016 clause 4):
//   - current_clock_speed excluded from cpu_info — changes with CPU throttling.
//   - Current memory usage fields excluded — change every second.
//   - os_version.name is aliased to "os" and system_info.hostname is included
//     in host:os because both keys are pinned: every stdlib module.yaml
//     declares them as required full-os-device fields (Issue #3319/#3358).

package osquery

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/features/modules"
)

// hostState implements modules.ConfigState for a single host:* fact domain.
// Values are non-empty strings; osquery columns with empty values are omitted.
// AsMap output is stable across calls on the same unchanged host.
type hostState struct {
	data map[string]string
}

// AsMap returns the fact payload. All values are non-empty strings. The map
// is suitable for JSON-serialisation with sorted keys (encoding/json guarantees
// this) to produce canonical, byte-identical output on repeated calls.
func (s *hostState) AsMap() map[string]interface{} {
	m := make(map[string]interface{}, len(s.data))
	for k, v := range s.data {
		m[k] = v
	}
	return m
}

// ToYAML is inert: host facts are produced by osquery, not operator YAML.
func (s *hostState) ToYAML() ([]byte, error) { return nil, nil }

// FromYAML is inert: hostState is read-only.
func (s *hostState) FromYAML(_ []byte) error { return nil }

// Validate is inert: the snapshot was validated by the producing query.
func (s *hostState) Validate() error { return nil }

// GetManagedFields is inert: hostState declares no field ownership.
func (s *hostState) GetManagedFields() []string { return nil }

var _ modules.ConfigState = (*hostState)(nil)

// ephemeralOsqueryFields is the set of osquery column names that must never
// appear in stable host:* fact payloads (ADR-016 clause 4). Values here
// change during normal operation without any cfg-driven configuration change.
var ephemeralOsqueryFields = map[string]bool{
	"current_clock_speed": true, // CPU throttling — changes on laptops/VMs
}

// SQL queries for each supported fact kind.
//
// All queries are single-per-kind for testability. Cross-joins between
// single-row virtual tables (system_info, os_version) in osquery produce
// exactly one row. LIMIT 1 is a defensive guard for cpu_info, which returns
// one row per physical CPU package on multi-socket systems.
//
// Columns in SELECT lists are explicit — no SELECT * — so the mapping is
// auditable and the ephemeral exclusions are visible at the query level.
const (
	// queryCPU collects CPU hardware identity from system_info and cpu_info.
	// current_clock_speed is excluded: it changes with CPU throttling and is
	// therefore ephemeral per ADR-016 clause 4.
	queryCPU = `SELECT
		system_info.cpu_brand,
		system_info.cpu_type,
		system_info.cpu_subtype,
		system_info.cpu_physical_cores,
		system_info.cpu_logical_cores,
		system_info.cpu_microcode,
		cpu_info.model,
		cpu_info.manufacturer,
		cpu_info.processor_type,
		cpu_info.cpu_family,
		cpu_info.max_clock_speed,
		cpu_info.number_of_cores,
		cpu_info.logical_processors,
		cpu_info.address_width
	FROM system_info, cpu_info LIMIT 1`

	// queryMemory collects total physical memory capacity from system_info.
	// Current-usage fields (free, available, cached) are omitted — they change
	// every second and are therefore ephemeral per ADR-016 clause 4.
	queryMemory = `SELECT physical_memory FROM system_info LIMIT 1`

	// queryOS collects OS identity plus the observed hostname.
	// os_version.name is aliased to "os" (pinned key contract, Issue #3319/#3358).
	// system_info.hostname is included unconditionally: every stdlib module.yaml
	// declares it as a required full-os-device field that must be present even
	// before a hostname module resource is configured (Issue #3319/#3358).
	queryOS = `SELECT
		os_version.name AS os,
		os_version.version,
		os_version.major,
		os_version.minor,
		os_version.patch,
		os_version.build,
		os_version.platform,
		os_version.platform_like,
		os_version.codename,
		os_version.arch,
		system_info.hostname
	FROM os_version, system_info LIMIT 1`

	// queryBIOS collects stable hardware-identity fields from system_info:
	// system/board vendor, model, version, serial, and UUID. These change only
	// on physical hardware replacement, not during normal operation.
	queryBIOS = `SELECT
		hardware_vendor,
		hardware_model,
		hardware_version,
		hardware_serial,
		uuid,
		board_vendor,
		board_model,
		board_version,
		board_serial
	FROM system_info LIMIT 1`
)

// kindToQuery maps each curated host:* fact kind to its SQL query.
var kindToQuery = map[string]string{
	"host:cpu":    queryCPU,
	"host:memory": queryMemory,
	"host:os":     queryOS,
	"host:bios":   queryBIOS,
}

// binPathResolver returns the on-disk path of an osquery binary that has just
// passed integrity verification, or an error if no verified path can be
// produced. getHostFact calls it exactly once per invocation — this is how
// exec.go's stated invariant ("callers are responsible for calling
// PreExecVerifier.VerifyBeforeExec before each invocation") is satisfied on the
// production Get() path. Passing a resolver rather than a plain string makes it
// impossible to reach runQuery with a path nobody verified.
type binPathResolver func() (string, error)

// getHostFact runs the appropriate osquery query for kind against the binary
// resolved by resolveBinPath and returns a stable, non-ephemeral ConfigState.
//
// The kind is validated before the resolver is called, so an unsupported kind
// costs no verification work and starts no process.
//
// Fail-closed: a resolver error (no verified installation, failed trust gate,
// or a binary tampered with since installation) aborts before any process is
// started. Zero rows from osquery means collection failed; an error is returned
// and no (even empty) ConfigState is emitted. All-empty rows also fail closed.
func getHostFact(ctx context.Context, resolveBinPath binPathResolver, kind string) (modules.ConfigState, error) {
	query, ok := kindToQuery[kind]
	if !ok {
		return nil, fmt.Errorf("osquery: unsupported fact kind %q", kind)
	}

	binPath, err := resolveBinPath()
	if err != nil {
		return nil, fmt.Errorf("osquery: resolve verified binary for %s: %w", kind, err)
	}

	rows, err := runQuery(ctx, binPath, query)
	if err != nil {
		return nil, fmt.Errorf("osquery: query for %s: %w", kind, err)
	}

	// Fail-closed: zero rows means the query ran but the table was empty —
	// this indicates a collection failure. Never emit an empty-but-present
	// fragment; callers that require a fragment will observe the absence.
	if len(rows) == 0 {
		return nil, fmt.Errorf("osquery: no rows returned for %s: collection failed", kind)
	}

	// Take the first row. For tables that may return multiple rows (cpu_info
	// on multi-socket systems), LIMIT 1 in the query already constrains this
	// to one row; using rows[0] here is a defensive belt-and-suspenders guard.
	row := rows[0]

	data := make(map[string]string, len(row))
	for k, v := range row {
		// Skip empty values — osquery returns "" for columns that have no data
		// on the current platform; omitting them keeps AsMap() sparse and
		// avoids spurious keys that would differ across platforms.
		if v == "" {
			continue
		}
		// Skip ephemeral fields regardless of value.
		if ephemeralOsqueryFields[k] {
			continue
		}
		data[k] = v
	}

	// Fail-closed: if every field was empty or ephemeral the collection is
	// effectively empty. Never emit a ConfigState with no fields.
	if len(data) == 0 {
		return nil, fmt.Errorf("osquery: all fields empty or ephemeral for %s: collection failed", kind)
	}

	return &hostState{data: data}, nil
}
