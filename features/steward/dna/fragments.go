// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules"
	entitygraphtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// fragmentSpec describes one host:* fragment kind: its taxonomy kind string,
// the source-envelope category name, and the curated attribute-key allowlist.
// Keys must be explicitly enumerated per platform file — no prefix-regex substitutes
// (implementation note: cpu_current_frequency_mhz doesn't share a clean prefix
// boundary with stable cpu_* keys).
type fragmentSpec struct {
	kind     string   // e.g. "host:cpu"
	category string   // envelope source suffix, e.g. "hardware" → source="gatherer:hardware"
	keys     []string // stable, non-ephemeral attribute keys for this kind
}

// hostFactFragmentSpecs is the curated allowlist of host:* fragment kinds
// this partition step emits (ADR-017 Amendment 3, §8).
//
// Only kinds registered in DefaultTaxonomy are listed here. To add a new kind,
// first register it in pkg/entitygraph/types/taxonomy.go's DefaultTaxonomy(),
// then add a spec below and document the change in the PR.
//
// Key-selection rationale per kind:
//   - host:cpu: hardware identity and topology (model, vendor, arch, core counts,
//     cache sizes). Excludes current-frequency keys (cpu_current_frequency_*) which
//     change with CPU throttling on laptops/VMs.
//   - host:memory: total physical memory capacity. Excludes current-usage keys
//     (memory_free_kb, memory_available_kb, etc.) which change every second.
//   - host:os: OS and kernel identity, plus the observed hostname (a required
//     full-os-device field per every stdlib module.yaml; carried here because
//     it must be unconditionally available even before a hostname module
//     resource is configured — see Issue #3319/#3358). Excludes
//     kernel_info/kernel_build_info which embed a build timestamp, making
//     them ephemeral. Excludes go_version/runtime_* which are
//     steward-process attributes, not OS attributes.
//   - host:bios: BIOS, motherboard, and system hardware identity. Includes
//     virtualization_type/role because they are stable platform identity attributes
//     (changing only on live migration, not at each collection).
var hostFactFragmentSpecs = []fragmentSpec{
	{
		kind:     "host:cpu",
		category: "hardware",
		keys: []string{
			// Runtime — always present on all platforms
			"cpu_count",
			"cpu_arch",
			// Linux /proc/cpuinfo
			"cpu_model",
			"cpu_vendor",
			"cpu_family",
			"cpu_model_id",
			"cpu_stepping",
			"cpu_frequency_mhz",
			"cpu_cache_size",
			"cpu_flags",
			"proc_cpu_count",
			// Linux lscpu
			"cpu_architecture",
			"cpu_op_modes",
			"cpu_byte_order",
			"cpu_logical_count",
			"cpu_threads_per_core",
			"cpu_cores_per_socket",
			"cpu_sockets",
			"cpu_numa_nodes",
			"cpu_l1d_cache",
			"cpu_l1i_cache",
			"cpu_l2_cache",
			"cpu_l3_cache",
			// Linux cpufreq sysfs (stable max/min, not current)
			"cpu_max_frequency_mhz",
			"cpu_max_frequency_khz",
			"cpu_min_frequency_mhz",
			"cpu_min_frequency_khz",
			// macOS sysctl
			"cpu_physical_cores",
			"cpu_logical_cores",
			// Windows WMI/CIM
			"cpu_name",
			"cpu_manufacturer",
			"cpu_max_clock_speed",
			"cpu_cores",
			"cpu_logical_processors",
		},
	},
	{
		kind:     "host:memory",
		category: "hardware",
		keys: []string{
			// Linux /proc/meminfo (total capacity — not current usage)
			"memory_total_kb",
			"memory_total_mb",
			"memory_total_gb",
			// Linux dmidecode
			"memory_dmidecode_available",
			"memory_slot_count",
			// Linux swap total (total configured, not current free)
			"swap_total_kb",
			// macOS sysctl hw.memsize
			"memory_total_bytes",
			"memory_page_size",
			// Windows WMI
			"memory_module_count",
			"memory_modules_total_capacity",
			"memory_module_capacity",
			"memory_module_form_factor",
			"memory_module_type",
			"memory_module_speed",
		},
	},
	{
		kind:     "host:os",
		category: "software",
		keys: []string{
			// Cross-platform runtime
			"os",
			// Host identity fact (Issue #3319/#3358): every stdlib module's
			// module.yaml declares "hostname" as a required full-os-device
			// field alongside "os". The hostname *module* owns the "hostname"
			// fragment kind for desired-state management, but that fragment
			// only exists once a hostname resource is explicitly configured —
			// never at first registration. Carrying the observed hostname here
			// too (sourced from the same unconditionally-populated
			// attributes["hostname"] that "os" already reads) keeps the
			// required-field presence check satisfiable for every steward,
			// not only ones with a hostname module resource declared.
			"hostname",
			// Linux /etc/os-release
			"os_name",
			"os_version",
			"os_id",
			"os_id_like",
			"os_version_id",
			"os_version_codename",
			"os_pretty_name",
			// Linux kernel (uname -r only; uname -a/-v include build timestamp)
			"kernel_version",
			// macOS sw_vers
			"os_build",
			// Windows registry
			"windows_caption",
			"windows_build_number",
			"windows_version",
		},
	},
	{
		kind:     "host:bios",
		category: "hardware",
		keys: []string{
			// Linux dmidecode system/bios/baseboard
			"system_manufacturer",
			"system_product_name",
			"system_version",
			"system_serial_number",
			"system_uuid",
			"bios_vendor",
			"bios_version",
			"bios_release_date",
			"motherboard_manufacturer",
			"motherboard_product",
			"motherboard_version",
			// Linux virtualization (stable platform identity)
			"virtualization_type",
			"virtualization_role",
			"hyperv_host",
			// macOS sysctl
			"hardware_model",
			"hardware_uuid",
			// Windows WMI/CIM
			"system_model",
			"bios_manufacturer",
			"motherboard_serial",
			"hyperv_role_installed",
			"hyperv_enabled",
		},
	},
}

// partitionEphemeralKeys are attribute keys that must never appear in any
// host:* fragment payload, regardless of whether they appear in a spec's key
// list (ADR-017 clause 4, Amendment 3). These are run-local values that would
// cause DNA hash churn on every collection cycle.
var partitionEphemeralKeys = map[string]bool{
	"timestamp":         true,
	"working_directory": true,
	"system_uptime":     true,
	"memory_go_alloc":   true,
	"memory_go_sys":     true,
}

// attributeConfigState wraps map[string]string as a modules.ConfigState for
// use with CanonicalizeFragment. String attribute values are exposed as
// interface{} values so the canonical encoder applies the string type tag.
type attributeConfigState struct {
	data map[string]string
}

func (s *attributeConfigState) AsMap() map[string]interface{} {
	m := make(map[string]interface{}, len(s.data))
	for k, v := range s.data {
		m[k] = v
	}
	return m
}

func (s *attributeConfigState) ToYAML() ([]byte, error)    { return nil, nil }
func (s *attributeConfigState) FromYAML(_ []byte) error    { return nil }
func (s *attributeConfigState) Validate() error            { return nil }
func (s *attributeConfigState) GetManagedFields() []string { return nil }

var _ modules.ConfigState = (*attributeConfigState)(nil)

// MapState adapts an already-materialised map[string]interface{} state snapshot to
// modules.ConfigState so it can be canonicalized by CanonicalizeFragment.
//
// It is a projection of state a module already produced via its own AsMap(), not a
// second independent reader of the underlying resource (ADR-017 §2a): the only
// method with real behaviour is AsMap. It therefore takes no part in a Get/Set
// convergence cycle, and the remaining ConfigState methods are inert.
type MapState map[string]interface{}

// AsMap returns the wrapped snapshot.
func (s MapState) AsMap() map[string]interface{} { return s }

// ToYAML is inert: MapState exists only to feed the canonical encoder.
func (s MapState) ToYAML() ([]byte, error) { return nil, nil }

// FromYAML is inert: MapState is read-only.
func (s MapState) FromYAML(_ []byte) error { return nil }

// Validate is inert: the snapshot was already validated by its producing module.
func (s MapState) Validate() error { return nil }

// GetManagedFields is inert: MapState declares no field ownership.
func (s MapState) GetManagedFields() []string { return nil }

var _ modules.ConfigState = MapState(nil)

// NewFragment canonicalizes state (S2) and hashes it (S3) into an ADR-017 Fragment.
//
// It is the single construction point for fragments assembled outside
// PartitionHostFacts — the steward's monitor bridge for cluster:* state and the
// controller-side fixtures that exercise the cluster registry parse path both use
// it, so canonical bytes and fragment hash can never drift apart.
func NewFragment(fragmentID, authority string, state modules.ConfigState) (*commonpb.Fragment, error) {
	canonical, err := CanonicalizeFragment(fragmentID, authority, state)
	if err != nil {
		return nil, fmt.Errorf("NewFragment %q: %w", fragmentID, err)
	}
	return &commonpb.Fragment{
		FragmentId:     fragmentID,
		Authority:      authority,
		CanonicalBytes: canonical,
		FragmentHash:   FragmentHash(canonical),
	}, nil
}

// FlattenFragments decodes every fragment's canonical bytes and merges their
// string key-value pairs into a single flat map — the projection of ADR-017
// fragment state onto the flat attribute shape that controller-side consumers
// (fleet inventory, role-policy selectors, DNA fingerprinting, attribute
// filters) still read.
//
// Keys whose value is not a non-empty string are omitted: the flat projection is
// a string map by contract, and an empty value is indistinguishable from an
// absent one to every consumer.
//
// Fragments with empty or malformed canonical bytes are skipped rather than
// failing the whole projection. Canonical bytes arrive from stewards, which per
// the threat model run on hosts that may be compromised, so one hostile fragment
// must not blank out the well-formed ones.
//
// Merge order is deterministic: fragments are visited in ascending fragment-ID
// order, so when two fragments declare the same key the highest fragment ID
// wins, every time. Determinism is load-bearing — the controller hashes this
// projection into the DNA fingerprint
// (features/controller/fleet/storage/storage.go), and a map-iteration-order
// merge would make that fingerprint flap between identical snapshots.
func FlattenFragments(frags []*commonpb.Fragment) map[string]string {
	ordered := make([]*commonpb.Fragment, 0, len(frags))
	for _, frag := range frags {
		if frag == nil || len(frag.GetCanonicalBytes()) == 0 {
			continue
		}
		ordered = append(ordered, frag)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].GetFragmentId() < ordered[j].GetFragmentId()
	})

	flat := make(map[string]string)
	for _, frag := range ordered {
		decoded, err := DecodeCanonicalFragment(frag.GetCanonicalBytes())
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

// PartitionHostFacts reads the already-populated flat attributes map (written by
// collectHardwareInfo, collectNetworkInfo, collectSecurityInfo, collectBasicInfo,
// and the background software/security collectors) and groups a curated, stable,
// non-ephemeral, non-module-owned subset of keys into host:* fragment payloads.
//
// Each fragment is canonicalized (S2 / CanonicalizeFragment) and hashed (S3 /
// FragmentHash). The envelope source is "gatherer:<category>"; confidence is
// "high" because the gatherers read real OS state directly.
//
// Fail-closed: if no keys from a kind's allowlist are present in attributes (the
// collector logged an error and populated nothing), that kind's fragment is
// omitted rather than emitted as an empty payload.
//
// Gather-once: this function MUST NOT call any Collect* function. It reads only
// the map that the existing gatherers have already populated.
func PartitionHostFacts(
	attributes map[string]string,
	taxonomy *entitygraphtypes.Taxonomy,
	ownership map[string][]modules.OwnershipDeclaration,
) ([]*commonpb.Fragment, map[string]*commonpb.FragmentEnvelope, error) {
	observedAt := time.Now()
	ownedKinds := buildOwnedKindSet(ownership)

	var fragments []*commonpb.Fragment
	envelopes := make(map[string]*commonpb.FragmentEnvelope)

	for _, spec := range hostFactFragmentSpecs {
		// Only emit kinds that are registered in the taxonomy (defensive check).
		if _, ok := taxonomy.LookupEntityType(spec.kind); !ok {
			continue
		}

		// Skip kinds claimed by a module — module authority preempts gatherer
		// observe-only data per ADR-017 §2 and Amendment 3.
		if ownedKinds[spec.kind] {
			continue
		}

		// Pick the stable, non-ephemeral keys that are actually populated.
		payload := pickAttributeKeys(attributes, spec.keys)

		// Fail-closed: no keys present means collection failed; omit fragment.
		if len(payload) == 0 {
			continue
		}

		state := &attributeConfigState{data: payload}
		canonical, err := CanonicalizeFragment(spec.kind, "gatherer", state)
		if err != nil {
			return nil, nil, fmt.Errorf("PartitionHostFacts: canonicalize %s: %w", spec.kind, err)
		}
		hash := FragmentHash(canonical)

		fragments = append(fragments, &commonpb.Fragment{
			FragmentId:     spec.kind,
			Authority:      "gatherer",
			CanonicalBytes: canonical,
			FragmentHash:   hash,
		})
		envelopes[spec.kind] = &commonpb.FragmentEnvelope{
			Source:     "gatherer:" + spec.category,
			ObservedAt: timestamppb.New(observedAt),
			Confidence: "high",
		}
	}

	return fragments, envelopes, nil
}

// buildOwnedKindSet extracts the set of fragment kinds claimed by any module in
// the ownership map, enabling O(1) exclusion checks in PartitionHostFacts.
func buildOwnedKindSet(ownership map[string][]modules.OwnershipDeclaration) map[string]bool {
	owned := make(map[string]bool)
	for _, decls := range ownership {
		for _, d := range decls {
			owned[d.Kind] = true
		}
	}
	return owned
}

// pickAttributeKeys selects keys from attributes that are in the allowlist,
// non-empty, and not on the partitionEphemeralKeys list. Returns a new map
// containing only the selected key-value pairs.
func pickAttributeKeys(attributes map[string]string, allowlist []string) map[string]string {
	result := make(map[string]string)
	for _, k := range allowlist {
		if partitionEphemeralKeys[k] {
			continue
		}
		if v, ok := attributes[k]; ok && v != "" {
			result[k] = v
		}
	}
	return result
}
