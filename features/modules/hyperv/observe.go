// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// DomainObservation is the ConfigState returned by Get("domain:hyperv"). It
// provides a deterministic, read-only inventory of the host's Hyper-V domain:
// the cluster this host belongs to (if any), the names of all local VMs, and
// the names of all local virtual switches. No ephemeral fields (ADR-016 §4).
//
// This is the single-resource summary form — the per-resource form (with full
// VM DNA fragments keyed by "vm:<name>" etc.) is available via GetDomain.
type DomainObservation struct {
	// ClusterName is the name of the failover cluster this host belongs to.
	// Empty when the host is standalone.
	ClusterName string `yaml:"cluster_name,omitempty"`
	// ClusterFound reports whether the host is a member of a failover cluster.
	ClusterFound bool `yaml:"cluster_found"`
	// VMNames is the sorted list of all VM names on this host.
	VMNames []string `yaml:"vm_names,omitempty"`
	// VSwitchNames is the sorted list of all virtual switch names on this host.
	VSwitchNames []string `yaml:"vswitch_names,omitempty"`
}

// AsMap implements modules.ConfigState. All values are deterministic and
// contain no ephemeral runtime state (ADR-016 §4).
func (d *DomainObservation) AsMap() map[string]interface{} {
	vmNames := make([]interface{}, len(d.VMNames))
	for i, n := range d.VMNames {
		vmNames[i] = n
	}
	swNames := make([]interface{}, len(d.VSwitchNames))
	for i, n := range d.VSwitchNames {
		swNames[i] = n
	}
	return map[string]interface{}{
		"cluster_name":  d.ClusterName,
		"cluster_found": d.ClusterFound,
		"vm_count":      len(d.VMNames),
		"vm_names":      vmNames,
		"vswitch_count": len(d.VSwitchNames),
		"vswitch_names": swNames,
	}
}

// ToYAML implements modules.ConfigState.
func (d *DomainObservation) ToYAML() ([]byte, error) {
	return yaml.Marshal(d)
}

// FromYAML implements modules.ConfigState. Domain observations are never
// decoded from operator YAML; provided for interface completeness.
func (d *DomainObservation) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, d)
}

// Validate implements modules.ConfigState. Domain observations carry no
// operator constraints — always valid.
func (d *DomainObservation) Validate() error { return nil }

// GetManagedFields implements modules.ConfigState. The domain observation is
// purely observed — no field participates in drift comparison.
func (d *DomainObservation) GetManagedFields() []string { return nil }

// GetDomain observes the full Hyper-V domain on this host without requiring any
// declared hyperv.* resource. It returns a map of natural resource IDs to their
// observed ConfigState:
//   - "cluster:<name>" — present when the host is a cluster member
//   - "vm:<name>"      — one entry per local VM (includes VMGUID + MAC addresses)
//   - "vswitch:<name>" — one entry per virtual switch
//
// All PowerShell calls are read-only (Get-* only). The returned map is suitable
// for direct use with cacheModuleDNAState: each entry produces cluster:*,
// vm:*, or vswitch:* DNA keys when processed by the steward's DNA layer,
// independently of any declared hyperv.* resource.
func (m *hypervModule) GetDomain(ctx context.Context) (map[string]modules.ConfigState, error) {
	result := make(map[string]modules.ConfigState)

	cluster, err := m.observeLocalCluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain observe (cluster): %w", err)
	}
	if cluster.Found {
		result["cluster:"+cluster.Name] = cluster
	}

	vmNames, err := m.enumerateVMNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain observe (vms): %w", err)
	}
	for _, name := range vmNames {
		cfg, found, rErr := m.readVMState(ctx, name)
		if rErr != nil || !found {
			continue
		}
		// Populate HARole from cluster observation so edge emission is accurate
		// (#3368). readVMState does not probe cluster membership (that is the
		// getVMLocal path); using the cluster.RoleOwners map already read avoids
		// additional PS calls. A VM whose name appears in RoleOwners is a
		// registered clustered role — set HARole so AsMap emits runs-on:cluster.
		if cluster.Found {
			if _, isRole := cluster.RoleOwners[name]; isRole {
				cfg.HARole = &HARoleConfig{ClusterName: cluster.Name}
			}
		}
		result["vm:"+name] = cfg
	}

	switches, err := m.observeVSwitchDomain(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain observe (vswitches): %w", err)
	}
	for _, sw := range switches {
		result["vswitch:"+sw.Name] = sw
	}

	return result, nil
}

// getDomainSummary returns a DomainObservation for the current host — a
// lightweight, deterministic summary of cluster membership, VM names, and
// vswitch names. Called by Get("domain:hyperv"). All sub-observations are
// read-only. VM names and vswitch names are sorted for determinism.
func (m *hypervModule) getDomainSummary(ctx context.Context) (*DomainObservation, error) {
	obs := &DomainObservation{}

	cluster, err := m.observeLocalCluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain summary (cluster): %w", err)
	}
	if cluster.Found {
		obs.ClusterName = cluster.Name
		obs.ClusterFound = true
	}

	vmNames, err := m.enumerateVMNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain summary (vms): %w", err)
	}
	sorted := make([]string, len(vmNames))
	copy(sorted, vmNames)
	sort.Strings(sorted)
	obs.VMNames = sorted

	switches, err := m.observeVSwitchDomain(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyperv: domain summary (vswitches): %w", err)
	}
	swNames := make([]string, len(switches))
	for i, sw := range switches {
		swNames[i] = sw.Name
	}
	sort.Strings(swNames)
	obs.VSwitchNames = swNames

	return obs, nil
}
