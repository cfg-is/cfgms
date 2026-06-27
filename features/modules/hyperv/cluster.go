// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ErrClusterNotDeclared is returned by getCluster / clusterOwnershipHelper when
// the requested cluster name does not match the steward's configured
// cluster_name scope cap (S5). It is returned WITHOUT invoking any PowerShell
// cmdlet — an undeclared cluster name is rejected before the transport is
// touched, regardless of ownership.
var ErrClusterNotDeclared = errors.New("hyperv: cluster not in declared cluster_name scope")

// ErrTransportNotConfigured is returned by getCluster / clusterOwnershipHelper
// when the module has no transport wired (m.transport == nil). It is distinct
// from ErrClusterNotDeclared (a scope-cap sentinel) so callers can tell a
// misconfiguration apart from an out-of-scope cluster name.
var ErrTransportNotConfigured = errors.New("hyperv: cluster transport not configured")

// ClusterConfig is the DESIRED state of a Hyper-V failover cluster as declared
// by an operator. S1 manages no cluster mutation; the desired-state struct
// exists so the executor and DNA layers have a stable ConfigState shape (Set /
// create lands in S2).
type ClusterConfig struct {
	// Name is the failover cluster name (the CNO). Required.
	Name string `yaml:"name"`
	// RoleNames is the bounded set of clustered VM role names this resource
	// manages (S5). Empty means "all roles in scope".
	RoleNames []string `yaml:"role_names,omitempty"`
	// AllowDestructive opts in to destructive cluster operations (S6). Default
	// false — read-only S1 never consults it, but the field is part of the
	// declared contract.
	AllowDestructive bool `yaml:"allow_destructive,omitempty"`
	// State is the desired lifecycle: present (default) — cluster formation /
	// teardown is out of scope for S1.
	State string `yaml:"state,omitempty"`
}

// Validate checks the ClusterConfig fields. Name is required.
func (c *ClusterConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("hyperv: cluster name is required")
	}
	return nil
}

// AsMap implements modules.ConfigState.
func (c *ClusterConfig) AsMap() map[string]interface{} {
	roles := make([]string, len(c.RoleNames))
	copy(roles, c.RoleNames)
	return map[string]interface{}{
		"name":              c.Name,
		"role_names":        roles,
		"allow_destructive": c.AllowDestructive,
		"state":             c.State,
	}
}

// ToYAML implements modules.ConfigState.
func (c *ClusterConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML implements modules.ConfigState.
func (c *ClusterConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// GetManagedFields implements modules.ConfigState.
func (c *ClusterConfig) GetManagedFields() []string {
	return []string{"name", "role_names", "allow_destructive", "state"}
}

// ClusterStatus is the OBSERVED state of a Hyper-V failover cluster returned by
// Get("cluster:<name>"). It is also the DNA payload shape consumed by the S4
// Monitor: AsMap exposes the stable keys member_nodes, resource_owner,
// cno_owner_node, csv_paths, and name.
type ClusterStatus struct {
	// Name is the cluster (CNO) name.
	Name string
	// CNOOwnerNode is the node currently owning the core "Cluster Group"
	// (the CNO). Empty when the CNO has no current owner (transient failover).
	CNOOwnerNode string
	// MemberNodes is the set of cluster member node names.
	MemberNodes []string
	// RoleOwners maps each clustered VM role (group) name to its current owner
	// node. Exposed as the AsMap key resource_owner.
	RoleOwners map[string]string
	// CSVPaths is the set of Cluster Shared Volume friendly volume paths.
	CSVPaths []string
	// Found reports whether the cluster exists / was queryable on the host.
	Found bool
}

// Validate implements modules.ConfigState. Observed status carries no operator
// constraints to enforce, so it always validates.
func (s *ClusterStatus) Validate() error { return nil }

// AsMap implements modules.ConfigState. The key set (member_nodes,
// resource_owner, cno_owner_node, csv_paths, name) is the DNA contract the S4
// Monitor and the controller-side reconciler read; do not rename them.
func (s *ClusterStatus) AsMap() map[string]interface{} {
	members := make([]string, len(s.MemberNodes))
	copy(members, s.MemberNodes)
	csv := make([]string, len(s.CSVPaths))
	copy(csv, s.CSVPaths)
	owners := make(map[string]string, len(s.RoleOwners))
	for k, v := range s.RoleOwners {
		owners[k] = v
	}
	return map[string]interface{}{
		"name":           s.Name,
		"cno_owner_node": s.CNOOwnerNode,
		"member_nodes":   members,
		"resource_owner": owners,
		"csv_paths":      csv,
		"found":          s.Found,
	}
}

// ToYAML implements modules.ConfigState.
func (s *ClusterStatus) ToYAML() ([]byte, error) {
	return yaml.Marshal(s.AsMap())
}

// FromYAML implements modules.ConfigState. Observed status is never decoded from
// operator YAML; provided for interface completeness.
func (s *ClusterStatus) FromYAML(_ []byte) error { return nil }

// GetManagedFields implements modules.ConfigState.
func (s *ClusterStatus) GetManagedFields() []string {
	return []string{"name", "cno_owner_node", "member_nodes", "resource_owner", "csv_paths"}
}

// psGetCluster reads the cluster identity, member node names, and CSV friendly
// volume paths. $ClusterName travels via ArgumentList — never interpolated. It
// emits {"found":false} when the cluster is not present (e.g. the cluster
// service is not running or the host is standalone).
const psGetCluster = `$c = Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue; if (-not $c) { Write-Output '{"found":false}'; return }; $nodes = @(Get-ClusterNode -Cluster $ClusterName -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }); $csv = @(Get-ClusterSharedVolume -Cluster $ClusterName -ErrorAction SilentlyContinue | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }); ConvertTo-Json @{ found=$true; Name=$c.Name; MemberNodes=$nodes; CsvPaths=$csv } -Compress -Depth 4`

// psGetClusterOwnerNode reads the current owner node of the core "Cluster
// Group" (the CNO). It emits {"owner":""} when the group has no current owner
// (transient failover) so the Go helper can treat absence as non-error.
const psGetClusterOwnerNode = `$g = Get-ClusterGroup -Cluster $ClusterName -Name 'Cluster Group' -ErrorAction SilentlyContinue; if (-not $g -or -not $g.OwnerNode) { Write-Output '{"owner":""}'; return }; ConvertTo-Json @{ owner=$g.OwnerNode.Name } -Compress`

// psGetClusterResourceOwner reads the current owner node of every clustered VM
// role group (GroupType -eq 'VirtualMachine'). It emits {"owners":{name:owner}}.
const psGetClusterResourceOwner = `$owners = @{}; Get-ClusterGroup -Cluster $ClusterName -ErrorAction SilentlyContinue | Where-Object { $_.GroupType -eq 'VirtualMachine' } | ForEach-Object { $owners[$_.Name] = if ($_.OwnerNode) { $_.OwnerNode.Name } else { '' } }; ConvertTo-Json @{ owners=$owners } -Compress -Depth 4`

// getCluster returns the observed state of a failover cluster on the host.
//
// Scope cap (S5): when the steward has a configured clusterName and the
// requested name differs, getCluster returns ErrClusterNotDeclared WITHOUT
// invoking the transport — an undeclared cluster name is never queried.
//
// Contract:
//   - cluster declared + present  → (&ClusterStatus{Found:true, ...}, nil)
//   - cluster declared + absent   → (&ClusterStatus{Name, Found:false}, nil)
//   - out-of-scope cluster name   → (nil, ErrClusterNotDeclared)
//   - module not ready / PS error → (nil, wrapped error)
func (m *hypervModule) getCluster(ctx context.Context, name string) (modules.ConfigState, error) {
	if m.clusterName != "" && name != m.clusterName {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: declining cluster — not in declared cluster_name scope",
				"requested", logging.SanitizeLogValue(name),
				"declared", logging.SanitizeLogValue(m.clusterName))
		}
		return nil, fmt.Errorf("hyperv: get cluster %q: %w", name, ErrClusterNotDeclared)
	}
	if m.transport == nil {
		return nil, fmt.Errorf("hyperv: get cluster %q: %w", name, ErrTransportNotConfigured)
	}

	output, err := m.transport.ExecutePS(ctx, psGetCluster, map[string]string{"ClusterName": name})
	if err != nil {
		return nil, fmt.Errorf("hyperv: get cluster %q: %w", name, err)
	}

	var parsed struct {
		Found       bool     `json:"found"`
		Name        string   `json:"Name"`
		MemberNodes []string `json:"MemberNodes"`
		CsvPaths    []string `json:"CsvPaths"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jsonErr != nil {
		return nil, fmt.Errorf("hyperv: parse get-cluster response for %q: %w", name, jsonErr)
	}
	if !parsed.Found {
		return &ClusterStatus{Name: name, Found: false}, nil
	}

	status := &ClusterStatus{
		Name:        firstNonEmpty(parsed.Name, name),
		MemberNodes: parsed.MemberNodes,
		CSVPaths:    parsed.CsvPaths,
		RoleOwners:  map[string]string{},
		Found:       true,
	}

	// CNO owner: absence is non-fatal (transient failover) — leave empty.
	ownsCNO, roleOwners, ownErr := m.clusterOwnershipHelper(ctx, name)
	if ownErr != nil {
		return nil, ownErr
	}
	if roleOwners != nil {
		status.RoleOwners = roleOwners
	}
	if ownsCNO {
		status.CNOOwnerNode = m.nodeHostname
	} else {
		// The helper already audited the ownership decision and captured the
		// owner; re-read it here so Get reflects the live CNO owner even when
		// this node is not the owner.
		status.CNOOwnerNode = m.readCNOOwner(ctx, name)
	}

	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
		"Get-Cluster", "cluster:"+name, nil, nil, nil)

	return status, nil
}

// readCNOOwner queries the current CNO owner node name, returning "" on any
// error or when the CNO has no current owner. Used by getCluster to populate
// cno_owner_node on a non-owner node without surfacing transient errors.
func (m *hypervModule) readCNOOwner(ctx context.Context, clusterName string) string {
	if m.transport == nil {
		return ""
	}
	out, err := m.transport.ExecutePS(ctx, psGetClusterOwnerNode, map[string]string{"ClusterName": clusterName})
	if err != nil {
		return ""
	}
	var parsed struct {
		Owner string `json:"owner"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); jsonErr != nil {
		return ""
	}
	return parsed.Owner
}

// clusterOwnershipHelper reports whether THIS node owns the CNO group and the
// per-role-group owner map. It is the coordination primitive every downstream
// cluster operation consults to decide which node acts (exactly-once) — it is
// coordination, NOT authorization (S1): it never blocks CFGMS from acting and a
// non-owner is a nil (skip), never an error.
//
// Scope cap (S5): an out-of-scope clusterName returns ErrClusterNotDeclared
// WITHOUT touching the transport, regardless of ownership.
//
// Technical Decision: when the CNO group has no current owner (transient
// failover), the helper returns (false, nil, nil) — no error, no intra-cycle
// retry. The caller treats this node as non-owner for this cycle.
func (m *hypervModule) clusterOwnershipHelper(ctx context.Context, clusterName string) (ownsCNO bool, resourceOwners map[string]string, err error) {
	if m.clusterName != "" && clusterName != m.clusterName {
		return false, nil, fmt.Errorf("hyperv: cluster ownership %q: %w", clusterName, ErrClusterNotDeclared)
	}
	if m.transport == nil {
		return false, nil, fmt.Errorf("hyperv: cluster ownership %q: %w", clusterName, ErrTransportNotConfigured)
	}

	owner := m.readCNOOwner(ctx, clusterName)

	// CNO transient: no current owner → treat this node as non-owner, no error
	// (Technical Decision). Do not query role owners or emit an ownership audit
	// for a cluster whose CNO is mid-failover.
	if owner == "" {
		return false, nil, nil
	}

	resourceOwners, err = m.readResourceOwners(ctx, clusterName)
	if err != nil {
		return false, nil, err
	}

	ownsCNO = strings.EqualFold(owner, m.nodeHostname)

	// S8: record the ownership decision with Go receipt-time and a non-empty
	// node identity (m.nodeHostname). after carries only the non-sensitive
	// decision scalars.
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
		"cluster-ownership", "cluster:"+clusterName, nil,
		map[string]interface{}{"owner": owner, "owns_cno": ownsCNO}, nil)

	return ownsCNO, resourceOwners, nil
}

// readResourceOwners queries the per-VM-role-group owner map.
func (m *hypervModule) readResourceOwners(ctx context.Context, clusterName string) (map[string]string, error) {
	out, err := m.transport.ExecutePS(ctx, psGetClusterResourceOwner, map[string]string{"ClusterName": clusterName})
	if err != nil {
		return nil, fmt.Errorf("hyperv: get cluster resource owners %q: %w", clusterName, err)
	}
	var parsed struct {
		Owners map[string]string `json:"owners"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); jsonErr != nil {
		return nil, fmt.Errorf("hyperv: parse cluster resource owners for %q: %w", clusterName, jsonErr)
	}
	if parsed.Owners == nil {
		parsed.Owners = map[string]string{}
	}
	return parsed.Owners, nil
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// compile-time guard: both cluster ConfigState types satisfy the interface.
//
// Audit timestamps for the ownership decision are Go receipt-time (S8): the
// audit Manager stamps time.Now() in RecordEvent — never a PS-reported value.
var (
	_ modules.ConfigState = (*ClusterConfig)(nil)
	_ modules.ConfigState = (*ClusterStatus)(nil)
)
