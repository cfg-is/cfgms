// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// ErrDestructiveOpBlocked is returned by setCluster when a destructive cluster
// operation (state: absent — role removal) is requested without the operator
// opting in via allow_destructive: true (S6). It is returned WITHOUT invoking
// any PowerShell write cmdlet — the destructive gate is checked before the
// transport is touched, so a default-off config can never delete a clustered
// role even if the steward owns the CNO.
var ErrDestructiveOpBlocked = errors.New("hyperv: destructive cluster operation blocked — set allow_destructive: true to proceed")

// ErrRoleMembershipNotClusterManaged is returned by setCluster when a
// hyperv.cluster resource attempts to remove VM-role membership (state: absent
// on role_names). VM cluster-role membership is a hyperv.vm setting (ha_role) —
// the single config surface for VM-scoped settings (#2372). Declaring or
// removing ha_role on the vm resource is the only way to promote or demote.
var ErrRoleMembershipNotClusterManaged = errors.New("hyperv: VM cluster-role membership is managed via the hyperv.vm ha_role setting, not hyperv.cluster role_names")

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
	// Roles maps a clustered VM role name (a member of RoleNames) to its desired
	// failover-cluster placement/scheduling properties. Reconciled on the CNO
	// owner AFTER the role exists. Absent/empty ⇒ leave properties at cluster
	// defaults. (#2306 declarative cluster-role properties.)
	Roles map[string]ClusterRoleProperties `yaml:"roles,omitempty"`
}

// ClusterRoleProperties is the desired placement and scheduling properties for
// one clustered VM role. All fields are optional; a nil pointer or empty slice
// means "leave at the cluster default".
type ClusterRoleProperties struct {
	// PreferredOwners is the ordered list of preferred failover nodes for the
	// role group. Reconciled via Set-ClusterOwnerNode -Group.
	PreferredOwners []string `yaml:"preferred_owners,omitempty"`
	// PossibleOwners restricts which nodes may own the role's VM resource.
	// Reconciled via Set-ClusterOwnerNode -Resource.
	PossibleOwners []string `yaml:"possible_owners,omitempty"`
	// Priority is the cluster group priority (0, 1000, 2000, or 3000).
	Priority *int `yaml:"priority,omitempty"`
	// AutoStart controls whether the cluster starts the group at node startup.
	AutoStart *bool `yaml:"auto_start,omitempty"`
	// AntiAffinityClass is an anti-affinity token the scheduler uses to separate
	// sibling roles across nodes.
	AntiAffinityClass string `yaml:"anti_affinity_class,omitempty"`
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
	roleNames := make([]string, len(c.RoleNames))
	copy(roleNames, c.RoleNames)
	m := map[string]interface{}{
		"name":              c.Name,
		"role_names":        roleNames,
		"allow_destructive": c.AllowDestructive,
		"state":             c.State,
	}
	if len(c.Roles) > 0 {
		roles := make(map[string]interface{}, len(c.Roles))
		for name, p := range c.Roles {
			roles[name] = p.asMap()
		}
		m["roles"] = roles
	}
	return m
}

// asMap serialises one role's properties to the stable declarative keys. Only
// set fields are included so the map round-trips through parseClusterConfig
// without inventing defaults.
func (p ClusterRoleProperties) asMap() map[string]interface{} {
	out := map[string]interface{}{}
	if len(p.PreferredOwners) > 0 {
		out["preferred_owners"] = append([]string(nil), p.PreferredOwners...)
	}
	if len(p.PossibleOwners) > 0 {
		out["possible_owners"] = append([]string(nil), p.PossibleOwners...)
	}
	if p.Priority != nil {
		out["priority"] = *p.Priority
	}
	if p.AutoStart != nil {
		out["auto_start"] = *p.AutoStart
	}
	if p.AntiAffinityClass != "" {
		out["anti_affinity_class"] = p.AntiAffinityClass
	}
	return out
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
	return []string{"name", "role_names", "allow_destructive", "state", "roles"}
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
	// ClusterAccessOK reports whether this node's computer account holds the
	// cluster-management access HA role operations require (#2306). True on a
	// standalone host (no cluster to gate) and when the probe cannot determine
	// access (unknown ⇒ no false alert). False only on a confirmed missing grant.
	ClusterAccessOK bool
	// ClusterAccessRemediation is the exact operator command to grant this node
	// cluster access when ClusterAccessOK is false; empty otherwise. Surfaced as a
	// controller-visible onboarding alert.
	ClusterAccessRemediation string
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
		"name":                       s.Name,
		"cno_owner_node":             s.CNOOwnerNode,
		"member_nodes":               members,
		"resource_owner":             owners,
		"csv_paths":                  csv,
		"found":                      s.Found,
		"cluster_access_ok":          s.ClusterAccessOK,
		"cluster_access_remediation": s.ClusterAccessRemediation,
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
	return []string{"name", "cno_owner_node", "member_nodes", "resource_owner", "csv_paths", "cluster_access_ok"}
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

// psAddClusterVMRole clusters an existing Hyper-V VM as a highly-available role
// (S2 create). $ClusterName and $VMName travel via ArgumentList — never
// interpolated. Add-ClusterVirtualMachineRole is the write cmdlet; only the
// CNO-owner node invokes it (the ownership gate ensures exactly-once across the
// members). The Go caller normalises an "already exists"/"already registered"
// error to nil (idempotency).
//
// Cluster by -VMId, NOT -VirtualMachine <name>: the by-name path makes
// Add-ClusterVirtualMachineRole resolve the VM via a WMI enumeration across
// cluster nodes (ViridianVirtualMachine.GetAllVirtualMachinesByName ->
// ManagementScope.Initialize), which fails "Access is denied" when the module
// runs as the LocalSystem steward — cross-node WMI as the machine identity is
// denied. Resolving the VM to its Id locally (Get-VM -Name is a local WMI call
// that succeeds) and clustering by -VMId skips that enumeration and works as
// SYSTEM. $VMName still travels via ArgumentList (never interpolated).
const psAddClusterVMRole = `$vmid = (Get-VM -Name $VMName -ErrorAction Stop).Id; Add-ClusterVirtualMachineRole -Cluster $ClusterName -VMId $vmid | Out-Null`

// psRemoveClusterResource removes a clustered VM role group (S2 destructive
// teardown, gated behind allow_destructive: true). $Name travels via
// ArgumentList — never interpolated. This const is a dispatch key; the executed
// command is Cfgms-RemoveClusterResource in the preamble, which uses
// Remove-ClusterGroup -RemoveResources (the VM role's GROUP name, not a resource
// name — see that function). Reached only after the Go destructive gate.
const psRemoveClusterResource = `Remove-ClusterGroup -Name $Name -RemoveResources -Force`

// psGetClusterAccessSelf reads whether THIS node's computer account holds
// cluster-management access (#2306 onboarding). Read-only; a denied/absent read
// (Get-ClusterAccess SilentlyContinue) yields access_ok:false. The account and
// the exact remediation grant come from PowerShell, never Go string composition.
const psGetClusterAccessSelf = `$me = '{0}\{1}$' -f $env:USERDOMAIN, $env:COMPUTERNAME; $acl = @(Get-ClusterAccess -Cluster $ClusterName -ErrorAction SilentlyContinue); $ok = @($acl | Where-Object { $_.IdentityReference -ieq $me }).Count -gt 0; ConvertTo-Json @{ account=$me; access_ok=$ok; remediation=("Grant-ClusterAccess -Cluster {0} -User '{1}' -Full" -f $ClusterName, $me) } -Compress`

// Cluster-access lifecycle commands (#2306 PROPERTIES/lifecycle, option 3).
// These are PRIVILEGED, controller-orchestrated grant/revoke primitives — NOT
// reachable from routine hyperv.cluster Set convergence. $NodeName is a cluster
// node's short name; the computer account (DOMAIN\<node>$) is built in PowerShell
// from $env:USERDOMAIN, never composed in Go. Dispatch keys.
const (
	// psListClusterAccessNodes returns the node short-names of the computer
	// accounts currently granted cluster access (drift-detection source).
	psListClusterAccessNodes = `ConvertTo-Json @{ nodes = @(Get-ClusterAccess -Cluster $ClusterName -ErrorAction SilentlyContinue | Where-Object { $_.IdentityReference -match '\$$' } | ForEach-Object { ($_.IdentityReference -replace '.*\\','') -replace '\$$','' }) } -Compress`
	// psGrantClusterAccess grants $NodeName's computer account Full cluster access
	// (the DOMAIN\<node>$ account is built in the preamble from $env:USERDOMAIN).
	psGrantClusterAccess = `Grant-ClusterAccess -Cluster $ClusterName -User (DOMAIN\$NodeName$) -Full`
	// psRevokeClusterAccess removes $NodeName's computer account from the cluster ACL.
	psRevokeClusterAccess = `Remove-ClusterAccess -Cluster $ClusterName -User (DOMAIN\$NodeName$)`
)

// Declarative cluster-role property set commands (#2306). These consts are
// dispatch KEYS — the executed PowerShell lives in the Cfgms-Set* preamble
// functions wired by the PS-transport story (PROPERTIES-B); the reconcile below
// dispatches them via m.transport.ExecutePS with ArgumentList args (never
// interpolated). Reconciled ONLY on the CNO-owner node, AFTER the role exists.
const (
	// psSetClusterRolePreferredOwners sets the ordered preferred owners of the
	// role GROUP. Args: ClusterName, GroupName, Owners (comma-joined node list).
	psSetClusterRolePreferredOwners = `Set-ClusterOwnerNode -Cluster $ClusterName -Group $GroupName -Owners $Owners`
	// psSetClusterRolePossibleOwners restricts the possible owners of the role's
	// VM RESOURCE. Args: ClusterName, ResourceName, Owners.
	psSetClusterRolePossibleOwners = `Set-ClusterOwnerNode -Cluster $ClusterName -Resource $ResourceName -Owners $Owners`
	// psSetClusterGroupPriority sets the cluster group priority. Args:
	// ClusterName, GroupName, Priority.
	psSetClusterGroupPriority = `Set-ClusterGroup -Cluster $ClusterName -Name $GroupName -Priority $Priority`
	// psSetClusterGroupAutoStart sets the group's AutoStart. Args: ClusterName,
	// GroupName, AutoStart (0|1).
	psSetClusterGroupAutoStart = `Set-ClusterGroup -Cluster $ClusterName -Name $GroupName -AutoStart $AutoStart`
	// psSetClusterGroupAntiAffinity sets the group's AntiAffinityClassNames.
	// Args: ClusterName, GroupName, ClassName.
	psSetClusterGroupAntiAffinity = `Set-ClusterGroup -Cluster $ClusterName -Name $GroupName -AntiAffinityClass $ClassName`
)

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
		// Standalone host: no cluster to gate access on — never alert.
		return &ClusterStatus{Name: name, Found: false, ClusterAccessOK: true}, nil
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

	// Cluster-access self-check (#2306 onboarding): does this node's computer
	// account hold the cluster-management access HA role ops require? A missing
	// grant surfaces (via the DNA cluster_access_ok field + the Monitor) as a
	// controller-visible onboarding alert with the exact remediation command.
	status.ClusterAccessOK, status.ClusterAccessRemediation = m.probeClusterAccess(ctx, name)

	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
		"Get-Cluster", "cluster:"+name, nil, nil, nil)

	return status, nil
}

// probeClusterAccess reports whether this node's computer account holds
// cluster-management access, and (when it does not) the exact operator command
// to grant it. Read-only. A transport or parse error is treated as UNKNOWN —
// access OK, no remediation — so a transient probe failure never raises a false
// onboarding alert (only a confirmed missing grant does).
func (m *hypervModule) probeClusterAccess(ctx context.Context, name string) (bool, string) {
	out, err := m.transport.ExecutePS(ctx, psGetClusterAccessSelf, map[string]string{"ClusterName": name})
	if err != nil {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: cluster-access self-check probe failed; treating as access OK",
				"cluster", logging.SanitizeLogValue(name))
		}
		return true, ""
	}
	var r struct {
		Account     string `json:"account"`
		AccessOK    bool   `json:"access_ok"`
		Remediation string `json:"remediation"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); jsonErr != nil {
		return true, ""
	}
	if r.AccessOK {
		return true, ""
	}
	return false, r.Remediation
}

// ClusterAccessReconcile is the outcome of a cluster-access lifecycle reconcile:
// the node computer accounts granted and revoked to make the cluster ACL match
// the desired member set.
type ClusterAccessReconcile struct {
	Granted []string
	Revoked []string
}

// computeClusterAccessReconcile computes, case-insensitively, which member nodes
// need a grant (a desired member whose computer account is not in the ACL) and
// which granted nodes need a revoke (in the ACL but no longer a desired member —
// drift, e.g. a retired node). Pure: no I/O, deterministic sets.
func computeClusterAccessReconcile(desiredMembers, currentGranted []string) (grants, revokes []string) {
	cur := map[string]string{} // lower(node) -> original
	for _, n := range currentGranted {
		if s := strings.TrimSpace(n); s != "" {
			cur[strings.ToLower(s)] = s
		}
	}
	des := map[string]struct{}{}
	for _, n := range desiredMembers {
		s := strings.TrimSpace(n)
		if s == "" {
			continue
		}
		des[strings.ToLower(s)] = struct{}{}
		if _, ok := cur[strings.ToLower(s)]; !ok {
			grants = append(grants, s)
		}
	}
	for lower, orig := range cur {
		if _, ok := des[lower]; !ok {
			revokes = append(revokes, orig)
		}
	}
	return grants, revokes
}

// ReconcileClusterAccess is the PRIVILEGED cluster-access lifecycle reconcile
// (#2306 option 3): make the cluster ACL's node computer-account grants match the
// desired member set. It reads the current grants, computes grants (desired
// members lacking access) + revokes (granted nodes no longer members), applies
// them via Grant-/Remove-ClusterAccess, and audits each. It is invoked by the
// CONTROLLER's cluster-access lifecycle — NOT by routine hyperv.cluster Set
// convergence — and runs on a node whose steward already holds cluster access.
// Grant/revoke of an already-consistent account is a no-op (idempotent).
func (m *hypervModule) ReconcileClusterAccess(ctx context.Context, clusterName string, desiredMembers []string) (ClusterAccessReconcile, error) {
	var result ClusterAccessReconcile
	if m.transport == nil {
		return result, fmt.Errorf("hyperv: reconcile cluster access %q: %w", clusterName, ErrTransportNotConfigured)
	}
	out, err := m.transport.ExecutePS(ctx, psListClusterAccessNodes, map[string]string{"ClusterName": clusterName})
	if err != nil {
		return result, fmt.Errorf("hyperv: list cluster access %q: %w", clusterName, err)
	}
	var parsed struct {
		Nodes []string `json:"nodes"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); jsonErr != nil {
		return result, fmt.Errorf("hyperv: parse cluster access list %q: %w", clusterName, jsonErr)
	}

	grants, revokes := computeClusterAccessReconcile(desiredMembers, parsed.Nodes)

	for _, node := range grants {
		if _, err := m.transport.ExecutePS(ctx, psGrantClusterAccess, map[string]string{"ClusterName": clusterName, "NodeName": node}); err != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-access-grant", "cluster:"+clusterName,
				map[string]interface{}{"node": logging.SanitizeLogValue(node)},
				map[string]interface{}{"granted": false}, err)
			return result, fmt.Errorf("hyperv: grant cluster access to %q: %w", node, err)
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-access-grant", "cluster:"+clusterName,
			map[string]interface{}{"node": logging.SanitizeLogValue(node)},
			map[string]interface{}{"granted": true}, nil)
		result.Granted = append(result.Granted, node)
	}
	for _, node := range revokes {
		if _, err := m.transport.ExecutePS(ctx, psRevokeClusterAccess, map[string]string{"ClusterName": clusterName, "NodeName": node}); err != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-access-revoke", "cluster:"+clusterName,
				map[string]interface{}{"node": logging.SanitizeLogValue(node)},
				map[string]interface{}{"revoked": false}, err)
			return result, fmt.Errorf("hyperv: revoke cluster access from %q: %w", node, err)
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-access-revoke", "cluster:"+clusterName,
			map[string]interface{}{"node": logging.SanitizeLogValue(node)},
			map[string]interface{}{"revoked": true}, nil)
		result.Revoked = append(result.Revoked, node)
	}
	return result, nil
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

// cachedResourceOwners returns the bulk cluster resource-owner map, reading it
// from the transport at most once per freshness window (Story #2577). This
// collapses the per-HA-VM membership probes of one converge pass into a single
// cluster read instead of one read per VM. It backs only the fail-safe READ
// path (probeClusterRoleMembership); the write-path owner gate keeps reading
// live via clusterOwnershipHelper. Any cluster-mutating op calls
// invalidateClusterOwnersCache so work we just performed is reflected at once.
// A returned map is treated as read-only by callers (it is the shared cache).
func (m *hypervModule) cachedResourceOwners(ctx context.Context, clusterName string) (map[string]string, error) {
	m.clusterOwnersMu.Lock()
	defer m.clusterOwnersMu.Unlock()
	if m.clusterOwners != nil && m.clusterOwnersTTL > 0 && time.Since(m.clusterOwnersAt) < m.clusterOwnersTTL {
		return m.clusterOwners, nil
	}
	owners, err := m.readResourceOwners(ctx, clusterName)
	if err != nil {
		return nil, err
	}
	m.clusterOwners = owners
	m.clusterOwnersAt = time.Now()
	return owners, nil
}

// invalidateClusterOwnersCache drops the cached bulk owner map so the next read
// path re-queries the cluster. Called after any op that changes clustered-role
// ownership or membership (register, move, remove) so a freshly-mutated cluster
// is never served stale from the Story #2577 read cache.
func (m *hypervModule) invalidateClusterOwnersCache() {
	m.clusterOwnersMu.Lock()
	m.clusterOwners = nil
	m.clusterOwnersMu.Unlock()
}

// setCluster reconciles the placement/scheduling PROPERTIES of existing
// clustered VM roles (#2306). It is the Set("cluster:<name>", config) write
// path — cluster-scoped only since #2372: it never creates or removes VM-role
// membership (that is the hyperv.vm ha_role setting, via
// reconcileRoleMembership below).
//
// Decision order (each step short-circuits BEFORE any transport call where it
// can):
//
//  1. Scope cap (S5): an out-of-scope clusterName returns ErrClusterNotDeclared
//     WITHOUT touching the transport.
//  2. Transport wired: a nil transport returns ErrTransportNotConfigured.
//  3. CNO gate (S1): clusterOwnershipHelper decides which node acts. A NON-owner
//     records an ownership-gated-skip audit event and returns nil — ownership is
//     coordination, not authorization, so a non-owner never errors or blocks.
//  4. On the owner:
//     - state: absent → ErrRoleMembershipNotClusterManaged with NO PS write —
//     the pre-#2372 destructive role-removal surface is hard-removed
//     (demote by removing ha_role on the vm resource).
//     - present (default): for each role NAMED in RoleNames
//     (drift-not-adopted, S1 — roles absent from cfg are never touched):
//     a role missing from the cluster is skipped with a warn + audit (it is
//     NOT created); an existing role gets its declared placement properties
//     reconciled via reconcileRoleProperties.
//
// Every path (create / gated-skip / idempotent no-op / destructive / drift)
// records a pkg/audit event via recordHypervOp with the node identity
// (m.nodeHostname), the CNO-owner decision, and before/after state maps;
// timestamps are Go receipt-time (S8).
func (m *hypervModule) setCluster(ctx context.Context, resourceID string, config modules.ConfigState) error {
	_, name, _ := splitResourceID(resourceID)

	cfg := parseClusterConfig(name, config)

	// (1) Scope cap (S5): reject an out-of-scope cluster name before the transport.
	if m.clusterName != "" && cfg.Name != m.clusterName {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: declining cluster Set — not in declared cluster_name scope",
				"requested", logging.SanitizeLogValue(cfg.Name),
				"declared", logging.SanitizeLogValue(m.clusterName))
		}
		return fmt.Errorf("hyperv: set cluster %q: %w", cfg.Name, ErrClusterNotDeclared)
	}

	// (2) Transport wired.
	if m.transport == nil {
		return fmt.Errorf("hyperv: set cluster %q: %w", cfg.Name, ErrTransportNotConfigured)
	}

	// (3) CNO gate (S1). The helper enforces the scope cap again, audits the
	// ownership decision, and returns the per-role owner map (its readResourceOwners
	// output) which doubles as the existence-check oracle below — no 4th PS function.
	ownsCNO, resourceOwners, err := m.clusterOwnershipHelper(ctx, cfg.Name)
	if err != nil {
		return fmt.Errorf("hyperv: set cluster %q: %w", cfg.Name, err)
	}

	cnoOwner := m.readCNOOwner(ctx, cfg.Name)

	if !ownsCNO {
		// Non-owner: record an ownership-gated-skip and return nil. Coordination,
		// not authorization (S1) — never an error, never a PS mutation here.
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-skip", "cluster:"+cfg.Name, nil,
			map[string]interface{}{
				"owns_cno":  false,
				"cno_owner": cnoOwner,
				"skipped":   true,
				"roles":     append([]string(nil), cfg.RoleNames...),
			}, nil)
		return nil
	}

	if resourceOwners == nil {
		resourceOwners = map[string]string{}
	}

	// (4) Owner path. hyperv.cluster is cluster-scoped only (#2372): it never
	// mutates VM-role membership. Creating and removing clustered VM roles is
	// the hyperv.vm ha_role setting — the single config surface for VM-scoped
	// settings. Roles named in role_names are property-reconcile targets ONLY.
	if strings.EqualFold(strings.TrimSpace(cfg.State), "absent") {
		// The pre-#2372 destructive role-removal surface. Hard-removed: demotion
		// is ha_role removal on the vm resource. Refused before any PS mutation.
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-remove-refused", "cluster:"+cfg.Name,
			map[string]interface{}{"roles": append([]string(nil), cfg.RoleNames...)},
			map[string]interface{}{"refused": true, "cno_owner": cnoOwner}, ErrRoleMembershipNotClusterManaged)
		return fmt.Errorf("hyperv: set cluster %q: %w", cfg.Name, ErrRoleMembershipNotClusterManaged)
	}

	for _, role := range cfg.RoleNames {
		if strings.TrimSpace(role) == "" {
			continue
		}
		if _, exists := resourceOwners[role]; !exists {
			// Not a clustered role: hyperv.cluster no longer creates it. The
			// role converges when its hyperv.vm resource declares ha_role; its
			// properties reconcile on a later cycle once it exists.
			if logger, ok := m.GetLogger(); ok {
				logger.Warn("hyperv: cluster role not present — hyperv.cluster does not create VM roles; declare ha_role on the hyperv.vm resource",
					"cluster", logging.SanitizeLogValue(cfg.Name),
					"role", logging.SanitizeLogValue(role))
			}
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-set-membership-skip", "cluster:"+cfg.Name,
				map[string]interface{}{"role": role, "exists": false},
				map[string]interface{}{"created": false, "single_surface": "hyperv.vm ha_role", "cno_owner": cnoOwner}, nil)
			continue
		}

		// Declarative property reconcile (#2306): the role exists on this
		// (CNO-owner) node — converge its placement/scheduling properties. A role
		// with no cfg.Roles entry is left at cluster defaults (no dispatch).
		if props, ok := cfg.Roles[role]; ok {
			if err := m.reconcileRoleProperties(ctx, cfg.Name, role, props); err != nil {
				return fmt.Errorf("hyperv: set cluster %q role %q properties: %w", cfg.Name, role, err)
			}
		}
	}

	return nil
}

// reconcileRoleMembership converges ONE VM's clustered-role membership — the
// single internal engine behind the hyperv.vm ha_role setting (#2372). It is
// called only by registerClusteredRole (promote, state "present") and
// demoteClusteredRole (demote, state "absent"); hyperv.cluster's operator
// surface never reaches it. Gates mirror setCluster: scope cap (S5), transport,
// CNO ownership (S1 — a non-owner audits a skip and returns nil; coordination,
// not authorization). Membership mutations are idempotent: an existing member
// is not re-added, an absent member is not re-removed, and Add's
// "already registered" error class is normalised to nil (post-failover
// existence-check↔Add race).
//
// allowDestructive gates the absent path exactly as S6 does for the old
// surface. The vm-side demote passes true unconditionally: demotion only ever
// removes the ROLE (Remove-ClusterGroup) — the VM itself is never touched — so
// the S6 opt-in protects nothing on this path and requiring a second operator
// flag would break AC1's convergent demote.
func (m *hypervModule) reconcileRoleMembership(ctx context.Context, clusterName, role, state string, allowDestructive bool) error {
	// (1) Scope cap (S5): reject an out-of-scope cluster name before the transport.
	if m.clusterName != "" && clusterName != m.clusterName {
		if logger, ok := m.GetLogger(); ok {
			logger.Warn("hyperv: declining role-membership reconcile — not in declared cluster_name scope",
				"requested", logging.SanitizeLogValue(clusterName),
				"declared", logging.SanitizeLogValue(m.clusterName))
		}
		return fmt.Errorf("hyperv: reconcile role membership %q/%q: %w", clusterName, role, ErrClusterNotDeclared)
	}

	// (2) Transport wired.
	if m.transport == nil {
		return fmt.Errorf("hyperv: reconcile role membership %q/%q: %w", clusterName, role, ErrTransportNotConfigured)
	}

	// (3) CNO gate (S1). The helper audits the ownership decision and returns
	// the role-owner map, which doubles as the existence oracle below.
	ownsCNO, resourceOwners, err := m.clusterOwnershipHelper(ctx, clusterName)
	if err != nil {
		return fmt.Errorf("hyperv: reconcile role membership %q/%q: %w", clusterName, role, err)
	}

	cnoOwner := m.readCNOOwner(ctx, clusterName)

	if !ownsCNO {
		// Non-owner: record an ownership-gated-skip and return nil.
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-skip", "cluster:"+clusterName, nil,
			map[string]interface{}{
				"owns_cno":  false,
				"cno_owner": cnoOwner,
				"skipped":   true,
				"roles":     []string{role},
			}, nil)
		return nil
	}

	if resourceOwners == nil {
		resourceOwners = map[string]string{}
	}
	_, exists := resourceOwners[role]

	if strings.EqualFold(strings.TrimSpace(state), "absent") {
		// S6 destructive gate. Default off: NO PS write cmdlet is issued.
		if !allowDestructive {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-set-remove-blocked", "cluster:"+clusterName,
				map[string]interface{}{"role": role, "exists": exists},
				map[string]interface{}{"allow_destructive": false, "blocked": true}, ErrDestructiveOpBlocked)
			return fmt.Errorf("hyperv: reconcile role membership %q role %q: %w", clusterName, role, ErrDestructiveOpBlocked)
		}
		if !exists {
			// Already gone — idempotent no-op for the destructive path.
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-set-remove-noop", "cluster:"+clusterName,
				map[string]interface{}{"role": role, "exists": false},
				map[string]interface{}{"removed": false, "cno_owner": cnoOwner}, nil)
			return nil
		}
		if _, rmErr := m.transport.ExecutePS(ctx, psRemoveClusterResource, map[string]string{"Name": role}); rmErr != nil {
			recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
				"cluster-set-remove", "cluster:"+clusterName,
				map[string]interface{}{"role": role, "exists": true},
				map[string]interface{}{"removed": false}, rmErr)
			return fmt.Errorf("hyperv: reconcile role membership %q remove role %q: %w", clusterName, role, rmErr)
		}
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-remove", "cluster:"+clusterName,
			map[string]interface{}{"role": role, "exists": true},
			map[string]interface{}{"removed": true, "cno_owner": cnoOwner}, nil)
		// Membership changed — drop the Story #2577 read cache so the next probe
		// sees the removed role.
		m.invalidateClusterOwnersCache()
		return nil
	}

	// Present (default): existence check BEFORE the Add (idempotency).
	if exists {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-noop", "cluster:"+clusterName,
			map[string]interface{}{"role": role, "exists": true},
			map[string]interface{}{"created": false, "cno_owner": cnoOwner}, nil)
		return nil
	}
	_, addErr := m.transport.ExecutePS(ctx, psAddClusterVMRole, map[string]string{
		"ClusterName": clusterName,
		"VMName":      role,
	})
	switch {
	case addErr == nil:
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-create", "cluster:"+clusterName,
			map[string]interface{}{"role": role, "exists": false},
			map[string]interface{}{"created": true, "cno_owner": cnoOwner}, nil)
	case isAlreadyRegistered(addErr):
		// Idempotency: an "already registered"/"already exists" error means a
		// concurrent owner (or a stale existence read post-failover) created
		// the role — normalise to nil. Only this text class is idempotent.
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-noop", "cluster:"+clusterName,
			map[string]interface{}{"role": role, "exists": false},
			map[string]interface{}{"created": false, "already_registered": true, "cno_owner": cnoOwner}, nil)
	default:
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-create", "cluster:"+clusterName,
			map[string]interface{}{"role": role, "exists": false},
			map[string]interface{}{"created": false}, addErr)
		return fmt.Errorf("hyperv: reconcile role membership %q add role %q: %w", clusterName, role, addErr)
	}
	// A role was registered (or observed already-registered) — drop the Story
	// #2577 read cache so the next membership probe reflects the new owner map.
	m.invalidateClusterOwnersCache()
	return nil
}

// reconcileRoleProperties converges the declarative placement/scheduling
// properties of one clustered VM role on the CNO-owner node. It is called by
// setCluster only after the role exists and only on the owner (the ownership
// gate is upstream). Each set is dispatched to the transport via ArgumentList
// args — never string-composed. The underlying Set-ClusterOwnerNode /
// Set-ClusterGroup cmdlets are idempotent, so re-applying an unchanged value is
// a harmless no-op. An audit event records what was reconciled (#2306).
func (m *hypervModule) reconcileRoleProperties(ctx context.Context, clusterName, role string, props ClusterRoleProperties) error {
	applied := map[string]interface{}{}

	if len(props.PreferredOwners) > 0 {
		if _, err := m.transport.ExecutePS(ctx, psSetClusterRolePreferredOwners, map[string]string{
			"ClusterName": clusterName,
			"GroupName":   role,
			"Owners":      strings.Join(props.PreferredOwners, ","),
		}); err != nil {
			return fmt.Errorf("preferred_owners: %w", err)
		}
		applied["preferred_owners"] = append([]string(nil), props.PreferredOwners...)
	}
	if len(props.PossibleOwners) > 0 {
		if _, err := m.transport.ExecutePS(ctx, psSetClusterRolePossibleOwners, map[string]string{
			"ClusterName":  clusterName,
			"ResourceName": role,
			"Owners":       strings.Join(props.PossibleOwners, ","),
		}); err != nil {
			return fmt.Errorf("possible_owners: %w", err)
		}
		applied["possible_owners"] = append([]string(nil), props.PossibleOwners...)
	}
	if props.Priority != nil {
		if _, err := m.transport.ExecutePS(ctx, psSetClusterGroupPriority, map[string]string{
			"ClusterName": clusterName,
			"GroupName":   role,
			"Priority":    strconv.Itoa(*props.Priority),
		}); err != nil {
			return fmt.Errorf("priority: %w", err)
		}
		applied["priority"] = *props.Priority
	}
	if props.AutoStart != nil {
		autoStart := "0"
		if *props.AutoStart {
			autoStart = "1"
		}
		if _, err := m.transport.ExecutePS(ctx, psSetClusterGroupAutoStart, map[string]string{
			"ClusterName": clusterName,
			"GroupName":   role,
			"AutoStart":   autoStart,
		}); err != nil {
			return fmt.Errorf("auto_start: %w", err)
		}
		applied["auto_start"] = *props.AutoStart
	}
	if props.AntiAffinityClass != "" {
		if _, err := m.transport.ExecutePS(ctx, psSetClusterGroupAntiAffinity, map[string]string{
			"ClusterName": clusterName,
			"GroupName":   role,
			"ClassName":   props.AntiAffinityClass,
		}); err != nil {
			return fmt.Errorf("anti_affinity_class: %w", err)
		}
		applied["anti_affinity_class"] = props.AntiAffinityClass
	}

	if len(applied) > 0 {
		recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.nodeHostname,
			"cluster-set-role-properties", "cluster:"+clusterName,
			map[string]interface{}{"role": role},
			map[string]interface{}{"applied": applied}, nil)
	}
	return nil
}

// parseClusterConfig builds a *ClusterConfig from the executor-supplied generic
// config map (config.AsMap), or copies a *ClusterConfig passed directly. The
// resource-id name is authoritative for Name so the scope cap always compares
// the addressed cluster.
func parseClusterConfig(name string, config modules.ConfigState) *ClusterConfig {
	cfg := &ClusterConfig{Name: name}
	if config == nil {
		return cfg
	}
	if cc, ok := config.(*ClusterConfig); ok {
		*cfg = *cc
		cfg.Name = name
		return cfg
	}
	cm := config.AsMap()
	cfg.RoleNames = parseStringList(cm["role_names"])
	if v, ok := cm["allow_destructive"].(bool); ok {
		cfg.AllowDestructive = v
	}
	if v, ok := cm["state"].(string); ok {
		cfg.State = v
	}
	cfg.Roles = parseClusterRoles(cm["roles"])
	return cfg
}

// parseClusterRoles builds the per-role properties map from the generic
// config map value at key "roles" (map[roleName]map[propertyKey]value). Unknown
// or malformed entries are skipped; a nil/empty input yields a nil map.
func parseClusterRoles(v interface{}) map[string]ClusterRoleProperties {
	raw, ok := v.(map[string]interface{})
	if !ok || len(raw) == 0 {
		return nil
	}
	roles := make(map[string]ClusterRoleProperties, len(raw))
	for name, pv := range raw {
		pm, ok := pv.(map[string]interface{})
		if !ok {
			continue
		}
		var p ClusterRoleProperties
		p.PreferredOwners = parseStringList(pm["preferred_owners"])
		p.PossibleOwners = parseStringList(pm["possible_owners"])
		if pr, ok := parseInt(pm["priority"]); ok {
			p.Priority = &pr
		}
		if as, ok := pm["auto_start"].(bool); ok {
			p.AutoStart = &as
		}
		if ac, ok := pm["anti_affinity_class"].(string); ok {
			p.AntiAffinityClass = ac
		}
		roles[name] = p
	}
	return roles
}

// parseInt coerces a config-map numeric (int, int64, or float64 from JSON) to an
// int. Returns ok=false when the value is absent or not numeric.
func parseInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// isAlreadyRegistered reports whether a PS error indicates the clustered role
// already exists. Matched case-insensitively on "already" ONLY — the stable
// fragments Failover Clustering emits when a VM is already an HA role both carry
// it ("already configured for high availability", "already exists"). A bare
// "exists" match is deliberately NOT used: it would swallow non-idempotent
// errors such as "The virtual machine 'web-01' does not exist". Any error
// without "already" is NOT idempotent and must surface (no blanket swallow).
func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "already")
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
