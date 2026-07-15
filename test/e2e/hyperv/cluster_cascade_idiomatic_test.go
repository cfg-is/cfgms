// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Idiomatic (Layer-2) fleet-e2e validation of the cluster.cfg cascade, the
// declarative FC placement surface, and the idiomatic leave — driven through the
// CONTROLLER (the cfg admin CLI) and observed via each member steward's effective
// configuration + the live cluster, rather than by calling module.Set directly.
//
// cluster_cascade_test.go (Layer 1, #2426) proves the owner-gating COMPONENTS by
// driving the real hyperv module as the node it runs on and steering ownership
// with raw Move-ClusterGroup. This file proves the OPERATING MODEL (#2577): config
// authored at the tenant/cluster scope, cascaded by the controller
// (InheritanceResolver, #2425), read by every member, with only the CNO acting —
// exactly the path an operator drives from the runbook, with nothing calling the
// module directly.
//
// The suite drives the controller with the `cfg` admin CLI (CFGMS_E2E_CFG_BIN +
// an admin bundle) and observes:
//   - each member steward's EFFECTIVE config via `cfg config show` (the cascade
//     fan-out), and
//   - the live cluster via the read-only cluster cmdlets (single create, declared
//     placement reflected, VM survival on leave).
//
// It authors NOTHING with raw cluster cmdlets — placement and membership are the
// things under test, so they only ever move through cfgms config.
//
// It reuses the Layer-1 harness in cluster_cascade_test.go (same package
// hyperv_e2e): ccPS / ccClusterNodes / ccMatchNode / ccVMInstances / ccEnv /
// getenvDefault / ccPollInterval / ccSettleTimeout.
//
// Skips cleanly (never fails) when the idiomatic controls are not configured:
// CFGMS_E2E_HYPERV_CLUSTER unset, no cfg binary / admin bundle, the member
// steward IDs unset, or the host is not a member of the named cluster.
package hyperv_e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Idiomatic-path environment (all required unless noted; the suite skips when any
// required one is unset):
//
//	CFGMS_E2E_CFG_BIN        path to the cfg admin binary (e.g. C:\git\cfgms\bin\cfg-dev.exe)
//	CFGMS_E2E_ADMIN_BUNDLE   admin bundle for mTLS auth (falls back to CFGMS_ADMIN_BUNDLE)
//	CFGMS_E2E_MEMBER_IDS     comma-separated steward IDs of the cluster members
//	CFGMS_E2E_HYPERV_CLUSTER the failover cluster name (shared with Layer 1)
//
// Optional:
//
//	CFGMS_E2E_HAROLE_VM      clustered ha_role VM/role name (default cfgms-e2e-ha-01)
//	CFGMS_E2E_ROLE_TAG       tag whose role config cascades the VM (default e2e-ha-cluster)
const (
	envCfgBin      = "CFGMS_E2E_CFG_BIN"
	envAdminBundle = "CFGMS_E2E_ADMIN_BUNDLE"
	envMemberIDs   = "CFGMS_E2E_MEMBER_IDS"
	envRoleTag     = "CFGMS_E2E_ROLE_TAG"
)

// icEnv is the resolved idiomatic-path environment for one live run.
type icEnv struct {
	ccEnv                // embeds the Layer-1 cluster/VM/node resolution
	cfgBin      string   // cfg admin CLI path
	adminBundle string   // admin bundle path
	memberIDs   []string // steward IDs of the cluster members (cascade targets)
	roleTag     string   // tag whose role config delivers the ha_role VM
}

// icSetup resolves the idiomatic-path environment and skips cleanly when the
// suite cannot run: no cluster, no cfg CLI / bundle, no member IDs, or the host is
// not a member of the named cluster. It reuses ccSetup for the cluster/node facts.
func icSetup(t *testing.T) icEnv {
	t.Helper()

	cfgBin := os.Getenv(envCfgBin)
	if cfgBin == "" {
		t.Skipf("idiomatic fleet-e2e: set %s to the cfg admin CLI path to run", envCfgBin)
	}
	if _, err := os.Stat(cfgBin); err != nil {
		t.Skipf("idiomatic fleet-e2e: %s=%q is not accessible: %v", envCfgBin, cfgBin, err)
	}
	bundle := getenvDefault(envAdminBundle, os.Getenv("CFGMS_ADMIN_BUNDLE"))
	if bundle == "" {
		t.Skipf("idiomatic fleet-e2e: set %s (or CFGMS_ADMIN_BUNDLE) to the admin bundle to run", envAdminBundle)
	}
	rawIDs := os.Getenv(envMemberIDs)
	if strings.TrimSpace(rawIDs) == "" {
		t.Skipf("idiomatic fleet-e2e: set %s to the comma-separated member steward IDs to run", envMemberIDs)
	}
	var memberIDs []string
	for _, id := range strings.Split(rawIDs, ",") {
		if s := strings.TrimSpace(id); s != "" {
			memberIDs = append(memberIDs, s)
		}
	}
	require.GreaterOrEqual(t, len(memberIDs), 2, "idiomatic cascade validation needs at least 2 member steward IDs")

	// Reuse the Layer-1 cluster/node/VM resolution (also skips if the cluster is
	// unset or unreachable, or this host is not a member).
	cc := ccSetup(t)

	ic := icEnv{
		ccEnv:       cc,
		cfgBin:      cfgBin,
		adminBundle: bundle,
		memberIDs:   memberIDs,
		roleTag:     getenvDefault(envRoleTag, "e2e-ha-cluster"),
	}

	// Fail-fast, skip-clean controller reachability probe: the CLI must authenticate
	// and enumerate at least the first member's stored config.
	if _, err := ic.cfg(t, "config", "show", memberIDs[0]); err != nil {
		t.Skipf("idiomatic fleet-e2e: controller not reachable via %s with the admin bundle (%v)", cfgBin, err)
	}
	return ic
}

// cfg runs the cfg admin CLI with the admin bundle and returns trimmed stdout.
// The bundle is passed via the environment (CFGMS_ADMIN_BUNDLE) so it never lands
// in the process argv.
func (ic icEnv) cfg(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ic.cfgBin, args...)
	cmd.Env = append(os.Environ(), "CFGMS_ADMIN_BUNDLE="+ic.adminBundle)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), &icCfgError{args: args, stderr: stderr.String(), err: err}
	}
	return strings.TrimSpace(stdout.String()), nil
}

type icCfgError struct {
	args   []string
	stderr string
	err    error
}

func (e *icCfgError) Error() string {
	return "cfg " + strings.Join(e.args, " ") + " failed: " + e.err.Error() + " | stderr: " + strings.TrimSpace(e.stderr)
}

// effectiveConfig is the subset of a steward's resolved (cascaded) config this
// suite asserts on: the ordered resource list. `cfg config show` emits a JSON
// document whose config.resources is the effective, post-cascade resource set.
type effectiveConfig struct {
	Config struct {
		Resources []struct {
			Name   string                 `json:"name"`
			Module string                 `json:"module"`
			Config map[string]interface{} `json:"config"`
		} `json:"resources"`
	} `json:"config"`
	Version string `json:"version"`
}

// icShow returns a member steward's effective (cascaded) config. The CLI prints a
// human preamble before the JSON body, so we parse from the first '{'.
func (ic icEnv) icShow(t *testing.T, stewardID string) effectiveConfig {
	t.Helper()
	out, err := ic.cfg(t, "config", "show", stewardID)
	require.NoErrorf(t, err, "cfg config show %s", stewardID)
	i := strings.IndexByte(out, '{')
	require.GreaterOrEqualf(t, i, 0, "cfg config show %s produced no JSON body:\n%s", stewardID, out)
	var ec effectiveConfig
	require.NoErrorf(t, json.Unmarshal([]byte(out[i:]), &ec), "parse effective config for %s", stewardID)
	return ec
}

// icResource returns the (module, name) resource from an effective config, or
// ok=false when it is absent — the cascade fan-out / drop oracle.
func icResource(ec effectiveConfig, module, name string) (map[string]interface{}, bool) {
	for _, r := range ec.Config.Resources {
		if r.Module == module && r.Name == name {
			return r.Config, true
		}
	}
	return nil, false
}

// ─── AC1 (idiomatic): cascade appears identically + exactly one CNO create ──────

// TestIdiomaticCascade_IdenticalAcrossMembersSingleCreate (REQUIRED, #2577 AC1) —
// a controller-pushed tenant/cluster config carrying one ha_role VM appears —
// identical — in every member steward's effective config (the InheritanceResolver
// cascade), and exactly one VM exists cluster-wide (the CNO created it). This is
// the idiomatic counterpart to Layer-1 SingleVMCreatedByOwner + NonOwnersConverged,
// driven by the real controller cascade rather than a direct module Set.
//
// Precondition (established by the runbook's cascade-in step, NOT by this test —
// authoring the VM is the thing under test, so the suite never Sets it): the
// ha_role VM's role config is deployed and its tag is on every member. When it is
// not yet cascaded the test skips with a pointer to the runbook, rather than
// creating the VM itself.
func TestIdiomaticCascade_IdenticalAcrossMembersSingleCreate(t *testing.T) {
	ic := icSetup(t)

	// Read every member's effective config and pull out the ha_role VM resource.
	type memberVM struct {
		id    string
		cfg   map[string]interface{}
		hasVM bool
	}
	members := make([]memberVM, 0, len(ic.memberIDs))
	for _, id := range ic.memberIDs {
		ec := ic.icShow(t, id)
		c, ok := icResource(ec, "hyperv.vm", ic.vmName)
		members = append(members, memberVM{id: id, cfg: c, hasVM: ok})
	}

	// If the cascade has not delivered the VM to every member, this is an
	// un-set-up bed, not a failure — skip with the runbook pointer.
	for _, m := range members {
		if !m.hasVM {
			t.Skipf("idiomatic cascade not staged: member %s effective config has no hyperv.vm %q — deploy the role config + tag per the runbook §Layer-2 cascade-in, then re-run", m.id, ic.vmName)
		}
	}

	// (a) The cascaded VM definition is IDENTICAL across all members — same
	// canonical config on every node (the cascade fan-out property).
	want, err := json.Marshal(members[0].cfg)
	require.NoError(t, err)
	for _, m := range members[1:] {
		got, err := json.Marshal(m.cfg)
		require.NoError(t, err)
		assert.JSONEqf(t, string(want), string(got),
			"the cascaded ha_role VM must be identical across members (%s vs %s)", members[0].id, m.id)
	}

	// (b) Exactly one VM cluster-wide, created by the CNO owner — the single-create
	// safety keystone, read cross-node (a duplicate is the failure this epic
	// prevents). Reuses the Layer-1 cross-node instance probe.
	present, distinct, err := ccVMInstances(t, ic.ccEnv)
	require.NoError(t, err, "cross-node Get-VM must succeed on every peer (an unreachable peer could mask a duplicate)")
	assert.Equalf(t, 1, distinct, "exactly one VM must exist cluster-wide from the cascade, no duplicate (present on %v)", present)
	assert.Lenf(t, present, 1, "the single instance lives on exactly one node (present on %v)", present)
}

// ─── AC2 (idiomatic): declarative FC placement reflected in the live cluster ────

// TestIdiomaticPlacement_DeclaredConfigReflectedLive (REQUIRED, #2577 AC2) — the
// declarative placement authored on the hyperv.cluster resource (preferred_owners
// / possible_owners / anti_affinity_class) is reflected in the LIVE cluster. The
// assertion is SOURCE-AGNOSTIC: it reads whatever placement the CNO's effective
// (cascaded) config declares for the role and asserts the live cluster matches it,
// so it validates the idiomatic property (declared cfgms config ⇒ live cluster)
// regardless of whether the operator authored the placement on the cluster-scoped
// device config or a cluster-scoped role config. When no placement is declared yet
// it skips with a runbook pointer rather than asserting a vacuous truth.
func TestIdiomaticPlacement_DeclaredConfigReflectedLive(t *testing.T) {
	ic := icSetup(t)

	// Find the member whose effective config declares placement for the role — the
	// CNO's config carries the hyperv.cluster resource with a roles.<vm> entry.
	var declared map[string]interface{}
	for _, id := range ic.memberIDs {
		ec := ic.icShow(t, id)
		cc, ok := icResource(ec, "hyperv.cluster", ic.cluster)
		if !ok {
			continue
		}
		roles, ok := cc["roles"].(map[string]interface{})
		if !ok {
			continue
		}
		if rp, ok := roles[ic.vmName].(map[string]interface{}); ok && len(rp) > 0 {
			declared = rp
			break
		}
	}
	if declared == nil {
		t.Skipf("no declarative placement for role %q found in any member's effective config — author hyperv.cluster roles.%s.{preferred_owners,possible_owners,anti_affinity_class} per the runbook §Layer-2 placement, then re-run", ic.vmName, ic.vmName)
	}

	// preferred_owners → the group's ordered preferred OwnerNodes.
	if want := icStringList(declared["preferred_owners"]); len(want) > 0 {
		got := ic.groupPreferredOwners(t, ic.vmName)
		assert.Equalf(t, want, got, "live group preferred owners must match the declared preferred_owners")
	}
	// possible_owners → the VM resource's restricted OwnerNodes (order-insensitive:
	// the cluster stores possible owners as a set).
	if want := icStringList(declared["possible_owners"]); len(want) > 0 {
		got := ic.resourcePossibleOwners(t, ic.vmName)
		assert.ElementsMatchf(t, want, got, "live resource possible owners must match the declared possible_owners")
	}
	// anti_affinity_class → the group's AntiAffinityClassNames.
	if want, ok := declared["anti_affinity_class"].(string); ok && want != "" {
		got := ic.groupAntiAffinity(t, ic.vmName)
		assert.Containsf(t, got, want, "live group AntiAffinityClassNames must contain the declared anti_affinity_class")
	}
}

// ─── AC4 (idiomatic): leave drops the definition without destroying the VM ──────

// TestIdiomaticLeave_DropsDefinitionKeepsVM (REQUIRED, #2577 AC4) — removing a
// member from the cascade membership (dropping its role tag) makes the cascaded VM
// definition disappear from THAT member's effective config, while the
// still-clustered VM keeps running on its owner — a dropped cascade definition is
// not a state:absent demote, so no removal is issued. Driven idiomatically through
// the controller (cfg steward tag rm), observed via effective config + cross-node
// Get-VM. The tag is restored on cleanup so the bed returns to full membership.
func TestIdiomaticLeave_DropsDefinitionKeepsVM(t *testing.T) {
	ic := icSetup(t)

	// Pick a member that is NOT the current owner of the role, so the leave never
	// touches the node actually hosting the VM. Owner is read from the live cluster.
	owner := ccGroupOwner(t, ic.cluster, ic.vmName)
	if owner == "" {
		t.Skipf("role %q has no current owner (not cascaded yet?) — run the cascade-in step first", ic.vmName)
	}
	// Map the leaving node to its steward ID: prefer a non-owner member that
	// currently carries the VM in its effective config.
	var leaveID string
	for _, id := range ic.memberIDs {
		ec := ic.icShow(t, id)
		if _, ok := icResource(ec, "hyperv.vm", ic.vmName); !ok {
			continue
		}
		hn := ic.stewardHostname(t, id)
		if hn != "" && !strings.EqualFold(hn, owner) {
			leaveID = id
			break
		}
	}
	if leaveID == "" {
		t.Skipf("no non-owner member currently carries the cascaded VM %q — cascade it to all members per the runbook, then re-run", ic.vmName)
	}

	// Baseline: exactly one VM cluster-wide before the leave.
	presBefore, distinctBefore, err := ccVMInstances(t, ic.ccEnv)
	require.NoError(t, err)
	require.Equalf(t, 1, distinctBefore, "precondition: exactly one VM before the leave (present on %v)", presBefore)

	// Drive the idiomatic leave: drop the role tag from the leaving member. Restore
	// it on cleanup regardless of outcome so the bed returns to full membership.
	_, err = ic.cfg(t, "steward", "tag", "rm", leaveID, ic.roleTag)
	require.NoErrorf(t, err, "cfg steward tag rm %s %s", leaveID, ic.roleTag)
	t.Cleanup(func() { _, _ = ic.cfg(t, "steward", "tag", "add", leaveID, ic.roleTag) })

	// (a) The cascaded VM definition disappears from the leaving member's effective
	// config (re-resolved without the matching role config).
	dropped := false
	deadline := time.Now().Add(ccSettleTimeout)
	for time.Now().Before(deadline) {
		ec := ic.icShow(t, leaveID)
		if _, ok := icResource(ec, "hyperv.vm", ic.vmName); !ok {
			dropped = true
			break
		}
		time.Sleep(ccPollInterval)
	}
	assert.Truef(t, dropped, "the cascaded VM definition must drop from the leaving member (%s) effective config after the tag is removed", leaveID)

	// (b) The still-clustered VM is NOT deleted: same single instance cluster-wide,
	// still owned by the same node. A dropped definition is not a demotion.
	presAfter, distinctAfter, err := ccVMInstances(t, ic.ccEnv)
	require.NoError(t, err)
	assert.Equalf(t, 1, distinctAfter, "the still-clustered VM must survive the leave — exactly one instance, no deletion (present on %v)", presAfter)
	assert.Lenf(t, presAfter, 1, "the VM keeps running on its single owner after the leave (present on %v)", presAfter)
	assert.True(t, ccRolePresent(t, ic.cluster, ic.vmName),
		"the clustered role must still exist after a member leaves the cascade")
}

// ─── live-cluster read helpers (read-only; author nothing) ──────────────────────

// groupPreferredOwners returns the ordered preferred OwnerNodes of the role group
// (Get-ClusterOwnerNode -Group) — the reflection of preferred_owners.
func (ic icEnv) groupPreferredOwners(t *testing.T, role string) []string {
	t.Helper()
	out := ccPSFatal(t, `((Get-ClusterOwnerNode -Cluster '`+ic.cluster+`' -Group '`+role+`').OwnerNodes | ForEach-Object { $_.Name }) -join "`+"`n"+`"`)
	return icLines(out)
}

// resourcePossibleOwners returns the restricted OwnerNodes of the role's Virtual
// Machine resource (Get-ClusterOwnerNode -Resource) — the reflection of
// possible_owners. The VM resource is matched via [string] coercion because
// Get-ClusterResource returns .OwnerGroup / .ResourceType as strings on some
// FailoverClusters builds (the #2577 possible_owners fix).
func (ic icEnv) resourcePossibleOwners(t *testing.T, role string) []string {
	t.Helper()
	script := `$res = @(Get-ClusterResource -Cluster '` + ic.cluster + `' | Where-Object { [string]$_.OwnerGroup -eq '` + role + `' -and [string]$_.ResourceType -eq 'Virtual Machine' }); if ($res.Count -eq 0) { '' } else { ((Get-ClusterOwnerNode -Cluster '` + ic.cluster + `' -Resource $res[0].Name).OwnerNodes | ForEach-Object { $_.Name }) -join "` + "`n" + `" }`
	return icLines(ccPSFatal(t, script))
}

// groupAntiAffinity returns the group's AntiAffinityClassNames — the reflection of
// anti_affinity_class.
func (ic icEnv) groupAntiAffinity(t *testing.T, role string) []string {
	t.Helper()
	out := ccPSFatal(t, `((Get-ClusterGroup -Cluster '`+ic.cluster+`' -Name '`+role+`').AntiAffinityClassNames) -join "`+"`n"+`"`)
	return icLines(out)
}

// stewardHostname returns the reported hostname of a steward from `cfg steward
// list`, or "" when unknown. Used to map a member steward ID to its cluster node.
func (ic icEnv) stewardHostname(t *testing.T, stewardID string) string {
	t.Helper()
	out, err := ic.cfg(t, "steward", "list")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, stewardID) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return fields[len(fields)-1] // HOSTNAME is the last column
			}
		}
	}
	return ""
}

// icStringList coerces a JSON-decoded config value (a []interface{} of strings) to
// []string. Returns nil for anything else.
func icStringList(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// icLines splits newline-joined PowerShell output into trimmed, non-empty lines.
func icLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
