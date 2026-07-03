// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration && windows

// Cluster HA lab e2e validation (SC6 of epic #2198). These tests run against the
// live cfg-lab 3-node S2D failover cluster: they cluster a VM as an HA role via
// the module, force a node failover out-of-band, and assert the module's cluster
// DNA Monitor emits a ChangeEvent carrying the updated resource_owner — the
// controller-side reconvergence signal (epic #415). They also cover the S1
// drift-not-adopted invariant and the S6 destructive gate against real cluster
// state.
//
// Build-tagged `integration && windows`: excluded from `make test-complete`
// (Linux CI cannot host Failover Clustering) and from the cross-platform unit
// build. Run on a cfg-lab node, from an elevated (cluster-admin) shell — the
// module's persistent PS host and the test's own out-of-band helpers both run at
// the test process's privilege, so cluster cmdlets need elevation:
//
//	$env:CFGMS_HYPERV_CLUSTER = 'lab-hv'
//	go test -tags="integration windows" -run TestClusterHA ./features/modules/hyperv/...
//
// Every test skips when CFGMS_HYPERV_CLUSTER is unset, and the failover test
// skips on a single-node cluster (nothing to fail over to). Each test removes the
// VMs and clustered roles it creates via t.Cleanup so a failure leaves the lab
// recoverable.
//
// Transport split — why the test does NOT drive its out-of-band lab setup through
// the module transport: the live ps-host transport (psHostTransport.ExecutePS) is
// a CLOSED dispatch table that only recognises the module's own psXxx verb
// consts; an arbitrary script returns "unknown psCommand". So the module's cluster
// operations (Set/Get/Monitor → Cfgms-GetCluster / -AddClusterVMRole /
// -RemoveClusterResource …) flow through m.transport, while the test's own setup
// and failover-trigger PowerShell (create VM, Move-ClusterGroup, cleanup) runs in
// a separate, directly-spawned powershell.exe via runTestPS. Names travel as
// process-environment variables, never composed into the script text.
package hyperv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// clusterPollInterval is the DNA poll cadence the tests configure. Short enough
// that a forced failover is observed and confirmed (the S8 two-poll dwell) well
// within the 90s wait, long enough not to hammer the cluster.
const clusterPollInterval = "3s"

// clusterHAParams holds the cfg-lab topology the tests need, sourced from env.
type clusterHAParams struct {
	cluster string // CFGMS_HYPERV_CLUSTER — the failover cluster (CNO) name
	csvPath string // CFGMS_HYPERV_CSV_PATH — CSV dir for failover-capable VM config
	seedDir string // CFGMS_HYPERV_SEED_DIR — host-local (non-CSV) provisioning seed dir
}

// requireClusterEnv reads the cfg-lab topology from the environment, skipping the
// test when the cluster is not configured (the integration_test.go guard shape).
func requireClusterEnv(t *testing.T) clusterHAParams {
	t.Helper()
	cluster := os.Getenv("CFGMS_HYPERV_CLUSTER")
	if cluster == "" {
		t.Skip("CFGMS_HYPERV_CLUSTER not set — cfg-lab failover cluster required for HA integration tests")
	}
	return clusterHAParams{
		cluster: cluster,
		csvPath: envOr("CFGMS_HYPERV_CSV_PATH", `C:\ClusterStorage\CSV01`),
		seedDir: envOr("CFGMS_HYPERV_SEED_DIR", `C:\cfgms-seeds`),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- test-local PowerShell helpers (NOT production code) -----------------------
//
// These drive the lab out-of-band (the module's own code path is the thing under
// test). Every cluster / node / VM / group name is read from a CFGMS_T_*
// process-environment variable that runTestPS sets — never composed into the
// script text — so the helpers carry no injectable surface even though the names
// are test-controlled constants/env values.

// psTestEnsureCNOOwner moves the core "Cluster Group" (CNO) to $env:CFGMS_T_NODE.
// The module mutates only on the CNO-owner node (the coordination gate), so the
// test pins ownership to the local node to exercise the owner path deterministically.
const psTestEnsureCNOOwner = `Move-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name 'Cluster Group' -Node $env:CFGMS_T_NODE -ErrorAction Stop | Out-Null; 'ok'`

// psTestCreateClusteredCapableVM creates a minimal Gen2 VM whose configuration
// lives on the CSV ($env:CFGMS_T_CSV) so the role can fail over between nodes. No
// VHD and it stays Off — failover transfers group ownership, which needs no
// running guest.
const psTestCreateClusteredCapableVM = `if (-not (Get-VM -Name $env:CFGMS_T_VM -ErrorAction SilentlyContinue)) { New-VM -Name $env:CFGMS_T_VM -MemoryStartupBytes 512MB -Generation 2 -NoVHD -Path $env:CFGMS_T_CSV -ErrorAction Stop | Out-Null }; 'ok'`

// psTestCreateClusteredRole creates a VM and clusters it as an HA role WITHOUT
// going through the module — used to stand up the declared role (so a present-Set
// is a clean no-op) and the undeclared "drift" role the module must never adopt.
const psTestCreateClusteredRole = `if (-not (Get-VM -Name $env:CFGMS_T_VM -ErrorAction SilentlyContinue)) { New-VM -Name $env:CFGMS_T_VM -MemoryStartupBytes 512MB -Generation 2 -NoVHD -Path $env:CFGMS_T_CSV -ErrorAction Stop | Out-Null }; if (-not (Get-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name $env:CFGMS_T_VM -ErrorAction SilentlyContinue)) { Add-ClusterVirtualMachineRole -Cluster $env:CFGMS_T_CLUSTER -VMId (Get-VM -Name $env:CFGMS_T_VM).Id -ErrorAction Stop | Out-Null }; 'ok'`

// cfgmsMoveClusterGroup forces an out-of-band failover of the clustered role
// group $env:CFGMS_T_GROUP to $env:CFGMS_T_NODE — the test's failover trigger.
const cfgmsMoveClusterGroup = `Move-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name $env:CFGMS_T_GROUP -Node $env:CFGMS_T_NODE -ErrorAction Stop | Out-Null; 'ok'`

// psTestOtherUpNode returns the name of an Up cluster node other than
// $env:CFGMS_T_NODE, or empty when no such node exists (single-node cluster).
const psTestOtherUpNode = `$n = @(Get-ClusterNode -Cluster $env:CFGMS_T_CLUSTER | Where-Object { $_.State -eq 'Up' -and $_.Name -ne $env:CFGMS_T_NODE }); if ($n.Count -gt 0) { $n[0].Name }`

// psTestRemoveClusteredVM tears the clustered role group down (if present) and
// removes the VM, leaving the lab recoverable after the test. Best-effort:
// SilentlyContinue throughout so cleanup never fails a passing test.
const psTestRemoveClusteredVM = `$g = Get-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name $env:CFGMS_T_VM -ErrorAction SilentlyContinue; if ($g) { Remove-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name $env:CFGMS_T_VM -RemoveResources -Force -ErrorAction SilentlyContinue }; $vm = Get-VM -Name $env:CFGMS_T_VM -ErrorAction SilentlyContinue; if ($vm) { Stop-VM -Name $env:CFGMS_T_VM -Force -ErrorAction SilentlyContinue; Remove-VM -Name $env:CFGMS_T_VM -Force -ErrorAction SilentlyContinue }; 'ok'`

// psTestReadGroupPriority reads the clustered role group's Priority (#2306 PROP-B).
const psTestReadGroupPriority = `(Get-ClusterGroup -Cluster $env:CFGMS_T_CLUSTER -Name $env:CFGMS_T_VM -ErrorAction Stop).Priority`

// psTestReadPreferredOwners reads the role group's ordered preferred owner nodes,
// comma-joined (#2306 PROP-B).
const psTestReadPreferredOwners = `(Get-ClusterOwnerNode -Cluster $env:CFGMS_T_CLUSTER -Group $env:CFGMS_T_VM -ErrorAction Stop).OwnerNodes.Name -join ','`

// runTestPS executes a test-local PS helper in a freshly-spawned powershell.exe
// (NOT the module's closed-dispatch ps-host transport, which would reject an
// arbitrary script with "unknown psCommand"). Names are passed via CFGMS_T_*
// process-environment variables, never interpolated into the script text. Fails
// the test on a non-zero exit (these are setup/teardown helpers, not assertions).
func runTestPS(t *testing.T, script string, env map[string]string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("test PS helper failed: %v\nscript: %s\nstderr: %s", err, script, stderr)
	}
	return strings.TrimSpace(string(out))
}

// getClusterStatus reads Get("cluster:<name>") through the module and asserts the
// live shape.
func getClusterStatus(t *testing.T, m *hypervModule, cluster string) *ClusterStatus {
	t.Helper()
	cs, err := m.Get(context.Background(), "cluster:"+cluster)
	require.NoError(t, err, "Get cluster status")
	status, ok := cs.(*ClusterStatus)
	require.True(t, ok, "Get must return a *ClusterStatus")
	require.True(t, status.Found, "cluster %q must be present on the host", cluster)
	return status
}

// assertReceiptTimestamps proves S8: every recorded audit event carries a
// non-zero receipt-time Timestamp inside the test's wall-clock window (±5s). A
// PS-reported or stale time would fall outside the window.
func assertReceiptTimestamps(t *testing.T, entries []*business.AuditEntry, start, end time.Time) {
	t.Helper()
	lo := start.Add(-5 * time.Second)
	hi := end.Add(5 * time.Second)
	require.NotEmpty(t, entries, "module operations must record audit events")
	for _, e := range entries {
		require.Falsef(t, e.Timestamp.IsZero(),
			"audit entry %q has a zero Timestamp — must be Go receipt-time (S8)", e.Action)
		assert.Falsef(t, e.Timestamp.Before(lo) || e.Timestamp.After(hi),
			"audit entry %q Timestamp %s outside the test window [%s, %s] — not receipt-time (S8)",
			e.Action, e.Timestamp, lo, hi)
	}
}

// newClusterHAModule builds a hypervModule wired for the live cfg-lab cluster: the
// persistent PS-host transport, the cluster scope cap (cluster_name +
// cluster_role_names), a non-CSV seed dir, a fast DNA poll cadence, and a fake
// audit manager whose entries the S8 receipt-time checks inspect.
func newClusterHAModule(t *testing.T, p clusterHAParams, roleNames []string) (*hypervModule, *fakeAuditStore) {
	t.Helper()
	store := newInlineStore() // ps-host transport needs no credentials
	m := newModuleWithDetector(store, &fakeDetector{result: true})
	auditMgr, auditStore := newFakeAuditManager(t)
	require.NoError(t, m.Configure(mapConfigState{
		"transport":             "ps-host",
		"tenant_id":             "lab",
		"audit_manager":         auditMgr,
		"cluster_name":          p.cluster,
		"cluster_role_names":    roleNames,
		"seed_dir":              p.seedDir,
		"cluster_poll_interval": clusterPollInterval,
	}))
	t.Cleanup(func() { _ = m.auditMgr.Stop(context.Background()) })
	// On a real Hyper-V host the ps-host transport must have been selected; a WinRM
	// fallback (which Configure takes only when powershell.exe is missing) would
	// not exercise the live host path this story validates.
	require.IsType(t, &psHostTransport{}, m.transport,
		"HA integration test requires the live ps-host transport")
	return m, auditStore
}

// TestClusterHA_CreateFailoverReconverge is the headline SC6 [REQUIRED TEST]: on
// cfg-lab the module clusters a VM as an HA role exactly once, a forced failover
// triggers a DNA ChangeEvent with an updated resource_owner, a second converge is
// an idempotent no-op, and the destructive cleanup removes the role.
func TestClusterHA_CreateFailoverReconverge(t *testing.T) {
	p := requireClusterEnv(t)
	const role = "cfgms-ha-runner-test"

	testStart := time.Now()
	m, auditStore := newClusterHAModule(t, p, []string{role})
	ctx := context.Background()

	// Recoverable cleanup regardless of where a failure lands.
	t.Cleanup(func() {
		_ = m.Close()
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role})
	})

	local := m.nodeHostname
	require.NotEmpty(t, local, "local node hostname must be known")

	// A failover needs a second Up node to move to.
	if runTestPS(t, psTestOtherUpNode, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": local}) == "" {
		t.Skip("single-node cluster (no other Up node) — nothing to fail over to")
	}

	// Pin CNO ownership to the local node so the module's owner-gated mutation runs
	// here, then create the failover-capable VM on the CSV.
	runTestPS(t, psTestEnsureCNOOwner, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": local})
	runTestPS(t, psTestCreateClusteredCapableVM, map[string]string{"CFGMS_T_VM": role, "CFGMS_T_CSV": p.csvPath})

	// --- Cluster the role via the module (create path, S2). -------------------
	createStart := time.Now()
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "present"}),
		"clustering the VM role must succeed on the CNO-owner node")
	createEnd := time.Now()

	// Get must now show a non-empty owner for the role.
	status := getClusterStatus(t, m, p.cluster)
	origOwner := status.RoleOwners[role]
	require.NotEmptyf(t, origOwner, "resource_owner[%s] must be non-empty after clustering", role)
	require.NotEmpty(t, status.CNOOwnerNode, "CNOOwnerNode must be non-empty after clustering the role")

	// The create must have recorded exactly one successful cluster-set-create.
	require.NoError(t, m.auditMgr.Flush(ctx))
	creates := auditEntriesByAction(auditStore.captured(), "cluster-set-create")
	require.Len(t, creates, 1, "the role must be clustered exactly once")
	assert.Equal(t, business.AuditResultSuccess, creates[0].Result, "create must succeed")
	// Tight S8 window around the create operation.
	assertReceiptTimestamps(t, creates, createStart, createEnd)

	// --- Register the DNA Monitor and let it establish its baseline. ----------
	require.NoError(t, m.Monitor(ctx, "cluster:"+p.cluster, nil))
	changes := m.Changes()
	// Let the poller take its baseline poll (no emit on the first poll) BEFORE the
	// failover, so the ownership change is detected as a change against it.
	time.Sleep(2 * pollDuration(t))

	// --- Force the failover out-of-band, to a node other than the current owner.
	target := runTestPS(t, psTestOtherUpNode, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": origOwner})
	require.NotEmptyf(t, target, "must have an Up node other than the current owner %q to fail over to", origOwner)
	runTestPS(t, cfgmsMoveClusterGroup, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_GROUP": role, "CFGMS_T_NODE": target})

	// --- Wait <=90s for a DNA ChangeEvent reflecting the new owner. -----------
	newOwner := waitForOwnerChange(t, changes, "cluster:"+p.cluster, role, origOwner, 90*time.Second)
	assert.Truef(t, strings.EqualFold(newOwner, target),
		"the DNA resource_owner must reflect the failover target (moved to %q, DNA reports %q)", target, newOwner)

	// --- Re-converge: a second Set is an idempotent no-op (no new create). -----
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "present"}),
		"a re-converge of an already-clustered role must not error")
	require.NoError(t, m.auditMgr.Flush(ctx))
	require.Len(t, auditEntriesByAction(auditStore.captured(), "cluster-set-create"), 1,
		"the second converge must not create the role again (idempotent)")
	assert.NotEmpty(t, auditEntriesByAction(auditStore.captured(), "cluster-set-noop"),
		"the second converge must record an idempotent no-op")

	// --- Destructive cleanup via the module: state absent + allow_destructive. -
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "absent", AllowDestructive: true}),
		"destructive removal must succeed with allow_destructive: true")
	after := getClusterStatus(t, m, p.cluster)
	assert.Emptyf(t, after.RoleOwners[role], "Get must show role %q absent after destructive removal", role)

	// --- S8: every audit event across the whole test is receipt-time. ---------
	require.NoError(t, m.auditMgr.Flush(ctx))
	assertReceiptTimestamps(t, auditStore.captured(), testStart, time.Now())
}

// TestClusterHA_GetRead is the read-surface [REQUIRED TEST] (#2306 V2): it
// asserts every ClusterStatus field returned by getCluster against live cfg-lab
// state, and that the DNA Monitor emits no ChangeEvent on a quiescent cluster.
func TestClusterHA_GetRead(t *testing.T) {
	p := requireClusterEnv(t)
	m, _ := newClusterHAModule(t, p, nil) // no role scope — read the whole cluster
	t.Cleanup(func() { _ = m.Close() })
	ctx := context.Background()

	// getClusterStatus already require's Found==true; assert the rest of the shape.
	status := getClusterStatus(t, m, p.cluster)
	assert.Equal(t, p.cluster, status.Name, "cluster name must match the declared cluster")
	assert.NotEmpty(t, status.CNOOwnerNode, "the CNO group must have an owner on a healthy cluster")
	assert.GreaterOrEqual(t, len(status.MemberNodes), 1, "cluster must report at least one member node")
	assert.GreaterOrEqual(t, len(status.CSVPaths), 1, "cluster must report at least one CSV path (CSV01)")

	// DNA Monitor: a quiescent cluster must not emit a ChangeEvent. Register the
	// Monitor, let it take its baseline poll (no emit on the first poll), and
	// confirm nothing fires over two poll intervals.
	require.NoError(t, m.Monitor(ctx, "cluster:"+p.cluster, nil))
	changes := m.Changes()
	time.Sleep(2 * pollDuration(t))
	select {
	case ev := <-changes:
		t.Errorf("DNA Monitor emitted an unexpected ChangeEvent on a quiescent cluster: %+v", ev)
	default:
	}
}

// TestClusterHA_CNOGatingNonOwner is the [REQUIRED TEST] (#2306 V3): a Set on a
// node that does NOT own the CNO records exactly one cluster-set-skip, issues zero
// write cmdlets, and leaves the VM unclustered — the coordination gate that gives
// exactly-once execution when the same cluster config reaches every node's steward.
//
// The module reads CNO ownership; it never moves the CNO (the cluster owns that),
// so neither does this test. It runs the non-owner assertion only when the local
// node is NATURALLY a non-owner, and skips on the CNO-owner node (that is the
// owner path, proven by TestClusterHA_CreateFailoverReconverge). The non-owner Go
// gate is additionally unit-covered (TestClusterSet_NonOwner*, clusterOwnership).
func TestClusterHA_CNOGatingNonOwner(t *testing.T) {
	p := requireClusterEnv(t)
	const role = "cfgms-ha-gating-test"

	m, auditStore := newClusterHAModule(t, p, []string{role})
	ctx := context.Background()
	local := m.nodeHostname

	// Only assert the non-owner path when this node is naturally a non-owner — no
	// CNO manipulation. On the owner node (or when ownership can't be determined),
	// there is nothing for this test to assert.
	status := getClusterStatus(t, m, p.cluster)
	if local == "" || strings.EqualFold(status.CNOOwnerNode, local) {
		t.Skipf("local node %q owns the CNO (owner=%q) — the non-owner skip is asserted only from a non-owner node",
			local, status.CNOOwnerNode)
	}

	t.Cleanup(func() {
		_ = m.Close()
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role})
	})

	// Create an unclustered VM on the CSV; the local node is already a non-owner.
	runTestPS(t, psTestCreateClusteredCapableVM, map[string]string{"CFGMS_T_VM": role, "CFGMS_T_CSV": p.csvPath})

	// Non-owner Set: coordination, not authorization — must return nil, mutate nothing.
	err := m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "present"})
	require.NoError(t, err, "non-owner Set must return nil — ownership is coordination, never an error")

	require.NoError(t, m.auditMgr.Flush(ctx))
	require.Len(t, auditEntriesByAction(auditStore.captured(), "cluster-set-skip"), 1,
		"a non-owner must record exactly one cluster-set-skip")
	require.Empty(t, auditEntriesByAction(auditStore.captured(), "cluster-set-create"),
		"a non-owner must issue no Add-ClusterVirtualMachineRole")

	status = getClusterStatus(t, m, p.cluster)
	assert.Emptyf(t, status.RoleOwners[role],
		"the VM must NOT be clustered after a non-owner Set — role %q", role)
}

// TestClusterHA_DriftNotAdopted is the S1 [REQUIRED TEST]: an out-of-band
// clustered role absent from the declared cluster_role_names is observed by Get
// (so it can be flagged as drift) but is NEVER mutated by Set.
func TestClusterHA_DriftNotAdopted(t *testing.T) {
	p := requireClusterEnv(t)
	const declared = "cfgms-ha-runner-test"
	const drift = "cfgms-ha-runner-DRIFT"

	m, auditStore := newClusterHAModule(t, p, []string{declared})
	ctx := context.Background()

	t.Cleanup(func() {
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": declared})
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": drift})
	})

	// The module's declared scope must exclude the drift role (test premise).
	require.NotContains(t, m.clusterRoleNames, drift, "drift role must be undeclared in the module scope")

	local := m.nodeHostname
	runTestPS(t, psTestEnsureCNOOwner, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": local})
	// Declared role exists (so the present-Set is a clean no-op); drift role exists
	// out-of-band (undeclared).
	runTestPS(t, psTestCreateClusteredRole, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": declared, "CFGMS_T_CSV": p.csvPath})
	runTestPS(t, psTestCreateClusteredRole, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": drift, "CFGMS_T_CSV": p.csvPath})

	// Get observes BOTH roles; the drift role is observed-but-not-declared.
	status := getClusterStatus(t, m, p.cluster)
	_, driftObserved := status.RoleOwners[drift]
	require.True(t, driftObserved, "Get must observe the out-of-band drift role (so it can be flagged as drift)")

	// Converge: Set with the DECLARED config only.
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{declared}, State: "present"}))
	require.NoError(t, m.auditMgr.Flush(ctx))

	// No audit event may reference the drift role anywhere (Action or payload) —
	// Set never touched it.
	for _, e := range auditStore.captured() {
		assert.NotContains(t, e.Action, drift, "no audit Action may reference the undeclared drift role")
		assertNoString(t, e, drift, "drift role name")
	}

	// And the drift role is still present, unchanged — never removed or adopted.
	afterStatus := getClusterStatus(t, m, p.cluster)
	_, stillThere := afterStatus.RoleOwners[drift]
	assert.True(t, stillThere, "Set must leave the undeclared drift role in place (drift-not-adopted, S1)")
}

// TestClusterHA_DestructiveGate is the S6 [REQUIRED TEST]: state absent with
// allow_destructive: false returns ErrDestructiveOpBlocked and the role persists
// — no PS write cmdlet runs.
func TestClusterHA_DestructiveGate(t *testing.T) {
	p := requireClusterEnv(t)
	const role = "cfgms-ha-runner-test"

	m, _ := newClusterHAModule(t, p, []string{role})
	ctx := context.Background()

	t.Cleanup(func() {
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role})
	})

	local := m.nodeHostname
	runTestPS(t, psTestEnsureCNOOwner, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": local})
	runTestPS(t, psTestCreateClusteredRole, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role, "CFGMS_T_CSV": p.csvPath})

	// Sanity: the role is clustered before the gated removal attempt.
	require.NotEmpty(t, getClusterStatus(t, m, p.cluster).RoleOwners[role],
		"role must be clustered before the destructive-gate check")

	// Destructive op WITHOUT the opt-in must be blocked.
	err := m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "absent", AllowDestructive: false})
	require.Error(t, err, "destructive removal without allow_destructive must error")
	assert.ErrorIs(t, err, ErrDestructiveOpBlocked, "the error must be the destructive-gate sentinel")

	// The role must still exist — the gate runs before any PS write cmdlet.
	assert.NotEmptyf(t, getClusterStatus(t, m, p.cluster).RoleOwners[role],
		"role %q must persist after a blocked destructive op", role)

	// True path (#2306 V4): allow_destructive:true must remove the clustered VM
	// role group (Remove-ClusterGroup -RemoveResources). The VM itself persists —
	// only the cluster group/resources are removed — so t.Cleanup still finds it.
	err = m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "absent", AllowDestructive: true})
	require.NoError(t, err, "destructive removal with allow_destructive:true must succeed")

	afterRemove := getClusterStatus(t, m, p.cluster)
	assert.Emptyf(t, afterRemove.RoleOwners[role],
		"role %q must be absent from RoleOwners after allow_destructive:true removal", role)

	// Re-add the role (present-Set) so the VM is a clustered role again before
	// t.Cleanup tears it down — proves the create path works post-removal.
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster,
		&ClusterConfig{Name: p.cluster, RoleNames: []string{role}, State: "present"}),
		"re-add after true-path removal must succeed")
	assert.NotEmptyf(t, getClusterStatus(t, m, p.cluster).RoleOwners[role],
		"role %q must reappear in RoleOwners after re-add", role)
}

// TestClusterHA_RoleProperties is the [REQUIRED TEST] (#2306 PROPERTIES-B): on the
// CNO-owner node, a Set that declares role properties (preferred_owners + priority)
// reconciles them onto the live clustered group, verified by reading the group back.
func TestClusterHA_RoleProperties(t *testing.T) {
	p := requireClusterEnv(t)
	const role = "cfgms-ha-props-test"

	m, _ := newClusterHAModule(t, p, []string{role})
	ctx := context.Background()

	t.Cleanup(func() {
		runTestPS(t, psTestRemoveClusteredVM, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role})
	})

	local := m.nodeHostname
	runTestPS(t, psTestEnsureCNOOwner, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_NODE": local})
	runTestPS(t, psTestCreateClusteredCapableVM, map[string]string{"CFGMS_T_VM": role, "CFGMS_T_CSV": p.csvPath})

	// Cluster the VM AND reconcile properties in a single owner-node Set.
	require.NoError(t, m.Set(ctx, "cluster:"+p.cluster, &ClusterConfig{
		Name:      p.cluster,
		RoleNames: []string{role},
		State:     "present",
		Roles: map[string]ClusterRoleProperties{
			role: {PreferredOwners: []string{local}, Priority: intPtr(2000)},
		},
	}), "clustering + property reconcile must succeed on the CNO owner")

	// Read the live group back and assert the declared properties applied.
	prio := strings.TrimSpace(runTestPS(t, psTestReadGroupPriority, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role}))
	assert.Equal(t, "2000", prio, "the cluster group Priority must reflect the declared value")
	owners := runTestPS(t, psTestReadPreferredOwners, map[string]string{"CFGMS_T_CLUSTER": p.cluster, "CFGMS_T_VM": role})
	assert.Containsf(t, owners, local, "preferred owners %q must include the declared node %q", owners, local)
}

// TestClusterHA_AccessReconcileNoOp validates the cluster-access lifecycle reconcile
// live (#2306 option 3) without mutating the ACL: reconciling against the CURRENT
// member set on a fully-onboarded cluster must be a no-op — zero grants, zero
// revokes — exercising the live ACL read + compute path.
func TestClusterHA_AccessReconcileNoOp(t *testing.T) {
	p := requireClusterEnv(t)
	m, _ := newClusterHAModule(t, p, nil)
	t.Cleanup(func() { _ = m.Close() })
	ctx := context.Background()

	status := getClusterStatus(t, m, p.cluster)
	require.NotEmpty(t, status.MemberNodes, "cluster must report members")

	res, err := m.ReconcileClusterAccess(ctx, p.cluster, status.MemberNodes)
	require.NoError(t, err)
	assert.Emptyf(t, res.Granted, "a fully-onboarded cluster needs no grants, got %v", res.Granted)
	assert.Emptyf(t, res.Revoked, "reconciling against the current member set revokes nothing, got %v", res.Revoked)
}

// auditEntriesByAction returns the captured entries whose Action matches, in order.
func auditEntriesByAction(entries []*business.AuditEntry, action string) []*business.AuditEntry {
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// pollDuration parses the configured DNA poll cadence for sleep budgeting.
func pollDuration(t *testing.T) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(clusterPollInterval)
	require.NoError(t, err)
	return d
}

// waitForOwnerChange drains the Changes() channel until a cluster ChangeEvent
// reports resource_owner[role] differing from origOwner, or fails after timeout.
// Returns the new owner.
func waitForOwnerChange(t *testing.T, changes <-chan modules.ChangeEvent, resourceID, role, origOwner string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-changes:
			if !ok {
				t.Fatal("Changes channel closed before a failover event arrived")
			}
			if ev.ResourceID != resourceID || ev.Details == nil {
				continue
			}
			assert.Equal(t, modules.ChangeTypeModified, ev.ChangeType, "failover must be a Modified event")
			assert.NotZero(t, ev.Timestamp, "ChangeEvent must carry a receipt-time timestamp (S8)")
			owners, ok := ev.Details.AsMap()["resource_owner"].(map[string]string)
			if !ok {
				continue
			}
			newOwner := owners[role]
			if newOwner != "" && !strings.EqualFold(newOwner, origOwner) {
				return newOwner
			}
		case <-deadline:
			t.Fatalf("no failover ChangeEvent with a changed resource_owner[%s] within %s", role, timeout)
			return ""
		}
	}
}
