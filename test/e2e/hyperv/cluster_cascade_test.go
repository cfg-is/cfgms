// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of the cluster.cfg cascade + owner-gated hyperv.vm
// convergence epic (#2418, stories #2420–#2425) against the real cfg-lab 3-node
// failover cluster.
//
// These tests exercise the LIVE cluster: they drive the real hyperv module
// (ps-host transport) as the node they physically run on, and observe/steer the
// cluster with direct PowerShell (Get-ClusterGroup / Get-VM / Move-ClusterGroup)
// — exactly the surface an operator drives from the runbook. Ownership is the
// pivot of every safety property in the epic, and a module instance's node
// identity is os.Hostname() (module.go:298), so a test faithfully represents
// only the node it runs on. Rather than depend on which node happens to own the
// CNO when the suite starts, each test STEERS ownership deterministically with
// Move-ClusterGroup so the local node plays the role under test (owner /
// non-owner / previous-owner / new-owner). The full simultaneous 3-node picture
// is driven by the runbook (docs/testing/hyperv-cluster-cascade-runbook.md),
// which runs this same suite on all three nodes at once.
//
// The suite is excluded from CI and `make test-complete` by the e2e build tag,
// and skips cleanly when CFGMS_E2E_HYPERV_CLUSTER is unset or the host is not a
// Hyper-V cluster node.
package hyperv_e2e

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Required environment variable (the suite skips when unset):
//
//	CFGMS_E2E_HYPERV_CLUSTER   the failover cluster name (e.g. "cfg-lab")
//
// Optional:
//
//	CFGMS_E2E_HAROLE_VM        clustered ha_role VM/role name (default cfgms-e2e-ha-01)
//	CFGMS_E2E_VHD_DIR          CSV directory for the VM VHD (default C:\ClusterStorage\CSV01)
//	CFGMS_E2E_SEED_DIR         host-LOCAL seed dir (default C:\cfgms\e2e-seed); must NOT be on CSV
//	CFGMS_E2E_SWITCH           virtual switch to connect (default HVSwitch_1G)
const (
	envCluster = "CFGMS_E2E_HYPERV_CLUSTER"
	envHAVM    = "CFGMS_E2E_HAROLE_VM"
	envSeedDir = "CFGMS_E2E_SEED_DIR"

	// ccPollInterval / ccSettleTimeout bound the cluster-state polling loops
	// (owner settle after a Move-ClusterGroup, convergence-loop cadence).
	ccPollInterval  = 3 * time.Second
	ccSettleTimeout = 90 * time.Second

	// ccCNOGroup is the core cluster group whose owner IS the CNO-owner node the
	// #2421 gate consults (readCNOOwner → Get-ClusterGroup "Cluster Group").
	ccCNOGroup = "Cluster Group"
)

// ─── in-memory audit store (external-package twin of the internal fakeAuditStore) ──
//
// A real business.AuditStore backing a real audit.Manager, so the module's
// recordHypervOp emissions (the owner-gate skips this suite asserts on) are
// captured and replayable. Not a mock — an in-memory store.
type ccAuditStore struct {
	mu      sync.Mutex
	entries []*business.AuditEntry
}

func (s *ccAuditStore) StoreAuditEntry(_ context.Context, e *business.AuditEntry) error {
	s.mu.Lock()
	s.entries = append(s.entries, e)
	s.mu.Unlock()
	return nil
}

func (s *ccAuditStore) StoreAuditBatch(_ context.Context, es []*business.AuditEntry) error {
	s.mu.Lock()
	s.entries = append(s.entries, es...)
	s.mu.Unlock()
	return nil
}

func (s *ccAuditStore) GetAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) ListAuditEntries(_ context.Context, _ *business.AuditFilter) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetAuditsByUser(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetAuditsByResource(_ context.Context, _, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetAuditsByAction(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetFailedActions(_ context.Context, _ *business.TimeRange, _ int) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetSuspiciousActivity(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) GetAuditStats(_ context.Context) (*business.AuditStats, error) {
	return &business.AuditStats{LastUpdated: time.Now()}, nil
}
func (s *ccAuditStore) GetLastAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, nil
}
func (s *ccAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *ccAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *ccAuditStore) Close() error { return nil }

// actionsSince returns the captured entries with the given Action recorded at or
// after `since` — used to assert a skip was produced by THIS cycle (e.g. the
// convergence tick after a failover), not a stale one from a prior phase.
func (s *ccAuditStore) actionsSince(action string, since time.Time) []*business.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*business.AuditEntry
	for _, e := range s.entries {
		if e.Action == action && !e.Timestamp.Before(since) {
			out = append(out, e)
		}
	}
	return out
}

// ─── live-cluster harness ──────────────────────────────────────────────────────

// ccEnv holds the resolved test environment for one live run.
type ccEnv struct {
	cluster   string
	localNode string   // this host's cluster node name (== module os.Hostname identity)
	nodes     []string // all cluster member node names
	vmName    string
	vhdPath   string
	seedDir   string
	switchNm  string
}

// ccSetup resolves the environment and skips cleanly when the suite cannot run
// live: no cluster configured, powershell/failover-clustering unavailable, or the
// host is not a member of the named cluster.
func ccSetup(t *testing.T) ccEnv {
	t.Helper()
	cluster := os.Getenv(envCluster)
	if cluster == "" {
		t.Skipf("live fleet-e2e: set %s to the cfg-lab cluster name to run", envCluster)
	}

	// Fail-fast, skip-clean cluster reachability probe.
	out, err := ccPS(t, `try { (Get-Cluster -Name $env:CFGMS_E2E_HYPERV_CLUSTER -ErrorAction Stop).Name } catch { "" }`)
	if err != nil || strings.TrimSpace(out) == "" {
		t.Skipf("live fleet-e2e: cluster %q not reachable from this host (need a cfg-lab member node with FailoverClusters): %v", cluster, err)
	}

	nodes := ccClusterNodes(t, cluster)
	require.GreaterOrEqual(t, len(nodes), 2, "cluster cascade validation needs at least 2 member nodes")

	localRaw, err := ccPS(t, `$env:COMPUTERNAME`)
	require.NoError(t, err)
	local := ccMatchNode(strings.TrimSpace(localRaw), nodes)
	require.NotEmptyf(t, local, "this host (%s) is not a member of cluster %q; run on a cfg-lab node", strings.TrimSpace(localRaw), cluster)

	vhdDir := getenvDefault("CFGMS_E2E_VHD_DIR", `C:\ClusterStorage\CSV01`)
	vmName := getenvDefault(envHAVM, "cfgms-e2e-ha-01")
	seedDir := getenvDefault(envSeedDir, `C:\cfgms\e2e-seed`)

	return ccEnv{
		cluster:   cluster,
		localNode: local,
		nodes:     nodes,
		vmName:    vmName,
		vhdPath:   vhdDir + `\` + vmName + `.vhdx`,
		seedDir:   seedDir,
		switchNm:  getenvDefault("CFGMS_E2E_SWITCH", "HVSwitch_1G"),
	}
}

// ccPS runs a PowerShell snippet on the local host and returns trimmed stdout.
// The suite runs on a Windows cluster node, so powershell.exe is present; a
// missing interpreter surfaces as an error the caller turns into a clean skip.
func ccPS(t *testing.T, script string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), &ccPSError{script: script, stderr: stderr.String(), err: err}
	}
	return strings.TrimSpace(stdout.String()), nil
}

type ccPSError struct {
	script string
	stderr string
	err    error
}

func (e *ccPSError) Error() string {
	return "powershell failed: " + e.err.Error() + " | stderr: " + strings.TrimSpace(e.stderr)
}

// ccPSFatal runs a snippet and fails the test on error — for orchestration steps
// (Move-ClusterGroup, cleanup) whose failure invalidates the test.
func ccPSFatal(t *testing.T, script string) string {
	t.Helper()
	out, err := ccPS(t, script)
	require.NoErrorf(t, err, "orchestration powershell failed: %s", script)
	return out
}

func ccClusterNodes(t *testing.T, cluster string) []string {
	t.Helper()
	out := ccPSFatal(t, `(Get-ClusterNode -Cluster '`+cluster+`' | Select-Object -ExpandProperty Name) -join "`+"`n"+`"`)
	var nodes []string
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			nodes = append(nodes, s)
		}
	}
	return nodes
}

// ccMatchNode returns the cluster node name matching `name` case-insensitively.
func ccMatchNode(name string, nodes []string) string {
	for _, n := range nodes {
		if strings.EqualFold(n, name) {
			return n
		}
	}
	return ""
}

// ccGroupOwner returns the current OwnerNode of a cluster group, or "" when the
// group is absent. This is the ground truth the module's readCNOOwner /
// readResourceOwners queries read.
func ccGroupOwner(t *testing.T, cluster, group string) string {
	t.Helper()
	out, _ := ccPS(t, `try { (Get-ClusterGroup -Cluster '`+cluster+`' -Name '`+group+`' -ErrorAction Stop).OwnerNode.Name } catch { "" }`)
	return strings.TrimSpace(out)
}

// ccRolePresent reports whether the clustered VM role group exists.
func ccRolePresent(t *testing.T, cluster, role string) bool {
	t.Helper()
	out, _ := ccPS(t, `try { if (Get-ClusterGroup -Cluster '`+cluster+`' -Name '`+role+`' -ErrorAction Stop) { "yes" } } catch { "" }`)
	return strings.TrimSpace(out) == "yes"
}

// ccGroupState returns the State string of a cluster group ("Online", "Offline",
// "PartiallyOnline", etc.) or "" when the group is absent.
func ccGroupState(t *testing.T, cluster, group string) string {
	t.Helper()
	out, _ := ccPS(t, `try { (Get-ClusterGroup -Cluster '`+cluster+`' -Name '`+group+`' -ErrorAction Stop).State.ToString() } catch { "" }`)
	return strings.TrimSpace(out)
}

// ccAutoBalancerEnabled reports whether the cluster's native VM dynamic optimizer
// is enabled (AutoBalancerMode >= 1: rebalance on join, or on join + periodic).
func ccAutoBalancerEnabled(t *testing.T, cluster string) bool {
	t.Helper()
	out, _ := ccPS(t, `try { if ((Get-Cluster -Name '`+cluster+`').AutoBalancerMode -ge 1) { "true" } else { "false" } } catch { "false" }`)
	return strings.TrimSpace(out) == "true"
}

// ccVMInstances snapshots, per cluster node, whether the named VM is present and
// its Hyper-V VMId. Two truths matter for the epic's safety property, and they
// are DIFFERENT:
//
//   - distinctIDs — the number of INDEPENDENT VMs (distinct VMIds) across the
//     cluster. This is the duplicate metric: the failure this epic prevents is
//     two nodes each independently creating a VM, which shows two distinct VMIds.
//     A live-migration transient shows the SAME VMId on two nodes briefly — that
//     is NOT a duplicate, so it must not be counted as one.
//   - present — the nodes whose Get-VM reports the VM at all. This is the liveness
//     metric: the VM must never vanish (present ≥ 1) during a failover.
//
// A peer-node query failure is returned as an error rather than swallowed: a
// silently-unreachable peer would read as "VM absent there" and could MASK a real
// duplicate.
func ccVMInstances(t *testing.T, env ccEnv) (present []string, distinctIDs int, err error) {
	t.Helper()
	ids := map[string]struct{}{}
	for _, node := range env.nodes {
		out, e := ccPS(t, `try { (Get-VM -ComputerName '`+node+`' -Name '`+env.vmName+`' -ErrorAction Stop).Id.Guid } catch { "" }`)
		if e != nil {
			return nil, 0, e
		}
		if id := strings.TrimSpace(out); id != "" {
			present = append(present, node)
			ids[id] = struct{}{}
		}
	}
	return present, len(ids), nil
}

// ccWaitSingleInstanceOn polls until exactly one node — `node` — reports the VM
// and there is exactly one distinct VMId cluster-wide, tolerating a brief
// migration transient. Fails the test on a peer-query error or on timeout.
func ccWaitSingleInstanceOn(t *testing.T, env ccEnv, node string) {
	t.Helper()
	deadline := time.Now().Add(ccSettleTimeout)
	var present []string
	var distinct int
	for time.Now().Before(deadline) {
		var err error
		present, distinct, err = ccVMInstances(t, env)
		require.NoError(t, err, "cross-node Get-VM must succeed on every peer (an unreachable peer could mask a duplicate)")
		require.LessOrEqual(t, distinct, 1, "a duplicate VM (distinct VMIds) must never exist (present on %v)", present)
		if len(present) == 1 && distinct == 1 && strings.EqualFold(present[0], node) {
			return
		}
		time.Sleep(ccPollInterval)
	}
	require.Failf(t, "VM never settled to a single instance",
		"expected exactly one instance on %q, last present=%v distinctIDs=%d", node, present, distinct)
}

// ccWaitGroupOwner polls until the group's owner equals want (case-insensitive)
// or the settle timeout elapses.
func ccWaitGroupOwner(t *testing.T, cluster, group, want string) {
	t.Helper()
	deadline := time.Now().Add(ccSettleTimeout)
	for time.Now().Before(deadline) {
		if strings.EqualFold(ccGroupOwner(t, cluster, group), want) {
			return
		}
		time.Sleep(ccPollInterval)
	}
	require.Failf(t, "cluster group never settled", "group %q did not reach owner %q within %s (last owner %q)",
		group, want, ccSettleTimeout, ccGroupOwner(t, cluster, group))
}

// ccMoveGroup moves a cluster group to a target node and waits for it to settle.
func ccMoveGroup(t *testing.T, cluster, group, target string) {
	t.Helper()
	ccPSFatal(t, `Move-ClusterGroup -Cluster '`+cluster+`' -Name '`+group+`' -Node '`+target+`' -ErrorAction Stop | Out-Null`)
	ccWaitGroupOwner(t, cluster, group, target)
}

// ccOtherNode returns any cluster node that is not `not`.
func ccOtherNode(env ccEnv, not string) string {
	for _, n := range env.nodes {
		if !strings.EqualFold(n, not) {
			return n
		}
	}
	return ""
}

// ─── module + convergence driver ───────────────────────────────────────────────

// ccBuildModule constructs the real hyperv module wired for the live cluster:
// ps-host transport (so its node identity is this host), the cluster_name scope
// cap, an in-memory provision store, and an audit manager whose store the test
// reads back. Returns the module, its audit manager, and the backing store.
func ccBuildModule(t *testing.T, env ccEnv) (modules.Module, *audit.Manager, *ccAuditStore) {
	t.Helper()
	store := &ccAuditStore{}
	mgr, err := audit.NewManager(store, "hyperv-cluster-e2e")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })

	m := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(hyperv.NewMemProvisionStore()))

	// Configure() rejects with errSecretStoreRequired before reading any config
	// key unless a SecretStore has been injected (module.go:268). A plain ha_role
	// VM references no secrets, so an empty in-memory store satisfies the contract
	// — same injection the provision_*_test.go references perform.
	injectable, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must accept an injected secret store")
	require.NoError(t, injectable.SetSecretStore(&e2eSecretStore{secrets: map[string]string{}}))

	configurable, ok := m.(modules.Configurable)
	require.True(t, ok, "hyperv module must be Configurable")
	require.NoError(t, configurable.Configure(e2eConfigState{
		"transport":     "ps-host",
		"cluster_name":  env.cluster,
		"seed_dir":      env.seedDir, // host-local (vm.go:358 HA-role CSV seed rule)
		"audit_manager": mgr,
		"steward_id":    "cfgms-e2e-steward-" + env.localNode,
	}))
	return m, mgr, store
}

// ccHAVMConfig builds the ha_role VM desired state. state ∈ {"stopped","running"}.
// The VHD is CSV-homed (required for an ha_role VM and for cross-node failover);
// the module creates it (New-VM -NewVHDPath, 64GB dynamic) on the owner.
func ccHAVMConfig(env ccEnv, state string) *hyperv.VMConfig {
	return &hyperv.VMConfig{
		Name:        env.vmName,
		MemoryMB:    2048,
		CPUCount:    2,
		VHDPath:     env.vhdPath,
		SwitchNames: []string{env.switchNm},
		Generation:  2,
		State:       state,
		HARole:      &hyperv.HARoleConfig{ClusterName: env.cluster},
	}
}

// ccConverge runs one module convergence pass for the ha_role VM (as the local
// node). Returns the error so callers can assert the fail-safe contracts.
func ccConverge(ctx context.Context, m modules.Module, env ccEnv, state string) error {
	return m.Set(ctx, "vm:"+env.vmName, ccHAVMConfig(env, state))
}

// ccEnsureRoleOnOwner brings the cluster to a known baseline: the ha_role VM
// exists exactly once, created + registered by the CNO owner. It moves the CNO to
// the local node, converges (which creates on the owner), and asserts a single
// instance. Registered as the shared precondition + cleanup for the tests that
// need an existing role.
func ccEnsureRoleOnOwner(t *testing.T, ctx context.Context, m modules.Module, env ccEnv) {
	t.Helper()
	// Make the local node the CNO owner so its convergence performs the create.
	ccMoveGroup(t, env.cluster, ccCNOGroup, env.localNode)
	require.NoError(t, ccConverge(ctx, m, env, "stopped"), "owner create-convergence must succeed")

	deadline := time.Now().Add(ccSettleTimeout)
	for time.Now().Before(deadline) {
		present, distinct, err := ccVMInstances(t, env)
		if err == nil && ccRolePresent(t, env.cluster, env.vmName) && len(present) == 1 && distinct == 1 {
			return
		}
		_ = ccConverge(ctx, m, env, "stopped")
		time.Sleep(ccPollInterval)
	}
	require.Fail(t, "baseline role never reached a single-instance registered state")
}

// ccCleanupRole tears the ha_role VM down cluster-wide: remove the clustered role
// group, then remove the VM + its VHD from whichever node holds it. Best-effort.
func ccCleanupRole(t *testing.T, env ccEnv) {
	ccPSFatal(t, `
$c = '`+env.cluster+`'; $role = '`+env.vmName+`'
try { Remove-ClusterGroup -Cluster $c -Name $role -RemoveResources -Force -ErrorAction Stop } catch {}
foreach ($n in @('`+strings.Join(env.nodes, "','")+`')) {
  try {
    $vm = Get-VM -ComputerName $n -Name $role -ErrorAction Stop
    if ($vm) {
      Stop-VM -ComputerName $n -Name $role -TurnOff -Force -ErrorAction SilentlyContinue
      $disks = (Get-VMHardDiskDrive -ComputerName $n -VMName $role -ErrorAction SilentlyContinue).Path
      Remove-VM -ComputerName $n -Name $role -Force -ErrorAction Stop
      foreach ($d in $disks) { try { Remove-Item -Path $d -Force -ErrorAction SilentlyContinue } catch {} }
    }
  } catch {}
}`)
}

// ─── AC: exactly one VM, created by the CNO owner ──────────────────────────────

// TestClusterCascade_SingleVMCreatedByOwner (REQUIRED, #2418 AC1) — with the same
// ha_role definition cascaded to every member, exactly one VM is created, by the
// CNO-owner steward. The test steers the CNO to the local node so its module
// plays the owner, converges, and asserts a single registered instance owned
// here — and that the owner's convergence recorded NO surface-and-wait skip.
func TestClusterCascade_SingleVMCreatedByOwner(t *testing.T) {
	env := ccSetup(t)
	ctx := context.Background()
	m, _, store := ccBuildModule(t, env)

	ccCleanupRole(t, env) // start from role-absent-cluster-wide
	t.Cleanup(func() { ccCleanupRole(t, env) })

	// Local node becomes CNO owner → its convergence is the creating one.
	ccMoveGroup(t, env.cluster, ccCNOGroup, env.localNode)
	require.Equal(t, env.localNode, ccGroupOwner(t, env.cluster, ccCNOGroup))

	start := time.Now()
	require.NoError(t, ccConverge(ctx, m, env, "stopped"),
		"the CNO owner must perform the first-ever create")

	// Role registered as a clustered VM group, owned by this (CNO-owner) node.
	require.True(t, ccRolePresent(t, env.cluster, env.vmName),
		"the created VM must be registered as a clustered role")
	assert.Equal(t, env.localNode, ccGroupOwner(t, env.cluster, env.vmName),
		"the role is owned by the CNO-owner node that created it")

	// The safety keystone: exactly one VM instance across the whole cluster,
	// living on the creating owner.
	ccWaitSingleInstanceOn(t, env, env.localNode)

	// The owner path must NOT have recorded a surface-and-wait skip.
	assert.Empty(t, store.actionsSince("vm-set-skip-not-cno-owner", start),
		"the CNO owner must not surface-and-wait — it creates")
	assert.Empty(t, store.actionsSince("vm-set-skip-hosted-elsewhere", start),
		"the creating owner must not skip as hosted-elsewhere")
}

// TestClusterCascade_NonOwnersConverged (REQUIRED, #2418 AC/#2420) — the members
// that do NOT host the role converge as no-ops: no drift, no create, no lifecycle
// action, and above all no duplicate VM. The test makes the local node a
// non-hosting member (role owned elsewhere) and asserts its convergence skips as
// hosted-elsewhere while the single instance stays put on the real owner.
func TestClusterCascade_NonOwnersConverged(t *testing.T) {
	env := ccSetup(t)
	ctx := context.Background()
	m, _, store := ccBuildModule(t, env)

	t.Cleanup(func() { ccCleanupRole(t, env) })
	ccEnsureRoleOnOwner(t, ctx, m, env) // baseline: one instance, owned by local

	// Hand the role to another node so the local module is now a NON-owner whose
	// VM is hosted elsewhere.
	other := ccOtherNode(env, env.localNode)
	require.NotEmpty(t, other, "need a second node to host the role elsewhere")
	ccMoveGroup(t, env.cluster, env.vmName, other)
	require.Equal(t, other, ccGroupOwner(t, env.cluster, env.vmName))

	// Precondition: exactly one instance, now on `other`.
	ccWaitSingleInstanceOn(t, env, other)

	start := time.Now()
	require.NoError(t, ccConverge(ctx, m, env, "stopped"),
		"a non-owner convergence is a clean no-op, never an error")

	// The non-owner produced a hosted-elsewhere skip and created nothing locally.
	assert.NotEmpty(t, store.actionsSince("vm-set-skip-hosted-elsewhere", start),
		"a non-hosting member must audit a hosted-elsewhere skip")

	// Still exactly one instance, still on the real owner — no local duplicate.
	present, distinct, err := ccVMInstances(t, env)
	require.NoError(t, err)
	require.Equal(t, 1, distinct, "a non-owner converge must not create an independent duplicate (present on %v)", present)
	require.Len(t, present, 1, "the single instance stays on its real owner (got %v)", present)
	assert.Equal(t, other, present[0], "the single instance stays on its real owner")
	assert.NotContains(t, present, env.localNode, "the non-owner must not materialize a local copy")
}

// TestClusterCascade_FailoverHandoff (REQUIRED, #2418 AC/#2422 — the epic's
// sharpest edge) — with the local convergence loop running LIVE throughout, a
// forced failover hands management over with zero operator action and zero
// duplicate VMs. The test keeps a real convergence loop ticking on the local node
// while it (a) receives the role — asserting the new owner converges the VM — and
// (b) loses the role — asserting the previous owner goes quiet (a
// lifecycle/hosted-elsewhere skip, no lifecycle writes). A background poller
// samples cross-node instance count across the entire window and asserts it is
// exactly 1 at every sample — never a duplicate, never a gap.
func TestClusterCascade_FailoverHandoff(t *testing.T) {
	env := ccSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, _, store := ccBuildModule(t, env)

	t.Cleanup(func() { ccCleanupRole(t, env) })
	ccEnsureRoleOnOwner(t, ctx, m, env) // one instance, owned by local

	other := ccOtherNode(env, env.localNode)
	require.NotEmpty(t, other, "failover needs a second node")

	// Baseline for a REAL ownership GAIN in Handoff 1: hand the role to `other`
	// first so the local node starts as a NON-owner. Without this, Handoff 1's
	// move-to-local would be a same-node no-op and never exercise a gain.
	ccMoveGroup(t, env.cluster, env.vmName, other)
	require.Equal(t, other, ccGroupOwner(t, env.cluster, env.vmName),
		"precondition: role hosted on `other` so the local loop starts as a non-owner")

	// Continuous cross-node safety poller across the whole failover window (not just
	// before/after snapshots). Tracks the worst-case DISTINCT-VMId count (the
	// duplicate metric — a live-migration transient of the same VMId is not a
	// duplicate) and the worst-case PRESENCE count (the liveness/gap metric), plus
	// the first peer-query error (a masked peer could hide a real duplicate).
	var pollMu sync.Mutex
	maxDistinct := 1 // ≤1 always: never two independent VMs
	minPresent := 1  // ≥1 always: never zero instances
	var pollErr error
	var pollWG sync.WaitGroup
	pollWG.Add(1)
	go func() {
		defer pollWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			present, distinct, err := ccVMInstances(t, env)
			pollMu.Lock()
			if err != nil {
				if pollErr == nil {
					pollErr = err
				}
			} else {
				if distinct > maxDistinct {
					maxDistinct = distinct
				}
				if len(present) < minPresent {
					minPresent = len(present)
				}
			}
			pollMu.Unlock()
			time.Sleep(ccPollInterval)
		}
	}()

	// Live convergence loop on the local node — real module ticks, never paused,
	// running THROUGH both Move-ClusterGroup calls below.
	var loopWG sync.WaitGroup
	loopWG.Add(1)
	go func() {
		defer loopWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = ccConverge(ctx, m, env, "running") // errors are transient; state is asserted via the cluster
			time.Sleep(ccPollInterval)
		}
	}()

	// GUARANTEED teardown of the goroutines, registered AFTER ccCleanupRole so it
	// runs BEFORE it (t.Cleanup is LIFO): even if a require below aborts the test,
	// the loop + poller are cancelled and joined before the VM/role is torn down,
	// so no live convergence races the cleanup. Idempotent with the inline join.
	t.Cleanup(func() {
		cancel()
		loopWG.Wait()
		pollWG.Wait()
	})

	// ── Handoff 1: role moves TO the local node — the new owner's live loop must
	// converge it with zero operator action.
	ccMoveGroup(t, env.cluster, env.vmName, env.localNode)
	deadline := time.Now().Add(ccSettleTimeout)
	converged := false
	for time.Now().Before(deadline) {
		present, distinct, err := ccVMInstances(t, env)
		require.NoError(t, err)
		require.LessOrEqual(t, distinct, 1, "no duplicate during the gain handoff (present on %v)", present)
		state := ccGroupOwner(t, env.cluster, env.vmName)
		if len(present) == 1 && distinct == 1 && strings.EqualFold(present[0], env.localNode) && strings.EqualFold(state, env.localNode) {
			converged = true
			break
		}
		time.Sleep(ccPollInterval)
	}
	require.True(t, converged, "the new owner's live loop must converge the role with no operator action")

	// ── Handoff 2: role moves AWAY to `other` — the previous owner (local) must go
	// quiet: its very next convergence cycles take zero lifecycle action.
	ccMoveGroup(t, env.cluster, env.vmName, other)
	quietStart := time.Now()

	// Wait for the local loop to observe the new owner and record a quiet-skip.
	quiet := false
	deadline = time.Now().Add(ccSettleTimeout)
	for time.Now().Before(deadline) {
		hostedElsewhere := store.actionsSince("vm-set-skip-hosted-elsewhere", quietStart)
		lifecycleSkip := store.actionsSince("vm-lifecycle-skip-not-owner", quietStart)
		if len(hostedElsewhere) > 0 || len(lifecycleSkip) > 0 {
			quiet = true
			break
		}
		time.Sleep(ccPollInterval)
	}
	assert.True(t, quiet,
		"the previous owner's convergence loop must go quiet (audited owner-gate skip) after losing the role")

	// Stop the loops and the poller, then assert the safety invariant held THROUGHOUT.
	cancel()
	loopWG.Wait()
	pollWG.Wait()

	pollMu.Lock()
	gotMaxDistinct, gotMinPresent, gotErr := maxDistinct, minPresent, pollErr
	pollMu.Unlock()
	require.NoError(t, gotErr, "a cross-node peer query failed during the poll window — count could be masking a duplicate")
	assert.LessOrEqual(t, gotMaxDistinct, 1, "a duplicate VM (2 distinct VMIds) must NEVER appear during failover")
	assert.GreaterOrEqual(t, gotMinPresent, 1, "the VM must NEVER vanish (0 instances) during failover")

	// Final state: exactly one instance, now on the new owner.
	ccWaitSingleInstanceOn(t, env, other)
}
