// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Fleet-e2e live validation of the workflow-driven Hyper-V role promotion epic
// (#2657, stories #2667/#2668/#2670/#2671) against the real cfg-lab 3-node
// failover cluster.
//
// The epic promotes a standalone hyperv.vm into a cluster-wide CNO-owned HA role
// with THREE moving parts that this suite exercises together, live:
//
//  1. set_ha_role step executor — writes the ha_role block into the VM's
//     device-scope config document (stewards/<id>) via
//     ConfigurationServiceV2.SetConfiguration.
//  2. the steward's own hyperv-module convergence — on seeing ha_role, the real
//     module registers the clustered VM role (registerClusteredRole →
//     Add-ClusterVirtualMachineRole), exactly once cluster-wide, gated on CNO
//     ownership. The workflow NEVER calls the module directly (epic grounding
//     note 1): it only writes config; the module does the rest.
//  3. move_resource_to_cluster step executor — relocates the resource definition
//     from device scope (stewards/<id>) to cluster scope
//     (cluster-policies/<clusterName>), Config unchanged.
//
// Per the story's Implementation Notes, this suite drives the two step executors
// DIRECTLY (constructed against a real flatfile-backed ConfigStore +
// ConfigurationServiceV2) and the real hyperv module directly — the same
// "drive the real component, not a mock" approach cluster_cascade_test.go uses —
// rather than standing up a full controller process or the HTTP/CLI layer (whose
// plumbing is covered by S5's own unit tests). The soak-delay step is a fixed
// wait in production (promote-hv-role.yaml, grounding note 5); here the test
// itself sequences module convergence between the two config writes, which is
// what the soak window exists to allow.
//
// The suite is excluded from CI and `make test-complete` by the e2e build tag,
// and skips cleanly when CFGMS_E2E_HYPERV_CLUSTER is unset or the host is not a
// Hyper-V cluster node. It reuses the shared live-cluster harness in
// cluster_cascade_test.go (ccSetup, ccPS/ccPSFatal, ccMoveGroup, ccGroupOwner,
// ccRolePresent, ccVMInstances, ccWaitSingleInstanceOn, ccCleanupRole,
// ccBuildModule, ccCNOGroup) and the shared in-memory helpers in
// provision_debian_test.go (e2eSecretStore, e2eConfigState, getenvDefault).
package hyperv_e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	controllersvc "github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/workflow"
	workflownodes "github.com/cfgis/cfgms/features/workflow/nodes"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Optional environment variable (in addition to the shared ccSetup gate vars):
//
//	CFGMS_E2E_PROMOTE_VM   the standalone-then-promoted VM/role name
//	                       (default cfgms-e2e-promote-01). Deliberately distinct
//	                       from the cascade suite's CFGMS_E2E_HAROLE_VM so the two
//	                       suites never share a VM identity or VHD path.
const (
	envPromoteVM = "CFGMS_E2E_PROMOTE_VM"

	// prTenantID is the tenant the device- and cluster-scope config documents are
	// keyed under. Arbitrary but consistent across both step executors.
	prTenantID = "cfgms-e2e"
)

// ─── config-migration stack (real flatfile ConfigStore, not a fake) ────────────

// prStack bundles the real config-scope-migration components and the real hyperv
// module for one live promotion run.
type prStack struct {
	store     cfgconfig.ConfigStore
	configSvc *controllersvc.ConfigurationServiceV2
	setExec   *workflownodes.SetHARoleNodeExecutor
	moveExec  *workflownodes.MoveResourceToClusterNodeExecutor
	module    modules.Module
	stewardID string
}

// prBuildStack constructs the config-migration executors against a real flatfile
// storage manager (SetupTestStorage: config/audit/steward on a real flatfile
// provider in t.TempDir(), business data on named in-memory SQLite) — a real
// ConfigStore + ConfigurationServiceV2, not an in-memory fake, as the epic's
// "verified live on cfg-lab" criterion requires. It also builds the real hyperv
// module wired for the live cluster (ccBuildModule).
func prBuildStack(t *testing.T, env ccEnv) prStack {
	t.Helper()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	m, _, _ := ccBuildModule(t, env)

	return prStack{
		store:     store,
		configSvc: configSvc,
		setExec:   workflownodes.NewSetHARoleNodeExecutor(store, configSvc),
		moveExec:  workflownodes.NewMoveResourceToClusterNodeExecutor(store, configSvc),
		module:    m,
		stewardID: "cfgms-e2e-steward-" + env.localNode,
	}
}

// prStandaloneConfig builds the desired state for a STANDALONE (non-clustered)
// VM: HARole is nil. The VHD is CSV-homed at env.vhdPath so that promotion needs
// no storage relocation (AC3 — the module only registers the cluster role; it
// never moves the disk). The module injects its host-local seed_dir into the
// config before Validate (vm.go:1179), so a CSV VHD passes the HA-role seed-dir
// rule once HARole is added on the promote pass.
func prStandaloneConfig(env ccEnv, state string) *hyperv.VMConfig {
	return &hyperv.VMConfig{
		Name:        env.vmName,
		MemoryMB:    2048,
		CPUCount:    2,
		VHDPath:     env.vhdPath,
		SwitchNames: []string{env.switchNm},
		Generation:  2,
		State:       state,
	}
}

// prHAConfig is prStandaloneConfig plus the ha_role block — the desired state
// after promotion. Converging this against the now-existing standalone VM drives
// the module's promote path (desired.HARole != nil && current.HARole == nil →
// registerClusteredRole).
func prHAConfig(env ccEnv, state string) *hyperv.VMConfig {
	c := prStandaloneConfig(env, state)
	c.HARole = &hyperv.HARoleConfig{ClusterName: env.cluster}
	return c
}

// prConverge runs one module convergence pass for the given desired state.
func prConverge(ctx context.Context, m modules.Module, cfg *hyperv.VMConfig) error {
	return m.Set(ctx, "vm:"+cfg.Name, cfg)
}

// prCleanup tears down this suite's VM + clustered role cluster-wide, best-effort.
// It mirrors ccCleanupRole but is EXIT-CODE-SAFE on a clean bed: when there is
// nothing to remove, each cmdlet's -ErrorAction Stop throws "not found" and is
// caught, which still leaves `powershell.exe -Command` with exit code 1 (a caught
// terminating error sets the host's exit state) — and ccPSFatal would treat that
// as a failure. The cascade suite never hit this because it always had a VM to
// remove (the final Remove-VM succeeded → exit 0); this suite runs against a
// guaranteed-clean, never-before-used VM name, so every branch is caught. The
// trailing `exit 0` makes teardown deterministically succeed whether or not
// anything was present — cleanup is inherently best-effort here (every removal is
// individually try/caught), matching ccCleanupRole's own swallow-all intent. Kept
// in this file so the story does not modify cluster_cascade_test.go (out of scope).
func prCleanup(t *testing.T, env ccEnv) {
	t.Helper()
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
}
exit 0`)
}

// ─── device/cluster config-document helpers ────────────────────────────────────

// prStandaloneResource is the device-scope resource entry for the standalone VM,
// before promotion: a hyperv.vm resource with NO ha_role block. Field names
// mirror the module's config surface for realism; the migration executors only
// key on Name + Module == "hyperv.vm", so the exact scalars are immaterial to
// them (the live convergence is driven by the *VMConfig above, not by this doc).
func prStandaloneResource(env ccEnv) stewardtypes.ResourceConfig {
	return stewardtypes.ResourceConfig{
		Name:   env.vmName,
		Module: "hyperv.vm",
		Config: map[string]interface{}{
			"memory_mb":    2048,
			"cpu_count":    2,
			"vhd_path":     env.vhdPath,
			"switch_names": []interface{}{env.switchNm},
			"generation":   2,
			"state":        "stopped",
		},
	}
}

// prSeedDeviceConfig writes the initial device-scope document (stewards/<id>)
// containing the standalone hyperv.vm resource, via the raw ConfigStore (no
// validation/fanout — this is the pre-existing state the promote workflow acts
// on, exactly as storeInitialStewardConfig does in the unit tests).
func prSeedDeviceConfig(t *testing.T, s prStack, env ccEnv) {
	t.Helper()
	cfg := stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:   s.stewardID,
			Mode: stewardtypes.ModeController,
		},
		Resources: []stewardtypes.ResourceConfig{prStandaloneResource(env)},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, s.store.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: prTenantID, Namespace: "stewards", Name: s.stewardID},
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}))
}

// prReadConfigDoc reads and unmarshals a config document at the given namespace,
// returning (config, present). A missing document is (zero, false), not an error.
func prReadConfigDoc(t *testing.T, s prStack, namespace, name string) (stewardtypes.StewardConfig, bool) {
	t.Helper()
	entry, err := s.store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  prTenantID,
		Namespace: namespace,
		Name:      name,
	})
	if err != nil {
		return stewardtypes.StewardConfig{}, false
	}
	var cfg stewardtypes.StewardConfig
	require.NoError(t, yaml.Unmarshal(entry.Data, &cfg))
	return cfg, true
}

// prDocHasVM reports whether a config document contains the hyperv.vm resource.
func prDocHasVM(cfg stewardtypes.StewardConfig, vmName string) bool {
	for _, r := range cfg.Resources {
		if r.Name == vmName && r.Module == "hyperv.vm" {
			return true
		}
	}
	return false
}

// prDeviceHasVM / prClusterHasVM answer the AC's "present in cluster-policies,
// absent from the originating steward's device config" question directly.
func prDeviceHasVM(t *testing.T, s prStack, env ccEnv) bool {
	cfg, ok := prReadConfigDoc(t, s, "stewards", s.stewardID)
	return ok && prDocHasVM(cfg, env.vmName)
}

func prClusterHasVM(t *testing.T, s prStack, env ccEnv) bool {
	cfg, ok := prReadConfigDoc(t, s, "cluster-policies", env.cluster)
	return ok && prDocHasVM(cfg, env.vmName)
}

// prRawClusterDoc returns the raw bytes of the cluster-policies document, for the
// re-run "no duplicate write" byte-identity assertion. Empty string when absent.
func prRawClusterDoc(t *testing.T, s prStack, env ccEnv) string {
	t.Helper()
	entry, err := s.store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  prTenantID,
		Namespace: "cluster-policies",
		Name:      env.cluster,
	})
	if err != nil {
		return ""
	}
	return string(entry.Data)
}

// ─── workflow step / execution builders ────────────────────────────────────────

// prExecution builds a WorkflowExecution carrying the four variables both
// executors require (steward_id, tenant_id, vm_name, cluster_name) — the same
// shape the CLI's POST .../execute {"variables": {...}} body populates.
func prExecution(s prStack, env ccEnv) *workflow.WorkflowExecution {
	ex := &workflow.WorkflowExecution{
		ID:          "exec-promote-e2e",
		Status:      workflow.StatusRunning,
		StepResults: make(map[string]workflow.StepResult),
		Variables:   make(map[string]interface{}),
		Done:        make(chan struct{}),
	}
	ex.SetVariable("steward_id", s.stewardID)
	ex.SetVariable("tenant_id", prTenantID)
	ex.SetVariable("vm_name", env.vmName)
	ex.SetVariable("cluster_name", env.cluster)
	return ex
}

func prStep(name string, stepType workflow.StepType) workflow.Step {
	return workflow.Step{Name: name, Type: stepType}
}

// ─── VHD path (storage-relocation guard, AC3) ──────────────────────────────────

// prVHDPath returns the on-disk path of the VM's primary VHD as reported by the
// node that currently hosts it — the ground truth for "storage path unchanged".
func prVHDPath(t *testing.T, env ccEnv, node string) string {
	t.Helper()
	out := ccPSFatal(t, `(Get-VMHardDiskDrive -ComputerName '`+node+`' -VMName '`+env.vmName+`' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path)`)
	return strings.TrimSpace(out)
}

// ─── promote helper (the live sequence both REQUIRED tests share) ──────────────

// prSetup resolves the shared live environment (ccSetup: cluster reachability,
// nodes, local node, switch, seed_dir; skips cleanly when unconfigured) and
// swaps in this suite's own VM identity so it never collides with the cascade
// suite's VM.
func prSetup(t *testing.T) ccEnv {
	t.Helper()
	env := ccSetup(t)
	vhdDir := getenvDefault("CFGMS_E2E_VHD_DIR", `C:\ClusterStorage\CSV01`)
	env.vmName = getenvDefault(envPromoteVM, "cfgms-e2e-promote-01")
	env.vhdPath = vhdDir + `\` + env.vmName + `.vhdx`
	return env
}

// prReachPromoted drives the full standalone → clustered-role promotion live and
// asserts every core invariant of the epic's happy path:
//
//   - a standalone VM is created on the local (CNO-owner) node with a CSV VHD and
//     is NOT yet a clustered role;
//   - set_ha_role writes ha_role into the device-scope config document;
//   - module convergence registers exactly one cluster-wide CNO-owned HA role;
//   - move_resource_to_cluster relocates the resource to cluster-policies/<cluster>
//     and removes it from stewards/<id>;
//   - the VM's VHD path is byte-identical before and after (no storage relocation).
//
// It returns the (unchanged) VHD path so callers can re-assert it after a re-run.
// This IS the content of AC1 + the present-in-cluster/absent-in-device AC + AC3;
// TestPromoteHVRole_StandaloneToClusteredRole is a thin wrapper over it, and
// TestPromoteHVRole_ReRunIsNoOp builds its no-op assertions on top of it.
func prReachPromoted(t *testing.T, ctx context.Context, env ccEnv, s prStack) string {
	t.Helper()

	// Start from a role-absent, VM-absent cluster, and guarantee teardown.
	prCleanup(t, env)
	t.Cleanup(func() { prCleanup(t, env) })

	// Make the local node the CNO owner so ITS convergence performs the create and
	// the promote registration (reconcileRoleMembership gates registration on CNO
	// ownership; a non-owner would surface-and-wait instead of registering).
	ccMoveGroup(t, env.cluster, ccCNOGroup, env.localNode)
	require.Equal(t, env.localNode, ccGroupOwner(t, env.cluster, ccCNOGroup))

	// ── Create the STANDALONE VM (no ha_role). It exists on the local node with a
	// CSV-homed VHD and is NOT registered as a clustered role.
	require.NoError(t, prConverge(ctx, s.module, prStandaloneConfig(env, "stopped")),
		"standalone create-convergence must succeed")
	ccWaitSingleInstanceOn(t, env, env.localNode)
	require.False(t, ccRolePresent(t, env.cluster, env.vmName),
		"the freshly-created standalone VM must NOT yet be a clustered role")

	// Capture the VHD path BEFORE promotion — AC3's baseline.
	vhdBefore := prVHDPath(t, env, env.localNode)
	require.NotEmpty(t, vhdBefore, "must resolve the standalone VM's VHD path")

	// Seed the device-scope config document with the standalone resource — the
	// pre-existing state the promote workflow acts on.
	prSeedDeviceConfig(t, s, env)
	require.True(t, prDeviceHasVM(t, s, env), "device config must start with the VM resource")
	require.False(t, prClusterHasVM(t, s, env), "cluster-policies must start without the VM resource")

	// ── STEP 1 (set_ha_role): write ha_role into the device-scope config document.
	setRes, err := s.setExec.ExecuteSetHARoleStep(ctx, prStep("set-ha-role", workflow.StepTypeSetHARole), prExecution(s, env))
	require.NoError(t, err, "set_ha_role must succeed")
	require.Equal(t, workflow.StatusCompleted, setRes.Status)
	deviceCfg, ok := prReadConfigDoc(t, s, "stewards", s.stewardID)
	require.True(t, ok)
	for _, r := range deviceCfg.Resources {
		if r.Name == env.vmName {
			ha, isMap := r.Config["ha_role"].(map[string]interface{})
			require.True(t, isMap, "ha_role must be written into the device config after set_ha_role")
			assert.Equal(t, env.cluster, ha["cluster_name"])
		}
	}

	// ── STEP 2 (steward convergence): the real module registers the cluster role.
	// This is what the steward's own converge loop does on receiving the fanout
	// push from set_ha_role's SetConfiguration — the workflow's fixed soak delay
	// exists precisely to let this happen before the scope move.
	require.NoError(t, prConverge(ctx, s.module, prHAConfig(env, "stopped")),
		"promote-convergence (ha_role registration) must succeed")
	require.True(t, ccRolePresent(t, env.cluster, env.vmName),
		"after convergence the VM must be registered as a clustered role")
	assert.Equal(t, env.localNode, ccGroupOwner(t, env.cluster, env.vmName),
		"the role is owned by the CNO-owner node that registered it")
	ccWaitSingleInstanceOn(t, env, env.localNode)

	// ── STEP 3 (move_resource_to_cluster): relocate the resource to cluster scope.
	moveRes, err := s.moveExec.ExecuteMoveResourceToClusterStep(ctx, prStep("move-to-cluster", workflow.StepTypeMoveResourceToCluster), prExecution(s, env))
	require.NoError(t, err, "move_resource_to_cluster must succeed")
	require.Equal(t, workflow.StatusCompleted, moveRes.Status)

	// AC: present in cluster-policies/<cluster>, absent from the originating
	// steward's device config.
	assert.True(t, prClusterHasVM(t, s, env),
		"the promoted resource must be present in cluster-policies/%s", env.cluster)
	assert.False(t, prDeviceHasVM(t, s, env),
		"the promoted resource must be absent from the originating steward's device config")

	// AC3: exactly one cluster-wide instance, and the VHD path never moved.
	ccWaitSingleInstanceOn(t, env, env.localNode)
	vhdAfter := prVHDPath(t, env, env.localNode)
	assert.Equal(t, vhdBefore, vhdAfter,
		"the VM's VHD path must be unchanged throughout promotion (no storage relocation)")

	return vhdAfter
}

// ─── AC1 (REQUIRED): standalone → exactly one CNO-owned clustered role ──────────

// TestPromoteHVRole_StandaloneToClusteredRole (REQUIRED, #2657 AC1) — a standalone
// VM on one cfg-lab node is promoted, via the set_ha_role + convergence +
// move_resource_to_cluster sequence, into exactly one cluster-wide CNO-owned HA
// role with its storage path untouched, and the resource ends up in cluster scope
// and out of device scope.
func TestPromoteHVRole_StandaloneToClusteredRole(t *testing.T) {
	env := prSetup(t)
	ctx := context.Background()
	s := prBuildStack(t, env)

	prReachPromoted(t, ctx, env, s)

	// Belt-and-suspenders: exactly one clustered role, owned by the CNO owner.
	require.True(t, ccRolePresent(t, env.cluster, env.vmName))
	present, distinct, err := ccVMInstances(t, env)
	require.NoError(t, err)
	assert.Equal(t, 1, distinct, "exactly one VM instance cluster-wide (present on %v)", present)
	assert.Len(t, present, 1, "the single instance lives on exactly one node (got %v)", present)
}

// ─── AC2 (REQUIRED): re-run against an already-promoted VM is a no-op ───────────

// TestPromoteHVRole_ReRunIsNoOp (REQUIRED, #2657 AC2) — re-running the promotion
// against an already-promoted VM makes no harmful change: no duplicate write to
// cluster-policies and no duplicate cluster role.
//
// After promotion the resource has LEFT device scope, so re-running set_ha_role
// (which reads stewards/<id>) would legitimately report "resource not found" —
// that is correct, not a no-op, so it is NOT re-driven here; its idempotency is
// covered by the unit suite (TestSetHARoleNode_IdempotentWhenAlreadySet). The
// operations a real re-dispatch actually re-hits ARE idempotent and are what this
// test re-drives:
//
//   - move_resource_to_cluster detects "absent from device, present in cluster"
//     and completes as a no-op WITHOUT rewriting the cluster document;
//   - module convergence sees current.HARole != nil and registers nothing new,
//     leaving exactly one clustered role.
func TestPromoteHVRole_ReRunIsNoOp(t *testing.T) {
	env := prSetup(t)
	ctx := context.Background()
	s := prBuildStack(t, env)

	vhdAfterFirst := prReachPromoted(t, ctx, env, s)

	// Snapshot the post-promotion state.
	clusterDocBefore := prRawClusterDoc(t, s, env)
	require.NotEmpty(t, clusterDocBefore, "cluster-policies document must exist after promotion")
	ownerBefore := ccGroupOwner(t, env.cluster, env.vmName)

	// ── Re-run move_resource_to_cluster — the idempotent scope-migration op.
	moveRes, err := s.moveExec.ExecuteMoveResourceToClusterStep(ctx,
		prStep("move-to-cluster-rerun", workflow.StepTypeMoveResourceToCluster), prExecution(s, env))
	require.NoError(t, err, "re-run move_resource_to_cluster must succeed as a no-op")
	require.Equal(t, workflow.StatusCompleted, moveRes.Status)

	// No duplicate write: the cluster document is byte-identical, and the resource
	// is still in cluster scope and still absent from device scope.
	assert.Equal(t, clusterDocBefore, prRawClusterDoc(t, s, env),
		"re-run must not rewrite the cluster-policies document (no duplicate write)")
	assert.True(t, prClusterHasVM(t, s, env), "resource stays in cluster-policies after re-run")
	assert.False(t, prDeviceHasVM(t, s, env), "resource stays out of device config after re-run")

	// ── Re-run module convergence — must not register a second role.
	require.NoError(t, prConverge(ctx, s.module, prHAConfig(env, "stopped")),
		"re-convergence against an already-registered role must be a clean no-op")

	// No duplicate cluster role: still present, still exactly one instance, still
	// the same owner, VHD still unmoved.
	require.True(t, ccRolePresent(t, env.cluster, env.vmName), "the clustered role must still exist after re-run")
	assert.Equal(t, ownerBefore, ccGroupOwner(t, env.cluster, env.vmName),
		"re-run must not change the role's owner")
	present, distinct, err := ccVMInstances(t, env)
	require.NoError(t, err)
	assert.Equal(t, 1, distinct, "re-run must not create a duplicate VM (present on %v)", present)
	assert.Len(t, present, 1, "still exactly one instance after re-run (got %v)", present)
	assert.Equal(t, vhdAfterFirst, prVHDPath(t, env, present[0]),
		"the VHD path must remain unchanged across the re-run")
}
