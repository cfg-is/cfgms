// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Live validation of the declarative hyperv.vm in-place rename (old_name → name,
// Issue #2776) against a real Hyper-V host. It drives the REAL hyperv module
// (ps-host transport) as the node it runs on — the same "real component, not a
// mock" approach the cluster suites use — creating a throwaway VM, renaming it
// via a converge with old_name set, and asserting the module renamed in place
// (new exists, old gone, no duplicate) rather than creating a second VM.
//
// The rename needs no guest OS (Rename-VM operates on the VM object regardless of
// boot state), so a bare stopped VM with a tiny blank VHD is sufficient. Excluded
// from CI / make test-complete by the e2e build tag; skips cleanly when
// CFGMS_E2E_HYPERV_RENAME is unset or the host is not a Hyper-V host.
package hyperv_e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/pkg/audit"
)

const envRenameE2E = "CFGMS_E2E_HYPERV_RENAME"

// rnBuildModule constructs the real hyperv module wired for ps-host (local
// PowerShell) transport — no cluster, so the rename path exercises the standalone
// (non-clustered) VM case. Reuses the package's in-memory audit + secret stores.
func rnBuildModule(t *testing.T) modules.Module {
	t.Helper()
	store := &ccAuditStore{}
	mgr, err := audit.NewManager(store, "hyperv-rename-e2e")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })

	m := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(hyperv.NewMemProvisionStore()))
	inj, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok)
	require.NoError(t, inj.SetSecretStore(&e2eSecretStore{secrets: map[string]string{}}))

	cfgbl, ok := m.(modules.Configurable)
	require.True(t, ok)
	require.NoError(t, cfgbl.Configure(e2eConfigState{
		"transport":     "ps-host",
		"seed_dir":      getenvDefault(envSeedDir, `C:\cfgms\e2e-seed`),
		"audit_manager": mgr,
		"steward_id":    "cfgms-e2e-rename-steward",
	}))
	return m
}

// rnVMExists reports whether a VM with the given name exists on the local host.
func rnVMExists(t *testing.T, name string) bool {
	out, _ := ccPS(t, `try { if (Get-VM -Name '`+name+`' -ErrorAction Stop) { "yes" } } catch { "" }`)
	return strings.TrimSpace(out) == "yes"
}

// rnCleanup removes the named VMs and their VHDs, best-effort.
func rnCleanup(t *testing.T, vhd string, names ...string) {
	for _, n := range names {
		ccPS(t, `try { Stop-VM -Name '`+n+`' -TurnOff -Force -ErrorAction SilentlyContinue; $d=(Get-VMHardDiskDrive -VMName '`+n+`' -ErrorAction SilentlyContinue).Path; Remove-VM -Name '`+n+`' -Force -ErrorAction SilentlyContinue; foreach($x in $d){ Remove-Item $x -Force -ErrorAction SilentlyContinue } } catch {}`)
	}
	if vhd != "" {
		ccPS(t, `Remove-Item '`+vhd+`' -Force -ErrorAction SilentlyContinue`)
	}
}

// TestE2E_VMRename_InPlace (REQUIRED, #2776) — a managed VM named old_name is
// renamed in place to name by a converge, not duplicated, and the rename is
// idempotent on re-run.
func TestE2E_VMRename_InPlace(t *testing.T) {
	if os.Getenv(envRenameE2E) == "" {
		t.Skipf("live rename e2e: set %s=1 on a Hyper-V host to run", envRenameE2E)
	}
	ctx := context.Background()

	const oldName = "cfgms-e2e-rename-old"
	const newName = "cfgms-e2e-rename-new"
	vhdDir := getenvDefault("CFGMS_E2E_RENAME_VHD_DIR", `C:\VMs`)
	vhd := vhdDir + `\` + oldName + `.vhdx`

	rnCleanup(t, vhd, oldName, newName)
	t.Cleanup(func() { rnCleanup(t, vhd, oldName, newName) })

	// Create a bare stopped VM under the OLD name (blank tiny dynamic VHD — the
	// rename needs no guest OS).
	ccPSFatal(t, `New-VHD -Path '`+vhd+`' -SizeBytes 2GB -Dynamic -ErrorAction Stop | Out-Null; `+
		`New-VM -Name '`+oldName+`' -MemoryStartupBytes 512MB -VHDPath '`+vhd+`' -Generation 2 -ErrorAction Stop | Out-Null`)
	require.True(t, rnVMExists(t, oldName), "precondition: old-named VM created")
	require.False(t, rnVMExists(t, newName), "precondition: new name must not exist yet")

	m := rnBuildModule(t)

	// Converge the desired state: name=newName, old_name=oldName. The module must
	// RENAME the existing oldName VM rather than create a new newName VM.
	cfg := &hyperv.VMConfig{
		Name: newName, OldName: oldName, State: "stopped",
		MemoryMB: 512, Generation: 2, VHDPath: vhd,
	}
	require.NoError(t, m.Set(ctx, "vm:"+newName, cfg), "rename converge must succeed")

	assert.True(t, rnVMExists(t, newName), "the VM must now exist under the new name")
	assert.False(t, rnVMExists(t, oldName), "the old name must be gone (renamed in place, not duplicated)")

	// Idempotent re-run: no error, still exactly the new name, no rename attempt.
	require.NoError(t, m.Set(ctx, "vm:"+newName, cfg), "idempotent re-converge must succeed")
	assert.True(t, rnVMExists(t, newName))
	assert.False(t, rnVMExists(t, oldName))
}
