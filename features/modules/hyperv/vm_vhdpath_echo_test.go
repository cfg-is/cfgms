// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getVMJSONWithPath builds a found-VM Get-VM JSON payload with an explicit disk
// Path — used to place the disk in a chosen directory/leaf the default
// hostVMJSON helper does not expose.
func getVMJSONWithPath(name, diskPath string) string {
	return `{"found":true,"Name":"` + name + `","MemoryStartupBytes":4294967296,"ProcessorCount":2,` +
		`"Generation":2,"Path":"` + diskPath + `","ConfigurationLocation":"","CheckpointCount":0,` +
		`"SwitchName":"","SwitchNames":[],"State":"Off"}`
}

// TestGetVM_VHDPathEcho_DirectoryCompliant_NoDrift is the #2776 follow-up: after a
// rename, Rename-VM leaves the VHD under its OLD leaf name (the module renames no
// disk files), so a declared vhd_path whose leaf tracks the new VM name differs
// from the on-disk leaf while the home DIRECTORY matches. getVM must echo the
// desired vhd_path so this leaf-only difference does not drift forever on
// something the module never reconciles.
func TestGetVM_VHDPathEcho_DirectoryCompliant_NoDrift(t *testing.T) {
	const vmName = "lab-01"
	const desiredPath = `C:\ClusterStorage\CSV01\lab-01\lab-01.vhdx`
	// Actual disk: SAME home directory, OLD leaf (Rename-VM did not rename it).
	const actualDisk = `C:\ClusterStorage\CSV01\lab-01\cfgms-ci-01.vhdx`

	transport := &testWinRMTransport{perCallOutputs: []string{
		getVMJSONWithPath(vmName, `C:\\ClusterStorage\\CSV01\\lab-01\\cfgms-ci-01.vhdx`),
	}}
	m := vmModuleWithTransport(transport, "t")
	// Seed the authored vhd_path as a prior setVM would.
	m.vhdPathDesired = map[string]string{vmName: desiredPath}

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)

	// The observed disk is read as-is on the struct...
	assert.Equal(t, actualDisk, cfg.VHDPath, "the struct still carries the true on-disk path")
	// ...but the drift SURFACE (AsMap) echoes the desired path, so a leaf-only
	// difference compares equal to desired and does not drift.
	assert.Equal(t, desiredPath, cfg.AsMap()["vhd_path"],
		"a disk already in the desired home directory must echo the desired vhd_path (no leaf-name drift)")
}

// TestGetVM_VHDPathEcho_WrongDirectory_ReportsActual verifies the echo is NOT
// applied when the disk is in a DIFFERENT directory: the actual path is reported
// so storageLocationDrift still fires and convergeStorageLocation moves the VM.
func TestGetVM_VHDPathEcho_WrongDirectory_ReportsActual(t *testing.T) {
	const vmName = "lab-01"
	const desiredPath = `C:\ClusterStorage\CSV01\lab-01\lab-01.vhdx`
	const actualDisk = `C:\VMs\lab-01.vhdx` // wrong home directory

	transport := &testWinRMTransport{perCallOutputs: []string{
		getVMJSONWithPath(vmName, `C:\\VMs\\lab-01.vhdx`),
	}}
	m := vmModuleWithTransport(transport, "t")
	m.vhdPathDesired = map[string]string{vmName: desiredPath}

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)

	assert.Equal(t, actualDisk, cfg.AsMap()["vhd_path"],
		"a disk in the WRONG home directory must report the actual path so storage-location drift surfaces")
}

// TestGetVM_VHDPathEcho_NoDesiredRecorded_ReportsActual verifies that before any
// setVM records a desired path (e.g. a fresh steward's first Get), getVM reports
// the actual disk — the authored vhd_path then drifts and drives that first Set,
// which records the path so subsequent Gets echo it. Mirrors the checkpoints echo.
func TestGetVM_VHDPathEcho_NoDesiredRecorded_ReportsActual(t *testing.T) {
	const vmName = "lab-01"
	const actualDisk = `C:\ClusterStorage\CSV01\lab-01\cfgms-ci-01.vhdx`

	transport := &testWinRMTransport{perCallOutputs: []string{
		getVMJSONWithPath(vmName, `C:\\ClusterStorage\\CSV01\\lab-01\\cfgms-ci-01.vhdx`),
	}}
	m := vmModuleWithTransport(transport, "t")
	// No vhdPathDesired seeded.

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, actualDisk, cfg.AsMap()["vhd_path"],
		"with no desired path recorded yet, getVM reports the actual disk (drives the first Set)")
}
