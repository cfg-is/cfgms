// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Characterization tests for hypervModule.Configure and provisionVM (Story
// #5826). They pin behavior so the complexity refactor changes none of it.

func moduleprovisionCharConfigure(t *testing.T, cfg mapConfigState) (*hypervModule, error) {
	t.Helper()
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	m.transport, m.transportPinned = &testPSTransport{}, true
	return m, m.Configure(cfg)
}

func moduleprovisionCharCfg(os string) *VMConfig {
	return &VMConfig{
		Name:       "stw-01",
		VHDPath:    `C:\VMs\stw-01.vhdx`,
		Generation: 2,
		Source:     &SourceConfig{ISO: `C:\iso\server.iso`, OSFamily: os},
	}
}

func TestModuleprovisionChar_ConfigureEnrollmentWiring(t *testing.T) {
	m, err := moduleprovisionCharConfigure(t, mapConfigState{
		"enroll_token":             "tok.en-1_x",
		"enroll_ca_fingerprint":    "AB:cd:01",
		"enroll_steward_path":      `C:\stage\steward.exe`,
		"enroll_launcher_path":     `C:\stage\launch.exe`,
		"enroll_ca_path":           `C:\stage\ca.pem`,
		"debug_ssh_authorized_key": "ssh-ed25519 AAAAC3Nza host",
		"seed_dir":                 `C:\seed`,
	})
	require.NoError(t, err)
	assert.Equal(t, "tok.en-1_x", m.enrollToken)
	assert.Equal(t, "AB:cd:01", m.enrollCAFingerprint)
	assert.Equal(t, `C:\stage\steward.exe`, m.enrollStewardPath)
	assert.Equal(t, `C:\stage\launch.exe`, m.enrollLauncherPath)
	assert.Equal(t, `C:\stage\ca.pem`, m.enrollCAPath)
	assert.Equal(t, "ssh-ed25519 AAAAC3Nza host", m.debugSSHAuthorizedKey)
	assert.Equal(t, `C:\seed`, m.seedDir)
}

func TestModuleprovisionChar_ConfigureWithoutEnrollmentWiring(t *testing.T) {
	m, err := moduleprovisionCharConfigure(t, mapConfigState{"tenant_id": "ops"})
	require.NoError(t, err)
	assert.Empty(t, m.enrollToken)
	assert.Empty(t, m.enrollCAFingerprint)
	assert.Empty(t, m.enrollStewardPath)
	assert.Empty(t, m.enrollLauncherPath)
	assert.Empty(t, m.enrollCAPath)
	assert.Empty(t, m.debugSSHAuthorizedKey)
	assert.Equal(t, "ops/hyperv", m.stewardID)
}

func TestModuleprovisionChar_ConfigureRejectsInvalidEnrollField(t *testing.T) {
	cases := []struct {
		field string
		value string
		want  error
	}{
		{"enroll_token", "bad token!", errInvalidEnrollToken},
		{"enroll_ca_fingerprint", "xyz", errInvalidEnrollCAFingerprint},
		{"enroll_steward_path", `\\host\share\s.exe`, errInvalidEnrollStewardPath},
		{"enroll_launcher_path", `C:\a\..\b.exe`, errInvalidEnrollLauncherPath},
		{"enroll_ca_path", `C:\a\*.pem`, errInvalidEnrollCAPath},
		{"debug_ssh_authorized_key", "not a key", errInvalidDebugSSHKey},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			_, err := moduleprovisionCharConfigure(t, mapConfigState{tc.field: tc.value})
			assert.Equal(t, tc.want, err)
		})
	}
}

func TestModuleprovisionChar_ConfigureClusterScope(t *testing.T) {
	t.Run("top-level cluster_name wins", func(t *testing.T) {
		m, err := moduleprovisionCharConfigure(t, mapConfigState{
			"cluster_name":       "c-top",
			"cluster_role_names": []interface{}{"r1", "r2"},
			"ha_role":            map[string]interface{}{"cluster_name": "c-nested"},
		})
		require.NoError(t, err)
		assert.Equal(t, "c-top", m.clusterName)
		assert.Equal(t, []string{"r1", "r2"}, m.clusterRoleNames)
	})
	t.Run("derived from ha_role block", func(t *testing.T) {
		m, err := moduleprovisionCharConfigure(t, mapConfigState{
			"ha_role": map[string]interface{}{"cluster_name": "c-nested"},
		})
		require.NoError(t, err)
		assert.Equal(t, "c-nested", m.clusterName)
	})
	t.Run("absent stays empty", func(t *testing.T) {
		m, err := moduleprovisionCharConfigure(t, mapConfigState{})
		require.NoError(t, err)
		assert.Empty(t, m.clusterName)
	})
}

func TestModuleprovisionChar_ConfigureCapturesHostname(t *testing.T) {
	want, _ := os.Hostname()
	m, err := moduleprovisionCharConfigure(t, mapConfigState{})
	require.NoError(t, err)
	assert.Equal(t, want, m.nodeHostname)
}

func TestModuleprovisionChar_ProvisionVMLeavesInProgressRecordAlone(t *testing.T) {
	for _, state := range []ProvisionState{ProvisionStateInstalling, ProvisionStateFinalizing} {
		t.Run(string(state), func(t *testing.T) {
			transport := &testPSTransport{}
			m := provisionModuleWithTransport(t, transport)
			store := NewMemProvisionStore()
			require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
				VMName: "stw-01", State: state, CorrelationID: "stw-01", RetryCount: 1,
			}))
			m.provisionStore = store

			require.NoError(t, m.provisionVM(context.Background(), "stw-01", "stw-01", moduleprovisionCharCfg("windows")))

			assert.Empty(t, transport.calls, "no host-side step may run")
			rec, err := store.GetProvision(context.Background(), "stw-01")
			require.NoError(t, err)
			assert.Equal(t, state, rec.State)
			assert.Equal(t, 1, rec.RetryCount, "RetryCount must not be bumped")
		})
	}
}

func TestModuleprovisionChar_ProvisionVMFailedRecordReentersCreating(t *testing.T) {
	transport := &testPSTransport{}
	m := provisionModuleWithTransport(t, transport)
	store := NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), &ProvisionRecord{
		VMName: "stw-01", State: ProvisionStateFailed, CorrelationID: "stw-01", RetryCount: 2,
	}))
	m.provisionStore = store

	require.NoError(t, m.provisionVM(context.Background(), "stw-01", "stw-01", moduleprovisionCharCfg("windows")))

	rec, err := store.GetProvision(context.Background(), "stw-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, rec.State)
	assert.Equal(t, 3, rec.RetryCount)
	assert.NotEmpty(t, callsContaining(transport.calls, psBuildAnswerIso))
}

func TestModuleprovisionChar_ProvisionVMNoSourceIsNoop(t *testing.T) {
	transport := &testPSTransport{}
	m := provisionModuleWithTransport(t, transport)
	cfg := moduleprovisionCharCfg("windows")
	cfg.Source = nil
	require.NoError(t, m.provisionVM(context.Background(), "stw-01", "stw-01", cfg))
	assert.Empty(t, transport.calls)
}

func TestModuleprovisionChar_ProvisionVMStepOrder(t *testing.T) {
	cases := []struct {
		name   string
		os     string
		gen    int
		expect []string
		absent []string
	}{
		{"windows gen2", "windows", 2,
			[]string{psSetVMFirmware, psBuildAnswerIso, psAttachDVD, psAttachDVD, psSetDVDFirstBoot, psBootKeypress}, []string{psNewSeedVHD}},
		{"linux gen1", "linux", 1,
			[]string{psNewSeedVHD, psMountSeedVHD, psCopyToSeedVHD, psAttachSeedDisk, psAttachDVD}, []string{psSetVMFirmware, psSetDVDFirstBoot, psBootKeypress}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &testPSTransport{}
			m := provisionModuleWithTransport(t, transport)
			cfg := moduleprovisionCharCfg(tc.os)
			cfg.Generation = tc.gen
			require.NoError(t, m.provisionVM(context.Background(), "stw-01", "stw-01", cfg))

			idx := 0
			for _, want := range tc.expect {
				found := false
				for ; idx < len(transport.calls); idx++ {
					if transport.calls[idx].scriptBlock == want {
						found, idx = true, idx+1
						break
					}
				}
				require.True(t, found, "step missing or out of order")
			}
			for _, a := range tc.absent {
				assert.Empty(t, callsContaining(transport.calls, a))
			}
			rec, err := m.provisionStore.GetProvision(context.Background(), "stw-01")
			require.NoError(t, err)
			assert.Equal(t, ProvisionStateInstalling, rec.State)
			assert.Equal(t, 1, rec.RetryCount)
		})
	}
}

func TestModuleprovisionChar_ProvisionVMStepFailureFailsRecord(t *testing.T) {
	// Windows gen2: call 0 firmware, 1 build ISO — fail the ISO build.
	transport := &testPSTransport{perCallErrors: []error{nil, assert.AnError}}
	m := provisionModuleWithTransport(t, transport)
	err := m.provisionVM(context.Background(), "stw-01", "stw-01", moduleprovisionCharCfg("windows"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `build answer ISO for VM "stw-01"`)
	rec, gerr := m.provisionStore.GetProvision(context.Background(), "stw-01")
	require.NoError(t, gerr)
	assert.Equal(t, ProvisionStateFailed, rec.State)
}
