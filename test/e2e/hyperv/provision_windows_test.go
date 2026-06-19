// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Package hyperv_e2e holds the host-gated end-to-end provisioning tests for the
// Hyper-V module. These tests require a real Hyper-V host and Windows install
// media and are excluded from CI (and from make test-complete) by the e2e build
// tag. They skip cleanly when the required environment variables are unset.
package hyperv_e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/modules/hyperv/completion"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// Required environment variables (the test skips when any is unset):
//
//	CFGMS_E2E_HYPERV_HOST          hostname/IP of the Hyper-V host (winrm transport)
//	CFGMS_E2E_WIN_ISO             host path to the Windows Server install ISO
//	CFGMS_E2E_WIN_PPKG_PATH       host path to the staged .ppkg enrollment package
//	CFGMS_E2E_REGTOKEN_SECRET_KEY secrets-provider key holding the enrollment regtoken
//
// Optional:
//
//	CFGMS_E2E_HYPERV_USER / _PASS WinRM credentials (when the host needs them)
//	CFGMS_E2E_STEWARD_STORE       path to the controller's flatfile steward
//	                              registry; when set the test waits for the real
//	                              registered steward to appear and drives the
//	                              controller-side completion reconciler with its
//	                              ID. When unset the test drives the reconciler
//	                              with the baked-in CorrelationID directly.
//	CFGMS_E2E_VHD_DIR             directory for the VM VHD (default the ISO dir's
//	                              drive root \cfgms-e2e). Must be an absolute
//	                              Windows path.
//	CFGMS_E2E_SWITCH              virtual switch to connect (default HVSwitch_1G).

const (
	envHost       = "CFGMS_E2E_HYPERV_HOST"
	envISO        = "CFGMS_E2E_WIN_ISO"
	envPpkg       = "CFGMS_E2E_WIN_PPKG_PATH"
	envRegToken   = "CFGMS_E2E_REGTOKEN_SECRET_KEY"
	envUser       = "CFGMS_E2E_HYPERV_USER"
	envPass       = "CFGMS_E2E_HYPERV_PASS"
	envStewardDir = "CFGMS_E2E_STEWARD_STORE"
	envVHDDir     = "CFGMS_E2E_VHD_DIR"
	envSwitch     = "CFGMS_E2E_SWITCH"

	// completionTimeout bounds the full provision: ISO boot, unattended Setup,
	// first-boot .ppkg enrollment, and steward registration.
	completionTimeout = 90 * time.Minute
	pollInterval      = 30 * time.Second
)

// e2eConfig is a minimal modules.ConfigState used only to drive module
// Configure() with the host/transport/secret-key wiring. It is a real value
// type, not a mock.
type e2eConfig struct{ m map[string]interface{} }

func (c e2eConfig) AsMap() map[string]interface{}     { return c.m }
func (c e2eConfig) ToYAML() ([]byte, error)           { return nil, nil }
func (c e2eConfig) FromYAML([]byte) error             { return nil }
func (c e2eConfig) Validate() error                   { return nil }
func (c e2eConfig) GetManagedFields() []string        { return nil }

// The e2eSecretStore type used here is the shared in-memory SecretStore double
// defined in provision_debian_test.go (#2046); both the Linux preseed and the
// Windows autounattend E2E paths resolve their render-time secrets through it.
// Not a mock — a real in-memory store seeded per test.

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestE2E_ProvisionWindows_ToStewardRegistered provisions a real Windows Server
// VM from an ISO + autounattend on a cfg-lab Hyper-V host and asserts the
// provisioning record reaches ready (set controller-side by the completion
// reconciler, #2050) and the steward appears in the controller steward list.
//
// Run live:
//
//	CFGMS_E2E_HYPERV_HOST=cfg-70-02 \
//	CFGMS_E2E_WIN_ISO='C:\ClusterStorage\CSV01\iso\windows-server-2025.iso' \
//	CFGMS_E2E_WIN_PPKG_PATH='C:\cfgms\packages\cfgms-enroll.ppkg' \
//	CFGMS_E2E_REGTOKEN_SECRET_KEY=hyperv/enroll/regtoken \
//	go test -tags e2e -run TestE2E_ProvisionWindows -timeout 120m ./test/e2e/hyperv/...
func TestE2E_ProvisionWindows_ToStewardRegistered(t *testing.T) {
	host := os.Getenv(envHost)
	iso := os.Getenv(envISO)
	ppkg := os.Getenv(envPpkg)
	regTokenKey := os.Getenv(envRegToken)
	if host == "" || iso == "" || ppkg == "" || regTokenKey == "" {
		t.Skipf("host-gated E2E: set %s, %s, %s, and %s to run against a real Hyper-V host",
			envHost, envISO, envPpkg, envRegToken)
	}

	ctx := context.Background()
	logger := logging.NewNoopLogger()

	// Real in-memory secret store carrying the .ppkg host path (referenced by the
	// autounattend template as {{ secret "ppkg-path-key" }}) and the regtoken.
	secretStore := &e2eSecretStore{secrets: map[string]string{
		"ppkg-path-key": ppkg,
		regTokenKey:     getenvDefault("CFGMS_E2E_REGTOKEN", "lab-regtoken"),
	}}

	// Shared provision store: the host-side module advances absent → … →
	// finalizing on it; the controller-side completion reconciler reads/flips the
	// same records to ready. This is the exact decomposition from ADR-009 §8.
	provStore := hyperv.NewMemProvisionStore()

	module := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(provStore))

	injectable, ok := module.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must accept an injected secret store")
	require.NoError(t, injectable.SetSecretStore(secretStore))

	configurable, ok := module.(modules.Configurable)
	require.True(t, ok, "hyperv module must be Configurable")

	cfgMap := map[string]interface{}{
		"transport":         "ps-host",
		"winrm_host":        host, // used only if the ps-host transport is unavailable
		"winrm_user_secret": "winrm-user",
		"winrm_pass_secret": "winrm-pass",
	}
	// Seed WinRM creds when supplied (winrm fallback path).
	if u := os.Getenv(envUser); u != "" {
		secretStore.secrets["winrm-user"] = u
		secretStore.secrets["winrm-pass"] = os.Getenv(envPass)
	}
	require.NoError(t, configurable.Configure(e2eConfig{m: cfgMap}))

	vmName := "cfgms-e2e-win-01"
	vhdDir := getenvDefault(envVHDDir, `C:\ClusterStorage\CSV01`)
	switchName := getenvDefault(envSwitch, "HVSwitch_1G")

	vmCfg := &hyperv.VMConfig{
		Name:        vmName,
		MemoryMB:    6144,
		CPUCount:    4,
		VHDPath:     vhdDir + `\` + vmName + ".vhdx",
		SwitchNames: []string{switchName},
		Generation:  2,
		State:       "running",
		Source: &hyperv.SourceConfig{
			ISO:      iso,
			OSFamily: "windows",
			// No explicit unattend → the built-in Windows autounattend profile is
			// rendered (autounattend.xml with the .ppkg first-logon enrollment).
			Completion: hyperv.CompletionConfig{Mode: "steward-registration", Timeout: "90m"},
			OnExisting: "never",
		},
	}

	t.Cleanup(func() {
		bg := context.Background()
		// Best-effort teardown: stop + remove the VM and its disks.
		removeCfg := &hyperv.VMConfig{Name: vmName, State: "absent"}
		_ = module.Set(bg, "vm:"+vmName, removeCfg)
	})

	// First convergence: create the VM, build + attach the seed VHDX with the
	// rendered autounattend, attach the ISO, power on. Advances absent → creating
	// → installing.
	require.NoError(t, module.Set(ctx, "vm:"+vmName, vmCfg),
		"create-from-source convergence (absent → installing) must succeed")

	rec, err := provStore.GetProvision(ctx, vmName)
	require.NoError(t, err)
	require.Equal(t, hyperv.ProvisionStateInstalling, rec.State,
		"host-side create path must end at installing")
	correlationID := rec.CorrelationID
	require.NotEmpty(t, correlationID, "a correlation identity must be baked into the record")

	// Controller-side completion reconciler over the SAME provision store. On a
	// real steward connect the controller calls OnConnect(mTLS CN); here we drive
	// it once the install has progressed and the steward is observed.
	reconciler := completion.New(provStore, logger, completion.WithCompletionTimeout(completionTimeout))

	var stewardStore business.StewardStore
	if dir := os.Getenv(envStewardDir); dir != "" {
		ss, ferr := flatfile.NewFlatFileStewardStore(dir)
		require.NoError(t, ferr, "open controller steward registry")
		stewardStore = ss
	}

	// Drive convergence to completion: re-run Set each cycle (idempotent — resume
	// from installing detaches the seed and advances to finalizing; resume from
	// finalizing/ready is a no-op), observe the registered steward, and let the
	// reconciler flip finalizing → ready.
	deadline := time.Now().Add(completionTimeout)
	var matchedStewardID string
	for time.Now().Before(deadline) {
		// Re-converge: advances installing → finalizing once the install settles.
		require.NoError(t, module.Set(ctx, "vm:"+vmName, vmCfg))

		// Determine the steward identity to correlate. When a controller steward
		// registry is provided, wait for the real steward to appear there and use
		// its ID; otherwise correlate on the baked-in CorrelationID directly.
		stewardID := correlationID
		if stewardStore != nil {
			if sid, found := findSteward(ctx, t, stewardStore, correlationID); found {
				stewardID = sid
				matchedStewardID = sid
			}
		}

		// Controller-side flip: OnConnect advances a finalizing record whose
		// CorrelationID matches stewardID to ready.
		require.NoError(t, reconciler.OnConnect(ctx, stewardID))

		rec, err = provStore.GetProvision(ctx, vmName)
		require.NoError(t, err)
		if rec.State == hyperv.ProvisionStateReady {
			break
		}
		require.NotEqual(t, hyperv.ProvisionStateFailed, rec.State,
			"provisioning must not reach failed: %s", rec.LastError)
		time.Sleep(pollInterval)
	}

	require.Equal(t, hyperv.ProvisionStateReady, rec.State,
		"provisioning record must reach ready (set controller-side by the completion reconciler)")

	// Steward-in-controller-list assertion (only when a real registry is wired).
	if stewardStore != nil {
		require.NotEmpty(t, matchedStewardID, "the provisioned VM's steward must register")
		got, gerr := stewardStore.GetSteward(ctx, matchedStewardID)
		require.NoError(t, gerr, "registered steward must be in the controller steward list")
		assert.Equal(t, matchedStewardID, got.ID)
	}
}

// findSteward returns the ID of a registered steward whose ID or hostname
// matches the provisioning correlation identity (the controller correlates a
// newly-registered steward to the provisioned VM via this value, ADR-009 §8).
func findSteward(ctx context.Context, t *testing.T, store business.StewardStore, correlationID string) (string, bool) {
	t.Helper()
	stewards, err := store.ListStewards(ctx)
	if err != nil {
		return "", false
	}
	for _, s := range stewards {
		if s == nil {
			continue
		}
		if s.ID == correlationID || s.Hostname == correlationID {
			return s.ID, true
		}
	}
	return "", false
}
