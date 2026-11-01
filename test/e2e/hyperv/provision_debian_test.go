// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build e2e

// Package hyperv_e2e contains the host-gated end-to-end provisioning tests for
// the Hyper-V create-from-source path (ADR-009). These tests provision REAL
// virtual machines on a REAL Hyper-V host and therefore:
//
//   - are gated behind the `e2e` build tag (excluded from `make test-complete`
//     and CI, which never build with `-tags e2e`), and
//   - skip cleanly (t.Skip) when the required host/env vars are not set.
//
// They run only on the cfg-lab Hyper-V host where the operator stages the
// Debian 12 ISO and the registration-token secret. No mocks: the real hyperv
// module drives the real PowerShell-host transport, and the real controller-side
// completion reconciler (#2050) — wired over the SAME provision store the module
// writes — flips the record to ready when the installed steward registers.
package hyperv_e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/modules/hyperv/completion"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// Env vars that gate and parameterise the live provisioning E2E (ADR-009 §8
// implementation notes). All but the controller URL are required; the test
// skips when any required one is unset so CI and non-host runs never fail.
const (
	envHypervHost      = "CFGMS_E2E_HYPERV_HOST"          // Hyper-V host name/IP (gate)
	envLinuxISO        = "CFGMS_E2E_LINUX_ISO"            // host path to the Debian 12 ISO (gate)
	envRegTokenSecret  = "CFGMS_E2E_REGTOKEN_SECRET_KEY"  // SecretStore key for the registration token (gate)
	envRegTokenValue   = "CFGMS_E2E_REGTOKEN_VALUE"       // registration token value to seed into the store
	envUserPwdCrypted  = "CFGMS_E2E_USER_PWD_CRYPTED"     // crypted preseed user password
	envVHDPath         = "CFGMS_E2E_LINUX_VHD_PATH"       // host path for the new VM's primary VHD
	envSwitchName      = "CFGMS_E2E_SWITCH_NAME"          // external vSwitch to attach
	envControllerURL   = "CFGMS_E2E_CONTROLLER_URL"       // controller admin API base URL (optional)
	envControllerToken = "CFGMS_E2E_CONTROLLER_API_TOKEN" // bearer token for the admin API (optional)
)

// e2eSecretStore is a minimal in-memory SecretStore seeded with the secret
// values the preseed render resolves at provisioning time. It is a real store
// (not a mock): GetSecret performs an ordinary map lookup. Secret VALUES are
// supplied by the operator via env vars and never logged.
type e2eSecretStore struct{ secrets map[string]string }

func (s *e2eSecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsif.ErrSecretNotFound
	}
	return &secretsif.Secret{Key: key, Value: v}, nil
}
func (s *e2eSecretStore) StoreSecret(_ context.Context, _ *secretsif.SecretRequest) error { return nil }
func (s *e2eSecretStore) CompareAndSwapSecret(_ context.Context, _ string, _ int, _ *secretsif.SecretRequest) (int, bool, error) {
	return 1, true, nil
}
func (s *e2eSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *e2eSecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *e2eSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsif.Secret, error) {
	return nil, nil
}
func (s *e2eSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsif.SecretRequest) error {
	return nil
}
func (s *e2eSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, secretsif.ErrSecretNotFound
}
func (s *e2eSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}
func (s *e2eSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, secretsif.ErrSecretNotFound
}
func (s *e2eSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *e2eSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *e2eSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *e2eSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *e2eSecretStore) Close() error                                             { return nil }

// e2eConfigState wraps the VM config map as a modules.ConfigState.
type e2eConfigState map[string]interface{}

func (c e2eConfigState) AsMap() map[string]interface{} { return map[string]interface{}(c) }
func (c e2eConfigState) ToYAML() ([]byte, error)       { return nil, nil }
func (c e2eConfigState) FromYAML(_ []byte) error       { return nil }
func (c e2eConfigState) Validate() error               { return nil }
func (c e2eConfigState) GetManagedFields() []string    { return nil }

// requireEnv returns the value of key, or skips the test when it is unset. Used
// for the gating vars so the E2E is silently skipped in CI / off-host runs.
func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set — live Hyper-V host + Debian 12 ISO required for this E2E; skipping", key)
	}
	return v
}

// TestE2E_ProvisionDebian_ToStewardRegistered provisions a real Debian 12 VM
// from an ISO + the built-in preseed profile and asserts the provisioning record
// reaches `ready` — the controller-side transition (#2050) that fires when the
// installed steward registers and the completion reconciler matches its mTLS CN
// to the record's CorrelationID. The test never polls the steward directly
// (ADR-009 §8): readiness is asserted via the provision record, and the steward
// is confirmed via the controller's registered-steward list.
func TestE2E_ProvisionDebian_ToStewardRegistered(t *testing.T) {
	// ── Gate: skip cleanly unless the live host env is configured. ──
	hostName := requireEnv(t, envHypervHost)
	isoPath := requireEnv(t, envLinuxISO)
	regTokenKey := requireEnv(t, envRegTokenSecret)
	t.Logf("E2E provisioning Debian 12 on Hyper-V host %q from ISO %q", hostName, isoPath)

	vhdPath := os.Getenv(envVHDPath)
	if vhdPath == "" {
		vhdPath = `C:\ClusterStorage\CSV01\cfgms-e2e-debian.vhdx`
	}
	switchName := os.Getenv(envSwitchName)
	if switchName == "" {
		switchName = "HVSwitch_1G"
	}

	const vmName = "cfgms-e2e-debian"

	ctx := context.Background()

	// ── Real secret store seeded with the values the preseed resolves. ──
	store := &e2eSecretStore{secrets: map[string]string{
		regTokenKey:                           os.Getenv(envRegTokenValue),
		"hyperv/enroll/regtoken":              os.Getenv(envRegTokenValue),
		"hyperv/enroll/user-password-crypted": os.Getenv(envUserPwdCrypted),
	}}

	// ── Shared provision store: the module WRITES it; the controller-side
	// completion reconciler READS/UPDATES it. This is exactly the real
	// controller wiring (features/controller/server/server.go #2050). ──
	provisionStore := hyperv.NewMemProvisionStore()
	reconciler := completion.New(provisionStore, logging.NewNoopLogger())

	// ── Real hyperv module over the real PowerShell-host transport. ──
	mod := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(provisionStore))
	injectable, ok := mod.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must accept a SecretStore")
	require.NoError(t, injectable.SetSecretStore(store))

	configurable, ok := mod.(modules.Configurable)
	require.True(t, ok, "hyperv module must be Configurable")
	require.NoError(t, configurable.Configure(e2eConfigState{
		"transport": "ps-host",
		"tenant_id": "e2e",
	}), "configure hyperv module against the local PS host")

	// ── Cleanup: remove the VM, the seed VHDX, and the primary VHD. ──
	t.Cleanup(func() {
		bg := context.Background()
		// state:absent drives the module's delete path (stop + remove VM).
		_ = mod.(modules.Module).Set(bg, "vm:"+vmName, e2eConfigState{
			"name":     vmName,
			"state":    "absent",
			"vhd_path": vhdPath,
		})
	})

	vmConfig := e2eConfigState{
		"name":        vmName,
		"memory_mb":   4096,
		"cpu_count":   2,
		"vhd_path":    vhdPath,
		"generation":  2,
		"state":       "running",
		"switch_name": switchName,
		"source": map[string]interface{}{
			"iso":       isoPath,
			"os_family": "linux",
			// No unattend reference → the built-in Debian 12 preseed profile.
			"completion": map[string]interface{}{
				"mode":    "steward-registration",
				"timeout": "90m",
			},
			"on_existing": "never",
		},
	}

	// ── Drive the create-from-source path: create VM, build+attach seed +
	// ISO, power on, record → installing. ──
	require.NoError(t, mod.(modules.Module).Set(ctx, "vm:"+vmName, vmConfig),
		"create-from-source apply must succeed")

	rec, err := provisionStore.GetProvision(ctx, vmName)
	require.NoError(t, err, "a provisioning record must exist after the create apply")
	require.Equal(t, hyperv.ProvisionStateInstalling, rec.State,
		"host-side create must end at installing")
	correlationID := rec.CorrelationID
	require.NotEmpty(t, correlationID, "record must carry a CorrelationID")

	// ── Converge to ready within the 90-minute timeout. Each cycle:
	//   1. re-apply (drives installing → finalizing once the install settles),
	//   2. when a steward whose CN matches the CorrelationID appears in the
	//      controller's registered-steward list, invoke the REAL completion
	//      reconciler (the controller's OnConnect path) to flip the record,
	//   3. check the shared store for `ready`. ──
	deadline := time.Now().Add(90 * time.Minute)
	stewardRegistered := false
	for time.Now().Before(deadline) {
		// Convergence cycle: advance installing → finalizing when settled.
		_ = mod.(modules.Module).Set(ctx, "vm:"+vmName, vmConfig)

		if stewardInControllerList(t, correlationID) {
			stewardRegistered = true
			// Drive the real reconciler exactly as the controller's gRPC
			// OnConnect hook does, with the steward's mTLS CN.
			require.NoError(t, reconciler.OnConnect(ctx, correlationID),
				"completion reconciler OnConnect must not error")
		}

		cur, getErr := provisionStore.GetProvision(ctx, vmName)
		require.NoError(t, getErr)
		if cur.State == hyperv.ProvisionStateReady {
			break
		}
		if cur.State == hyperv.ProvisionStateFailed {
			t.Fatalf("provisioning failed: %s", cur.LastError)
		}

		time.Sleep(30 * time.Second)
	}

	final, err := provisionStore.GetProvision(ctx, vmName)
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateReady, final.State,
		"provisioning record must reach ready (set controller-side by the completion reconciler, #2050)")
	assert.True(t, stewardRegistered,
		"the provisioned steward must appear in the controller's registered-steward list")
}

// stewardInControllerList reports whether a steward whose ID/CN matches
// correlationID appears in the controller's registered-steward list. When the
// controller URL is not configured it returns false (the test continues
// polling); the operator sets CFGMS_E2E_CONTROLLER_URL + token on the live host
// so the registered-steward assertion is exercised end to end.
func stewardInControllerList(t *testing.T, correlationID string) bool {
	t.Helper()
	baseURL := os.Getenv(envControllerURL)
	if baseURL == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/api/v1/stewards", nil)
	if err != nil {
		return false
	}
	if token := os.Getenv(envControllerToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// The list handler wraps results in a success envelope; decode loosely and
	// scan any steward id/CN for a correlation match.
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	for _, s := range payload.Data {
		if strings.EqualFold(s.ID, correlationID) {
			return true
		}
	}
	return false
}
