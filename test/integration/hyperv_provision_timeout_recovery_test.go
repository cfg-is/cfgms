// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3804 (Epic #3799): end-to-end regression proving the deadline-decoupling
// (#3801), bounded seed-phase repair (#3802), and retry-exhausted-visibility
// (#3803) stories compose correctly for the scenario that motivated the epic — a
// cloud-image hyperv.vm provision that gets deadline-killed mid seed-build:
//
//	(a) a legitimately long-running repair is no longer truncated by
//	    commands.Handler's 30s-unless-overridden command deadline;
//	(b) a seed-phase-failed VM within its retry budget is repaired automatically
//	    on a later convergence pass;
//	(c) once retry-exhausted, that terminal state is visible in the resulting
//	    ConfigStatusReport, not just a repeating steward-local log line.
//
// This is deliberately cross-component (commands.Handler + execution.Executor +
// the real features/modules/hyperv module) rather than a single package's unit
// test, so it lives in test/integration/ per CLAUDE.md's test-taxonomy table. It
// is the platform-independent half of the story; the part that must exercise a
// real Windows Mount-VHD kill/dismount against pstransport_windows.go lives in
// the go:build windows sibling file (hyperv_provision_timeout_recovery_windows_test.go).
//
// # What is real here
//
// The module under test is the real one: hyperv.New builds the production
// hypervModule, and every decision these tests assert on — whether an existing
// VM's failed seed-phase record is within its retry budget, whether that means
// re-invoking the seed build or returning *modules.RetryExhaustedError — is made
// by the real applySourceGated code, reached through the real
// commands.Handler → execution.Executor.ApplyConfiguration → ConfigStatusReport
// pipeline. Nothing in this file re-implements or mirrors that decision, so it
// cannot drift away from the module's behavior: if applySourceGated's branch
// condition changes, these tests change with it or fail.
//
// The only stand-in is the Hyper-V HOST itself, injected at the module's own
// exported host-execution boundary (hyperv.HostCommandTransport, applied with
// hyperv.WithHostCommandTransport). Driving a live host instead would require
// Hyper-V admin rights on Windows or a reachable WinRM host on any platform,
// neither of which exists on a Linux CI runner — and the real-host coverage is
// exactly what the go:build windows sibling provides.
//
// The retry BUDGET is not mirrored either: both fixtures declare source.retry_max
// in the resource config, so the module computes exhaustion from the authored
// value (SourceConfig.retryBudget) rather than from a constant copied out of the
// hyperv package.
package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/steward/commands"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const (
	// hypervModuleRef is the production module reference shape for a VM
	// resource: bundle "hyperv" (what the factory loads, ADR-006) plus the
	// ".vm" resource-type selector the executor turns into the "vm:<name>"
	// resourceID the module's Get/Set expect.
	hypervModuleRef = "hyperv.vm"
	hypervBundle    = "hyperv"

	seedRepairVMName  = "seed-repair-vm"
	seedRepairVHDPath = `C:\VMs\seed-repair-vm.vhdx`
	seedRepairISOPath = `C:\VMs\iso\debian-12.iso`
	seedRepairSwitch  = "HVSwitch_1G"
)

// scriptedHypervHost stands in for the Hyper-V HOST — the external system on the
// far side of the module's own exported host-execution boundary
// (hyperv.HostCommandTransport). It is not a stand-in for any CFGMS component:
// the module issuing these commands, and every decision it makes about them, is
// the real one.
//
// The host answers every command with its current VM inventory in the JSON shape
// the module's Get-VM script emits (the module parses that answer only for its
// VM read; the mutation commands ignore output, exactly as a real host's do),
// accepts every mutation, and powers the VM on when it is told to. slowCommand /
// slowFor make one named command genuinely slow — a real seed build against a
// real host takes minutes, which is the whole point of AC (a). failCmd /
// failRemaining make one named command fail for a bounded number of calls, used
// by buildSeedPhaseFailedFixture (Issue #3804 AC2) to drive the real module's
// own provisionVM/failProvision path into a genuine seed-phase failure instead
// of hand-constructing a ProvisionRecord. created tracks whether New-VM has
// actually been issued yet, so Get-VM correctly answers "not found" until the
// real createVM call has run — required for the fixture-building "VM absent"
// pass to reach createVM+provisionVM in the first place.
type scriptedHypervHost struct {
	mu            sync.Mutex
	calls         []string
	created       bool
	vmState       string
	slowCmd       string
	slowFor       time.Duration
	slowSeen      int
	failCmd       string
	failRemaining int
}

var _ hyperv.HostCommandTransport = (*scriptedHypervHost)(nil)

func (h *scriptedHypervHost) ExecutePS(ctx context.Context, psCommand string, _ map[string]string) (string, error) {
	h.mu.Lock()
	h.calls = append(h.calls, psCommand)

	if h.failRemaining > 0 && h.failCmd != "" && strings.Contains(psCommand, h.failCmd) {
		h.failRemaining--
		h.mu.Unlock()
		return "", fmt.Errorf("scripted host: forced failure of %s", h.failCmd)
	}

	slow := h.slowFor > 0 && h.slowCmd != "" && strings.Contains(psCommand, h.slowCmd)
	if slow {
		h.slowSeen++
	}
	// psCreateVM issues "New-VM -Name $Name ..." — matched with the trailing
	// space so it never collides with New-VMSwitch (unused by these VM-only
	// tests, but matched precisely regardless).
	if strings.Contains(psCommand, "New-VM -Name") {
		h.created = true
	}
	h.mu.Unlock()

	if slow {
		select {
		case <-time.After(h.slowFor):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	// A powered-on VM stays powered on for every subsequent read.
	if strings.Contains(psCommand, "Start-VM") {
		h.mu.Lock()
		h.vmState = "Running"
		h.mu.Unlock()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.created {
		return `{"found":false}`, nil
	}
	return `{"found":true,"Name":"` + seedRepairVMName + `","MemoryStartupBytes":4294967296,` +
		`"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\` + seedRepairVMName + `.vhdx",` +
		`"ConfigurationLocation":"C:\\VMs",` +
		`"SwitchName":"` + seedRepairSwitch + `","SwitchNames":["` + seedRepairSwitch + `"],` +
		`"State":"` + h.vmState + `"}`, nil
}

// countCalls returns how many commands the host was asked to run that contain
// the given cmdlet name.
func (h *scriptedHypervHost) countCalls(cmdlet string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, call := range h.calls {
		if strings.Contains(call, cmdlet) {
			n++
		}
	}
	return n
}

// hypervHostDetector reports that this machine is a Hyper-V host. It implements
// the module's exported HypervDetector host-capability probe — the same
// injection point production uses to supply NewDefaultDetector — so the real
// module runs its real code path against the scripted host above on a runner
// that has no Hyper-V role. It decides nothing about VM convergence.
type hypervHostDetector struct{}

func (hypervHostDetector) IsHypervHost(_ context.Context) (bool, error) { return true, nil }

var _ hyperv.HypervDetector = hypervHostDetector{}

// buildSeedPhaseFailedFixture builds the "already failed during the seed
// phase, attemptCount attempts made" starting fixture by driving the REAL
// module through its own createVM -> provisionVM -> failProvision code path
// attemptCount times, then reading the resulting record back from the real
// hyperv.ProvisionStore — never a hand-built ProvisionRecord literal that
// could silently drift from what production actually writes (Issue #3804
// AC2).
//
// It does this against a scripted host whose New-VHD command is set to fail
// for exactly attemptCount calls: the first pass finds the VM absent (the
// host has not yet seen "New-VM -Name", so Get-VM answers not-found) and goes
// through applySourceGated's !vmExists branch — createVM (a real New-VM call
// the host accepts) followed by provisionVM, which fails at the scripted
// New-VHD. Every subsequent pass finds the VM existing (createVM already ran)
// and re-enters provisionVM through the real seed-phase-failure repair gate,
// consuming one more attempt from a budget declared generous enough
// (attemptCount+5) that the fixture-building passes themselves never trip
// retry-exhaustion. The returned host has its scripted failure and call log
// cleared before return — New-VHD behaves normally again, and callers that
// want to assert on calls made by the scenario under test start from a clean
// slate — but retains the "VM exists" state learned while building the
// fixture, so a fresh module instance wired to the same store+host picks up
// exactly where fixture-building left off, the same way a real steward's
// convergence loop would across two passes.
func buildSeedPhaseFailedFixture(t *testing.T, vmName string, attemptCount int) (hyperv.ProvisionStore, *scriptedHypervHost) {
	t.Helper()
	require.Positive(t, attemptCount, "fixture requires at least one real failed attempt")

	store := hyperv.NewMemProvisionStore()
	host := &scriptedHypervHost{vmState: "Off", failCmd: "New-VHD", failRemaining: attemptCount}
	exec := newSeedRepairExecutor(t, newRealHypervModule(t, store, host), 90)

	// A retry budget comfortably larger than attemptCount so these
	// fixture-building passes never themselves trip the retry-exhausted
	// branch, which would stop re-invoking provisionVM short of attemptCount
	// real failures.
	configYAML := buildSeedRepairConfigYAML(t, attemptCount+5)

	for i := 0; i < attemptCount; i++ {
		report, applyErr := exec.ApplyConfiguration(context.Background(), configYAML, "v-fixture-build")
		require.NoError(t, applyErr)
		require.NotNil(t, report)
	}

	record, err := store.GetProvision(context.Background(), vmName)
	require.NoError(t, err)
	require.Equal(t, hyperv.ProvisionStateFailed, record.State,
		"fixture-building must leave the record failed")
	require.Equal(t, hyperv.ProvisionStateCreating, record.FailedFrom,
		"fixture-building must fail during the seed/create phase")
	require.Equal(t, attemptCount, record.RetryCount,
		"fixture-building must consume exactly attemptCount real attempts")

	host.mu.Lock()
	host.calls = nil
	host.failCmd = ""
	host.failRemaining = 0
	host.mu.Unlock()

	return store, host
}

// newRealHypervModule builds the production hyperv module over the supplied
// provisioning store and scripted host. Both injection points are the module's
// own exported options; no unexported behavior is reached or reproduced.
func newRealHypervModule(t *testing.T, store hyperv.ProvisionStore, host *scriptedHypervHost) modules.Module {
	t.Helper()
	mod := hyperv.New(hypervHostDetector{},
		hyperv.WithProvisionStore(store),
		hyperv.WithHostCommandTransport(host))

	injectable, ok := mod.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must implement modules.SecretStoreInjectable")
	// The module requires an injected SecretStore before it will render a seed
	// answer file, whether or not the resolved profile references any secret.
	require.NoError(t, injectable.SetSecretStore(newTestSecretStore()))
	return mod
}

// newSeedRepairExecutor wires the real steward factory + executor around the real
// hyperv module, registered under the production bundle name so the executor
// resolves it exactly as it does at runtime.
func newSeedRepairExecutor(t *testing.T, mod modules.Module, moduleCallTimeoutSec int) *execution.Executor {
	t.Helper()
	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.NewNoopLogger())
	f.RegisterModule(hypervBundle, mod)

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.NewNoopLogger(),
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: moduleCallTimeoutSec,
	})
	require.NoError(t, err)
	return exec
}

// newSyncConfigTestHandler builds a real commands.Handler and registers a
// CommandSyncConfig CommandFunc that mirrors the production decoupling fix
// (features/steward/client/client_transport.go, Issue #3801): it derives its
// own context.Background() for executor.ApplyConfiguration rather than reusing
// executeCommand's 30s-unless-overridden ctx, so the executor's own
// ModuleCallTimeoutSec is the real effective budget. This is a deliberately
// narrow re-creation of that one contract — not the full syncConfigNow
// pipeline (signed proto config, gRPC data-plane fetch, monitor restart), which
// features/steward/client/sync_config_deadline_test.go already covers as a
// dedicated package-internal regression.
func newSyncConfigTestHandler(t *testing.T, exec *execution.Executor) *commands.Handler {
	t.Helper()
	handler, err := commands.New(&commands.Config{
		StewardID: "steward-hyperv-timeout-recovery",
		OnStatus:  func(_ context.Context, _ *cpTypes.Event) {},
		Logger:    logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	handler.RegisterHandler(cpTypes.CommandSyncConfig, func(_ context.Context, cmd *cpTypes.Command) error {
		configYAML, ok := cmd.Params["config_yaml"].([]byte)
		if !ok {
			return assert.AnError
		}
		// Issue #3801: an independent background context, not executeCommand's
		// ctx — this is the exact property under test.
		applyCtx := context.Background()
		_, applyErr := exec.ApplyConfiguration(applyCtx, configYAML, "v-timeout-recovery-1")
		return applyErr
	})
	return handler
}

func dispatchSyncConfig(t *testing.T, handler *commands.Handler, configYAML []byte) time.Duration {
	t.Helper()
	cmd := &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "cmd-hyperv-timeout-recovery",
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-hyperv-timeout-recovery",
			Timestamp: time.Now(),
			Params:    map[string]interface{}{"config_yaml": configYAML},
		},
	}
	start := time.Now()
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))
	handler.Wait()
	return time.Since(start)
}

// buildSeedRepairConfigYAML marshals a StewardConfig carrying one real
// hyperv.vm resource with a source: block (Issue #3804 AC) and an explicitly
// declared retry_max, so the module derives the retry budget from authored
// config rather than this test assuming the built-in default.
func buildSeedRepairConfigYAML(t *testing.T, retryMax int) []byte {
	t.Helper()
	cfg := stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: "steward-hyperv-timeout-recovery"},
		Resources: []stewardtypes.ResourceConfig{
			{
				Name:   seedRepairVMName,
				Module: hypervModuleRef,
				Config: map[string]interface{}{
					"name":        seedRepairVMName,
					"memory_mb":   4096,
					"cpu_count":   2,
					"generation":  2,
					"vhd_path":    seedRepairVHDPath,
					"state":       "running",
					"switch_name": seedRepairSwitch,
					"source": map[string]interface{}{
						"iso":         seedRepairISOPath,
						"os_family":   "linux",
						"on_existing": "never",
						"retry_max":   retryMax,
						"completion": map[string]interface{}{
							"mode":    "steward-registration",
							"timeout": "60m",
						},
					},
				},
			},
		},
	}
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return out
}

// TestHypervVMSeedRepair_SlowRetry_SucceedsPastOld30sCeiling is the [REQUIRED
// TEST] for Issue #3804 AC (a)+(b): a hyperv.vm resource whose provisioning
// record failed during the seed phase, still within its declared retry budget, is
// repaired by the real module on a later convergence pass — and because the seed
// rebuild against the host genuinely takes longer than the old 30s executeCommand
// ceiling, the repair runs to completion instead of being killed mid-flight.
func TestHypervVMSeedRepair_SlowRetry_SucceedsPastOld30sCeiling(t *testing.T) {
	// Comfortably past the old 30s ceiling; comfortably under the executor's
	// configured 90s ModuleCallTimeoutSec below.
	const seedBuildDuration = 32 * time.Second

	// One prior failed attempt, built via the real module's own
	// createVM/provisionVM/failProvision path (Issue #3804 AC2) — against a
	// declared budget of 3 below, so the real applySourceGated must repair
	// rather than surface-and-wait.
	store, host := buildSeedPhaseFailedFixture(t, seedRepairVMName, 1)
	// New-VHD appears only in the seed-build command (psNewSeedVHD); the VM
	// itself already exists, so nothing else creates a disk on this pass.
	host.slowCmd = "New-VHD"
	host.slowFor = seedBuildDuration

	exec := newSeedRepairExecutor(t, newRealHypervModule(t, store, host), 90)
	handler := newSyncConfigTestHandler(t, exec)

	elapsed := dispatchSyncConfig(t, handler, buildSeedRepairConfigYAML(t, 3))

	require.GreaterOrEqual(t, elapsed, seedBuildDuration,
		"the repair must actually wait out the full seed build, not be cut short by the old 30s ceiling")
	assert.Equal(t, 1, host.slowSeen, "the slow seed build must have been attempted exactly once")
	assert.Positive(t, host.countCalls("Add-VMHardDiskDrive"),
		"a repair must re-attach the rebuilt seed disk — work that only happens AFTER the slow seed build returns")
	assert.Positive(t, host.countCalls("Start-VM"),
		"a completed repair powers the VM on, the last step of the seed/create phase")
	assert.Zero(t, host.countCalls("New-VM"),
		"the VM already exists — a repair must never recreate it")
	assert.Zero(t, host.countCalls("Remove-VM"),
		"a repair must never destroy the existing VM")

	record, err := store.GetProvision(context.Background(), seedRepairVMName)
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateInstalling, record.State,
		"a repair that survived the full seed build advances the record to installing; a truncated one would be left at creating or failed")
	assert.Equal(t, 2, record.RetryCount,
		"the repair must have consumed exactly one more attempt from the declared budget")
}

// TestHypervVMSeedRepair_RetryExhausted_ReachesConfigStatusReport is the
// [REQUIRED TEST] for Issue #3804 AC (c): a hyperv.vm resource whose
// provisioning record has exhausted its declared seed-phase retry budget
// produces a distinct, queryable RETRY_EXHAUSTED status in the
// ConfigStatusReport returned by executor.ApplyConfiguration — not a
// repeating, indistinguishable "verification failed" — with the classification
// originating in the real module's own retry-exhausted branch.
func TestHypervVMSeedRepair_RetryExhausted_ReachesConfigStatusReport(t *testing.T) {
	// Two prior failed attempts, built via the real module's own
	// createVM/provisionVM/failProvision path (Issue #3804 AC2), against a
	// declared budget of 2 below: exhausted.
	store, host := buildSeedPhaseFailedFixture(t, seedRepairVMName, 2)
	exec := newSeedRepairExecutor(t, newRealHypervModule(t, store, host), 90)

	// Drive ApplyConfiguration directly (not through commands.Handler) so this
	// test can inspect the returned *cpTypes.ConfigStatusReport — the dispatch
	// path itself (proving the 30s ceiling doesn't apply) is what the sibling
	// test above already covers.
	//
	// ApplyConfiguration's function-level error return only ever carries a
	// configuration-parse failure — the retry-exhausted classification (like
	// every other per-resource outcome) rides the *report* it returns
	// alongside a nil error, not this error return.
	report, applyErr := exec.ApplyConfiguration(context.Background(), buildSeedRepairConfigYAML(t, 2), "v-retry-exhausted-1")
	require.NoError(t, applyErr)
	require.NotNil(t, report)

	assert.Equal(t, "RETRY_EXHAUSTED", report.Status,
		"the overall report status must surface the retry-exhausted classification, not ERROR")

	moduleStatus, ok := report.Modules[hypervModuleRef]
	require.True(t, ok, "the retry-exhausted resource's module must appear in the report")
	assert.Equal(t, "RETRY_EXHAUSTED", moduleStatus.Status,
		"a retry-exhausted resource must produce a distinct RETRY_EXHAUSTED module status, not ERROR")

	require.Len(t, report.ApplyOutcomes, 1)
	assert.Equal(t, "retry_exhausted", report.ApplyOutcomes[0].Status,
		"the apply-outcome record must classify this as retry_exhausted, not failed")
	assert.Equal(t, seedRepairVMName, report.ApplyOutcomes[0].ResourceID)

	// Surface-and-wait: the exhausted branch performs no host work at all and
	// leaves the record untouched for an operator.
	assert.Zero(t, host.countCalls("New-VHD"),
		"an exhausted budget must not trigger another seed build")
	assert.Zero(t, host.countCalls("Start-VM"),
		"a VM with no working seed must never be powered on")

	record, err := store.GetProvision(context.Background(), seedRepairVMName)
	require.NoError(t, err)
	assert.Equal(t, hyperv.ProvisionStateFailed, record.State)
	assert.Equal(t, 2, record.RetryCount, "retry-exhausted must not consume a further attempt")
}

// testSecretStore is a minimal, real (non-mock) in-memory implementation of the
// secretsif.SecretStore provider contract, shared by this file and its
// windows-tagged sibling. The hyperv module requires an injected SecretStore
// unconditionally — to reach Configure at all, and to render a seed answer file
// regardless of whether the resolved profile references any {{ secret "key" }}
// placeholder — so a real, correct implementation of the interface is required
// to drive the module. The built-in Linux preseed profile these tests drive (no
// source.unattend override) looks up no key today, but the store must still
// behave correctly if that changes.
type testSecretStore struct {
	mu   sync.Mutex
	data map[string]*secretsif.Secret
}

func newTestSecretStore() *testSecretStore {
	return &testSecretStore{data: make(map[string]*secretsif.Secret)}
}

func (s *testSecretStore) StoreSecret(_ context.Context, req *secretsif.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	version := 1
	if existing, ok := s.data[req.Key]; ok {
		version = existing.Version + 1
	}
	s.data[req.Key] = &secretsif.Secret{
		Key: req.Key, Value: req.Value, Metadata: req.Metadata, Tags: req.Tags,
		Version: version, CreatedAt: now, UpdatedAt: now,
		CreatedBy: req.CreatedBy, UpdatedBy: req.CreatedBy,
		TenantID: req.TenantID, Description: req.Description,
	}
	return nil
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.data[key]
	if !ok {
		return nil, secretsif.ErrSecretNotFound
	}
	copySecret := *secret
	return &copySecret, nil
}

func (s *testSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *testSecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*secretsif.SecretMetadata, 0, len(s.data))
	for _, secret := range s.data {
		out = append(out, &secretsif.SecretMetadata{
			Key: secret.Key, Metadata: secret.Metadata, Tags: secret.Tags,
			Version: secret.Version, CreatedAt: secret.CreatedAt, UpdatedAt: secret.UpdatedAt,
			CreatedBy: secret.CreatedBy, UpdatedBy: secret.UpdatedBy,
			TenantID: secret.TenantID, Description: secret.Description,
		})
	}
	return out, nil
}

func (s *testSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	out := make(map[string]*secretsif.Secret, len(keys))
	for _, key := range keys {
		secret, err := s.GetSecret(ctx, key)
		if err == nil {
			out[key] = secret
		}
	}
	return out, nil
}

func (s *testSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *testSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expectedVersion int, req *secretsif.SecretRequest) (int, bool, error) {
	s.mu.Lock()
	existing, ok := s.data[key]
	currentVersion := 0
	if ok {
		currentVersion = existing.Version
	}
	s.mu.Unlock()
	if currentVersion != expectedVersion {
		return currentVersion, false, nil
	}
	if err := s.StoreSecret(ctx, req); err != nil {
		return currentVersion, false, err
	}
	updated, err := s.GetSecret(ctx, key)
	if err != nil {
		return currentVersion, false, err
	}
	return updated.Version, true, nil
}

func (s *testSecretStore) GetSecretVersion(ctx context.Context, key string, _ int) (*secretsif.Secret, error) {
	return s.GetSecret(ctx, key)
}

func (s *testSecretStore) ListSecretVersions(_ context.Context, key string) ([]*secretsif.SecretVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.data[key]
	if !ok {
		return nil, secretsif.ErrSecretNotFound
	}
	return []*secretsif.SecretVersion{{Version: secret.Version, CreatedAt: secret.CreatedAt, CreatedBy: secret.CreatedBy}}, nil
}

func (s *testSecretStore) GetSecretMetadata(ctx context.Context, key string) (*secretsif.SecretMetadata, error) {
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return nil, err
	}
	return &secretsif.SecretMetadata{
		Key: secret.Key, Metadata: secret.Metadata, Tags: secret.Tags,
		Version: secret.Version, CreatedAt: secret.CreatedAt, UpdatedAt: secret.UpdatedAt,
		CreatedBy: secret.CreatedBy, UpdatedBy: secret.UpdatedBy,
		TenantID: secret.TenantID, Description: secret.Description,
	}, nil
}

func (s *testSecretStore) UpdateSecretMetadata(_ context.Context, key string, metadata map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.data[key]
	if !ok {
		return secretsif.ErrSecretNotFound
	}
	secret.Metadata = metadata
	secret.UpdatedAt = time.Now()
	return nil
}

func (s *testSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	s.mu.Lock()
	existing, ok := s.data[key]
	s.mu.Unlock()
	req := &secretsif.SecretRequest{Key: key, Value: newValue}
	if ok {
		req.TenantID = existing.TenantID
		req.Metadata = existing.Metadata
		req.Tags = existing.Tags
	}
	return s.StoreSecret(ctx, req)
}

func (s *testSecretStore) ExpireSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.data[key]
	if !ok {
		return secretsif.ErrSecretNotFound
	}
	past := time.Now().Add(-time.Second)
	secret.ExpiresAt = &past
	return nil
}

func (s *testSecretStore) HealthCheck(_ context.Context) error { return nil }
func (s *testSecretStore) Close() error                        { return nil }

var _ secretsif.SecretStore = (*testSecretStore)(nil)
