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
// features/modules/hyperv's exported surface) rather than a single package's
// unit test, so it lives in test/integration/ per CLAUDE.md's test-taxonomy
// table. It is the Linux-runnable half of the story; the part that must exercise
// a real Windows Mount-VHD kill/dismount against pstransport_windows.go lives in
// the go:build windows sibling file (hyperv_provision_timeout_recovery_windows_test.go).
//
// # Fixture provenance (Issue #3804 AC)
//
// features/modules/hyperv's failProvision/advanceProvision bookkeeping and its
// transport-injection seam (testWinRMTransport, used by that package's own
// TestApplySourceGated_FailedSeedPhaseRetriesWithinBudget /
// TestApplySourceGated_FailedSeedPhaseDoesNotStartVM) are both unexported —
// unreachable from this package. Driving the real hypervModule.Set() end-to-end
// from here would additionally require either live Hyper-V admin rights
// (Windows) or a reachable WinRM host (any platform), neither available in this
// environment or on a Linux CI runner. hyperv.ProvisionRecord and
// hyperv.ProvisionStore ARE exported, so the "already retried N times" fixture
// below is a struct literal of the real, exported type — checked by the Go
// compiler against the real field set, not a hand-typed JSON blob that could
// silently drift from what failProvision actually writes (contrast: the exact
// shape asserted by features/modules/hyperv/vm_reconcile_integration_test.go's
// own fixtures, which this literal matches field-for-field) — round-tripped
// through the real hyperv.NewMemProvisionStore() to prove it also matches the
// store's real (de)serialization path.
//
// stubSeedRepairModule below stands in for the hyperv module's host interaction
// only: its retry-vs-exhausted branch mirrors applySourceGated's real decision
// (RetryCount vs. the retry budget — features/modules/hyperv/provision.go's
// seedPhaseRetryExhausted, also unexported) but never touches a real transport.
// The retry MECHANICS themselves — that a within-budget retry actually
// re-invokes the seed build and increments RetryCount, and that an
// exhausted-budget record does not — are already proven end-to-end against a
// real fake transport by the hyperv package's own tests cited above; this
// file's job is the piece those tests cannot reach from inside their own
// package: proving the resulting terminal state actually surfaces through the
// real commands.Handler → execution.Executor.ApplyConfiguration →
// ConfigStatusReport pipeline, and that the pipeline does not truncate a
// long-running repair at the old 30s ceiling.
package integration

import (
	"context"
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
)

// seedPhaseRetryBudget mirrors features/modules/hyperv's
// defaultSeedPhaseRetryMax (unexported) — the total create/seed-phase attempt
// budget (original attempt + 2 automatic repairs) ADR-009 §2's amendment
// settled on.
const seedPhaseRetryBudget = 3

// stubSeedRepairModule stands in for hyperv.vm's host interaction (see the file
// doc comment). Get reports drift until repaired; Set reads the real
// hyperv.ProvisionRecord fixture from a real hyperv.ProvisionStore and mirrors
// applySourceGated's real retry-vs-exhausted decision without touching any
// transport: within budget, it sleeps for repairDelay (simulating a genuinely
// slow seed rebuild) and then succeeds; at or past budget, it returns
// *modules.RetryExhaustedError immediately, exactly as the real gate does.
type stubSeedRepairModule struct {
	store       hyperv.ProvisionStore
	vmName      string
	repairDelay time.Duration
	repaired    bool
}

var _ modules.Module = (*stubSeedRepairModule)(nil)

func (s *stubSeedRepairModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	if s.repaired {
		return execution.NewConfigState(map[string]interface{}{"state": "ready"}), nil
	}
	return execution.NewConfigState(map[string]interface{}{"state": "failed"}), nil
}

func (s *stubSeedRepairModule) Set(ctx context.Context, _ string, _ modules.ConfigState) error {
	record, err := s.store.GetProvision(ctx, s.vmName)
	if err != nil {
		return err
	}
	if record.RetryCount >= seedPhaseRetryBudget {
		// Mirrors applySourceGated's exhausted branch: no transport call, no
		// mutation, an immediate typed sentinel (Issue #3803).
		return modules.NewRetryExhaustedError(record.LastError, string(record.FailedFrom))
	}
	// Mirrors the within-budget branch: a real repair attempt that legitimately
	// takes time. Long enough to have been killed by the old 30s
	// executeCommand ceiling; comfortably inside this test's configured
	// ModuleCallTimeoutSec.
	select {
	case <-time.After(s.repairDelay):
	case <-ctx.Done():
		return ctx.Err()
	}
	s.repaired = true
	return nil
}

// seedPhaseFailedRecord builds the "already failed during the seed phase, N
// attempts made" fixture — see the file doc comment on fixture provenance.
// Field values mirror exactly what features/modules/hyperv's failProvision
// documents itself as writing on a create/seed-phase failure.
func seedPhaseFailedRecord(vmName string, retryCount int) *hyperv.ProvisionRecord {
	now := time.Now().UTC()
	return &hyperv.ProvisionRecord{
		VMName:        vmName,
		State:         hyperv.ProvisionStateFailed,
		FailedFrom:    hyperv.ProvisionStateCreating,
		CorrelationID: vmName,
		StartedAt:     now.Add(-time.Hour),
		UpdatedAt:     now,
		LastError:     `hyperv: create seed VHDX for VM "` + vmName + `": exit status 1`,
		RetryCount:    retryCount,
	}
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
// dedicated package-internal regression — so this test can drive it against an
// executor wired with a stub hyperv-shaped module instead of a real data-plane
// session.
func newSyncConfigTestHandler(t *testing.T, exec *execution.Executor) *commands.Handler {
	t.Helper()
	var completed []*cpTypes.Event
	handler, err := commands.New(&commands.Config{
		StewardID: "steward-hyperv-timeout-recovery",
		OnStatus: func(_ context.Context, evt *cpTypes.Event) {
			completed = append(completed, evt)
		},
		Logger: logging.NewNoopLogger(),
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

// buildHypervVMConfigYAML marshals a minimal StewardConfig carrying one
// resource against moduleName — standing in for a hyperv.vm resource with a
// source: cloud-image block (Issue #3804 AC), routed to stubSeedRepairModule.
func buildHypervVMConfigYAML(t *testing.T, moduleName string) []byte {
	t.Helper()
	cfg := stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: "steward-hyperv-timeout-recovery"},
		Resources: []stewardtypes.ResourceConfig{
			{
				Name:   "vm:seed-repair-vm",
				Module: moduleName,
				Config: map[string]interface{}{"name": "seed-repair-vm", "state": "running"},
			},
		},
	}
	out, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return out
}

// TestHypervVMSeedRepair_SlowRetry_SucceedsPastOld30sCeiling is the [REQUIRED
// TEST] for Issue #3804 AC (a)+(b): a hyperv.vm resource whose provisioning
// record failed during the seed phase, still within its retry budget, is
// repaired by a genuinely slow re-invocation — longer than the old 30s
// executeCommand ceiling, well under the configured ModuleCallTimeoutSec — and
// the sync succeeds rather than being killed mid-repair.
func TestHypervVMSeedRepair_SlowRetry_SucceedsPastOld30sCeiling(t *testing.T) {
	const vmName = "seed-repair-vm"
	const moduleName = "hyperv-seed-repair-stub"
	// Comfortably past the old 30s ceiling; comfortably under this test's
	// configured 90s ModuleCallTimeoutSec below.
	const repairDelay = 32 * time.Second

	store := hyperv.NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), seedPhaseFailedRecord(vmName, 1)))

	stub := &stubSeedRepairModule{store: store, vmName: vmName, repairDelay: repairDelay}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.NewNoopLogger())
	f.RegisterModule(moduleName, stub)

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.NewNoopLogger(),
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 90, // well above repairDelay, well under production's 120s default
	})
	require.NoError(t, err)

	handler := newSyncConfigTestHandler(t, exec)
	configYAML := buildHypervVMConfigYAML(t, moduleName)

	elapsed := dispatchSyncConfig(t, handler, configYAML)

	require.GreaterOrEqual(t, elapsed, repairDelay,
		"the repair must actually wait out the full delay, not be cut short by the old 30s ceiling")
	assert.True(t, stub.repaired, "the slow repair must have completed, not been cancelled mid-flight")
}

// TestHypervVMSeedRepair_RetryExhausted_ReachesConfigStatusReport is the
// [REQUIRED TEST] for Issue #3804 AC (c): a hyperv.vm resource whose
// provisioning record has exhausted its bounded seed-phase retry budget
// produces a distinct, queryable RETRY_EXHAUSTED status in the
// ConfigStatusReport returned by executor.ApplyConfiguration — not a
// repeating, indistinguishable "verification failed" — via the real
// commands.Handler → executor pipeline.
func TestHypervVMSeedRepair_RetryExhausted_ReachesConfigStatusReport(t *testing.T) {
	const vmName = "seed-repair-vm"
	const moduleName = "hyperv-seed-repair-stub"

	store := hyperv.NewMemProvisionStore()
	require.NoError(t, store.SetProvision(context.Background(), seedPhaseFailedRecord(vmName, seedPhaseRetryBudget)))

	stub := &stubSeedRepairModule{store: store, vmName: vmName, repairDelay: 0}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, logging.NewNoopLogger())
	f.RegisterModule(moduleName, stub)

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               logging.NewNoopLogger(),
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: 90,
	})
	require.NoError(t, err)

	// Drive ApplyConfiguration directly (not through commands.Handler) so this
	// test can inspect the returned *cpTypes.ConfigStatusReport — the dispatch
	// path itself (proving the 30s ceiling doesn't apply) is what the sibling
	// test above already covers.
	//
	// ApplyConfiguration's function-level error return only ever carries a
	// configuration-parse failure — the retry-exhausted classification (like
	// every other per-resource outcome) rides the *report* it returns
	// alongside a nil error, not this error return.
	configYAML := buildHypervVMConfigYAML(t, moduleName)
	report, applyErr := exec.ApplyConfiguration(context.Background(), configYAML, "v-retry-exhausted-1")
	require.NoError(t, applyErr)
	require.NotNil(t, report)

	assert.Equal(t, "RETRY_EXHAUSTED", report.Status,
		"the overall report status must surface the retry-exhausted classification, not ERROR")

	moduleStatus, ok := report.Modules[moduleName]
	require.True(t, ok, "the retry-exhausted resource's module must appear in the report")
	assert.Equal(t, "RETRY_EXHAUSTED", moduleStatus.Status,
		"a retry-exhausted resource must produce a distinct RETRY_EXHAUSTED module status, not ERROR")

	require.Len(t, report.ApplyOutcomes, 1)
	assert.Equal(t, "retry_exhausted", report.ApplyOutcomes[0].Status,
		"the apply-outcome record must classify this as retry_exhausted, not failed")
	assert.Equal(t, "vm:seed-repair-vm", report.ApplyOutcomes[0].ResourceID)
}
