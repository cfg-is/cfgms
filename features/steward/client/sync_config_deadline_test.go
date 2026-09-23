// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the CommandSyncConfig deadline decoupling from
// Issue #3801: ApplyConfiguration/StartMonitors must run under a context with
// no executeCommand-supplied 30s-unless-overridden deadline, so the executor's
// own per-call ModuleCallTimeoutSec budget (ADR-012 §7) is the real effective
// bound — matching the precedent already established for the on-connect sync
// path (Issue #2480).
package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/modules"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/features/steward/factory"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// slowSetModule is a real modules.Module implementation that reports drift on
// the first Get(), then blocks in Set() for `delay` before applying — long
// enough to have been killed by the old executeCommand 30s ceiling, but
// comfortably inside the executor's configured ModuleCallTimeoutSec. Mirrors
// SlowSetModule in features/steward/execution/executor_test.go; duplicated
// here (rather than imported) because that type is unexported in a different
// package and this test needs it wired through the real commands.Handler /
// CommandSyncConfig path, not the executor package directly.
type slowSetModule struct {
	mu      sync.Mutex
	delay   time.Duration
	applied bool
}

var _ modules.Module = (*slowSetModule)(nil)

func (s *slowSetModule) Get(_ context.Context, _ string) (modules.ConfigState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied {
		return &inMemoryConfigState{data: map[string]interface{}{"state": "desired"}}, nil
	}
	return &inMemoryConfigState{data: map[string]interface{}{"state": "drifted"}}, nil
}

func (s *slowSetModule) Set(ctx context.Context, _ string, _ modules.ConfigState) error {
	select {
	case <-time.After(s.delay):
		s.mu.Lock()
		s.applied = true
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runSlowSyncConfig drives one real CommandSyncConfig round trip through the real
// commands.Handler (no mocks): it constructs a signed sync_config command whose
// executeCommand-level deadline is `cmdTimeoutSeconds` (handler.go:475's
// "timeout_seconds" override), configures the executor's per-call budget to
// `moduleCallTimeoutSec` (ADR-012 §7), and drives a module.Set that legitimately
// takes `slowSetDelay`. stewardIDSuffix keeps steward/tenant IDs unique per
// subtest so components from one case can't leak into another.
func runSlowSyncConfig(t *testing.T, stewardIDSuffix string, slowSetDelay time.Duration,
	moduleCallTimeoutSec int, cmdTimeoutSeconds float64) (elapsed time.Duration, events []*cpTypes.Event) {
	t.Helper()

	stewardID := "steward-slow-sync-" + stewardIDSuffix
	tenantID := "tenant-slow-sync-" + stewardIDSuffix

	_, signer, certPEM := newSigningCA(t)

	resourceConfig, err := structpb.NewStruct(map[string]interface{}{"state": "desired"})
	require.NoError(t, err)

	protoConfig := &controllerpb.StewardConfig{
		Steward: &controllerpb.StewardSettings{Id: stewardID},
		Resources: []*controllerpb.ResourceConfig{
			{Name: "slow-resource", Module: "slow-set", Config: resourceConfig},
		},
	}
	configData := marshalSignedConfig(t, signer, protoConfig)
	transfer := buildSignedConfigTransfer(t, signer, configData, "v-slow-"+stewardIDSuffix)

	sess := &testConfigSession{
		testDataPlaneSession: *newTestSession(),
		data:                 transfer.Data,
		version:              transfer.Version,
		signature:            transfer.Signature,
	}

	errCfg := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure:  stewardconfig.ActionContinue,
		ResourceFailure:    stewardconfig.ActionWarn,
		ConfigurationError: stewardconfig.ActionFail,
	}
	f := factory.New(discovery.ModuleRegistry{}, errCfg, newTestLogger(t))
	f.RegisterModule("slow-set", &slowSetModule{delay: slowSetDelay})

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{
		Logger:               newTestLogger(t),
		Factory:              f,
		ErrorHandling:        errCfg,
		ModuleCallTimeoutSec: moduleCallTimeoutSec,
	})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, tenantID)
	c.signingCertPEMs = []string{certPEM}

	handler, err := c.setupCommandHandler(context.Background(), stewardID)
	require.NoError(t, err)

	cmdValue := cpTypes.Command{
		ID:        "cmd-slow-sync-" + stewardIDSuffix,
		Type:      cpTypes.CommandSyncConfig,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"timeout_seconds": cmdTimeoutSeconds},
	}
	rawParams := cpTypes.InterfaceParamsToStringMap(cmdValue.Params)
	commandBytes, err := cpTypes.CommandSigningBytes(&cmdValue, rawParams)
	require.NoError(t, err)
	commandSignature, err := signer.Sign(commandBytes)
	require.NoError(t, err)
	cmd := &cpTypes.SignedCommand{Command: cmdValue, Signature: commandSignature}

	start := time.Now()
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	// handler.Wait() blocks until executeCommand's goroutine finishes.
	handler.Wait()
	elapsed = time.Since(start)

	return elapsed, drainEvents(capture.events)
}

// configAppliedStatus returns the "status" detail from the first EventConfigApplied
// event found, or "" if none was published.
func configAppliedStatus(events []*cpTypes.Event) (found bool, status string) {
	for _, evt := range events {
		if evt.Type == cpTypes.EventConfigApplied {
			s, _ := evt.Details["status"].(string)
			return true, s
		}
	}
	return false, ""
}

// TestCommandSyncConfig_SlowModuleSet_SucceedsPastExecuteCommandDeadline is the
// load-bearing regression test for Issue #3801, run at a scale that finishes in
// ~1s instead of the original 32s. It constructs the REAL commands.Handler (no
// mocks) via setupCommandHandler, dispatches a real signed CommandSyncConfig
// whose "timeout_seconds" param shrinks executeCommand's own context deadline
// (handler.go:475) to 1s — a stand-in for the production 30s-unless-overridden
// default, shrunk so the test doesn't have to wait out 30+ real seconds — and
// drives a module.Set that legitimately takes longer than that 1s command-level
// deadline but well under the executor's separately configured
// ModuleCallTimeoutSec budget.
//
// Before the fix, the CommandSyncConfig handler passed executeCommand's ctx
// straight into syncConfigNow, so this Set would have been cancelled by
// context.DeadlineExceeded at the ~1s command-level mark. After the fix, the
// handler derives its own background context (mirroring the on-connect sync
// path), so the executor's own per-call timeout is the only budget that
// applies and the sync succeeds despite legitimately outliving the shrunk
// command-level deadline.
func TestCommandSyncConfig_SlowModuleSet_SucceedsPastExecuteCommandDeadline(t *testing.T) {
	const slowSetDelay = 1200 * time.Millisecond
	const cmdTimeoutSeconds = 1    // shrunk stand-in for the 30s-unless-overridden default; smaller than slowSetDelay
	const moduleCallTimeoutSec = 3 // comfortably above slowSetDelay

	elapsed, events := runSlowSyncConfig(t, "success", slowSetDelay, moduleCallTimeoutSec, cmdTimeoutSeconds)

	require.GreaterOrEqual(t, elapsed, slowSetDelay,
		"the sync must actually wait out the full Set delay, not be cut short by executeCommand's shrunk command-level deadline")

	found, status := configAppliedStatus(events)
	require.True(t, found,
		"a config-applied event must be published once the slow Set finishes past the shrunk command-level deadline; got event types: %v",
		eventTypes(events))
	assert.Equal(t, "OK", status,
		"the slow Set legitimately finished within ModuleCallTimeoutSec, so the resource must be reported applied, not errored")

	var completedEvt *cpTypes.Event
	for _, evt := range events {
		if evt.Type == cpTypes.EventCommandCompleted {
			completedEvt = evt
		}
	}
	require.NotNil(t, completedEvt,
		"executeCommand must still report EventCommandCompleted once the underlying sync finishes — its own bookkeeping is unaffected by this fix")
}

// TestCommandSyncConfig_SlowModuleSet_FailsWhenModuleTimeoutBelowDelay is the
// flip side of the regression guard above: with the same slowSetDelay, and the
// command-level "timeout_seconds" deliberately set large (so it cannot be the
// bottleneck), configuring the executor's ModuleCallTimeoutSec BELOW the delay
// must still cause the module.Set to be cut short. This proves the executor's
// own per-call budget (ADR-012 §7) — not some other hardcoded ceiling — is the
// real, effective bound: the outcome flips exactly at the configured value.
func TestCommandSyncConfig_SlowModuleSet_FailsWhenModuleTimeoutBelowDelay(t *testing.T) {
	const slowSetDelay = 1200 * time.Millisecond
	const cmdTimeoutSeconds = 10   // large stand-in; must not be the bottleneck for this case
	const moduleCallTimeoutSec = 1 // below slowSetDelay

	elapsed, events := runSlowSyncConfig(t, "failure", slowSetDelay, moduleCallTimeoutSec, cmdTimeoutSeconds)

	require.Less(t, elapsed, slowSetDelay,
		"a module.Set budget below the delay must cut the call short instead of waiting out the full delay")
	require.GreaterOrEqual(t, elapsed, time.Duration(moduleCallTimeoutSec)*time.Second,
		"the call must run for the full configured ModuleCallTimeoutSec budget before being cut short")

	found, status := configAppliedStatus(events)
	require.True(t, found,
		"a config-applied event must still be published even when a resource times out; got event types: %v",
		eventTypes(events))
	assert.Equal(t, "ERROR", status,
		"a module.Set that exceeds ModuleCallTimeoutSec must be reported as an error, proving that budget — not a larger command-level deadline — was the effective bound")
}

func eventTypes(events []*cpTypes.Event) []cpTypes.EventType {
	out := make([]cpTypes.EventType, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}
