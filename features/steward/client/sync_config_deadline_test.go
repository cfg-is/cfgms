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

// TestCommandSyncConfig_SlowModuleSet_SucceedsPastOld30sCeiling is the
// load-bearing regression test for Issue #3801. It constructs the REAL
// commands.Handler (no mocks) via setupCommandHandler, with its production
// 30s-unless-overridden executeCommand deadline (handler.go:475, untouched by
// this story) intact, dispatches a real CommandSyncConfig, and drives a
// module.Set that legitimately takes longer than 30s but well under the
// configured ModuleCallTimeoutSec budget.
//
// Before the fix, the CommandSyncConfig handler passed executeCommand's ctx
// straight into syncConfigNow, so this Set was cancelled by
// context.DeadlineExceeded at the 30s mark and the sync failed. After the fix,
// the handler derives its own background context (mirroring the on-connect
// sync path), so the executor's own per-call timeout is the only budget that
// applies and the sync succeeds.
func TestCommandSyncConfig_SlowModuleSet_SucceedsPastOld30sCeiling(t *testing.T) {
	const stewardID = "steward-slow-sync"
	const tenantID = "tenant-slow-sync"
	// Comfortably past the old 30s ceiling; comfortably under production's 120s
	// ModuleCallTimeoutSec default — this test configures its own, larger budget
	// below so the margin isn't flaky under load.
	const slowSetDelay = 32 * time.Second

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
	transfer := buildSignedConfigTransfer(t, signer, configData, "v-slow-1")

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
		ModuleCallTimeoutSec: 90, // well above slowSetDelay, well under production's 120s
	})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, tenantID)
	c.signingCertPEMs = []string{certPEM}

	handler, err := c.setupCommandHandler(context.Background(), stewardID)
	require.NoError(t, err)

	cmdValue := cpTypes.Command{
		ID:        "cmd-slow-sync-1",
		Type:      cpTypes.CommandSyncConfig,
		StewardID: stewardID,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Params:    map[string]interface{}{},
	}
	rawParams := cpTypes.InterfaceParamsToStringMap(cmdValue.Params)
	commandBytes, err := cpTypes.CommandSigningBytes(&cmdValue, rawParams)
	require.NoError(t, err)
	commandSignature, err := signer.Sign(commandBytes)
	require.NoError(t, err)
	cmd := &cpTypes.SignedCommand{Command: cmdValue, Signature: commandSignature}

	start := time.Now()
	require.NoError(t, handler.HandleCommand(context.Background(), cmd))

	// handler.Wait() blocks until executeCommand's goroutine finishes — this is
	// the assertion under test: it must NOT return early at ~30s.
	handler.Wait()
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, slowSetDelay,
		"the sync must actually wait out the full Set delay, not be cut short by executeCommand's old 30s ceiling")

	events := drainEvents(capture.events)
	var configApplied bool
	var completedEvt *cpTypes.Event
	for _, evt := range events {
		if evt.Type == cpTypes.EventConfigApplied {
			configApplied = true
		}
		if evt.Type == cpTypes.EventCommandCompleted {
			completedEvt = evt
		}
	}
	assert.True(t, configApplied,
		"a config-applied event must be published once the slow Set finishes past the old 30s ceiling; got event types: %v",
		eventTypes(events))
	require.NotNil(t, completedEvt,
		"executeCommand must still report EventCommandCompleted once the underlying sync finishes — its own bookkeeping is unaffected by this fix")
}

func eventTypes(events []*cpTypes.Event) []cpTypes.EventType {
	out := make([]cpTypes.EventType, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return out
}
