// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// heartbeatCapture is a real control plane test implementation that records every
// heartbeat the client sends.
type heartbeatCapture struct {
	*eventCapture
	mu    sync.Mutex
	beats []*cpTypes.Heartbeat
}

func (h *heartbeatCapture) SendHeartbeat(_ context.Context, hb *cpTypes.Heartbeat) error {
	h.mu.Lock()
	h.beats = append(h.beats, hb)
	h.mu.Unlock()
	return nil
}

func (h *heartbeatCapture) snapshot() []*cpTypes.Heartbeat {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*cpTypes.Heartbeat(nil), h.beats...)
}

// carries reports whether any recorded heartbeat has a reason for component.
func (h *heartbeatCapture) carries(component string) *cpTypes.HealthReason {
	for _, hb := range h.snapshot() {
		for i := range hb.Reasons {
			if hb.Reasons[i].Component == component {
				return &hb.Reasons[i]
			}
		}
	}
	return nil
}

// newGuardClient builds a client that heartbeats every few milliseconds into the
// returned capture.
func newGuardClient(t *testing.T) (*TransportClient, *heartbeatCapture) {
	t.Helper()
	prev := heartbeatJitterMax
	heartbeatJitterMax = 2 * time.Millisecond
	t.Cleanup(func() { heartbeatJitterMax = prev })

	hc := &heartbeatCapture{eventCapture: newEventCapture()}
	c := &TransportClient{
		stewardID:          "steward-guard",
		tenantID:           "tenant-guard",
		heartbeatInterval:  5 * time.Millisecond,
		heartbeatStop:      make(chan struct{}),
		convergenceStop:    make(chan struct{}),
		dnaRefreshStop:     make(chan struct{}),
		convergeIntervalCh: make(chan struct{}, 1),
		convergeInterval:   10 * time.Millisecond,
		logger:             logging.NewNoopLogger(),
	}
	c.controlPlane = hc
	return c, hc
}

func startBeating(t *testing.T, c *TransportClient) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.startHeartbeat()
	}()
	t.Cleanup(func() {
		close(c.heartbeatStop)
		<-done
	})
}

func waitReason(t *testing.T, hc *heartbeatCapture, component string) *cpTypes.HealthReason {
	t.Helper()
	var got *cpTypes.HealthReason
	require.Eventually(t, func() bool {
		got = hc.carries(component)
		return got != nil
	}, 5*time.Second, 5*time.Millisecond, "heartbeat must carry a reason naming %q", component)
	return got
}

func assertFixedPanicReason(t *testing.T, r *cpTypes.HealthReason, component, secret string) {
	t.Helper()
	assert.Equal(t, healthReasonCodePanic, r.Code)
	assert.Equal(t, component+" recovered from a panic", r.Message)
	assert.False(t, strings.Contains(r.Message, secret), "panic value must not reach the reason")
}

const panicSecret = "s3cr3t-panic-value"

func TestGuard_Heartbeat_PanicRecoveredAndReasonClears(t *testing.T) {
	c, hc := newGuardClient(t)
	var calls atomic.Int32
	c.SetStatusFunc(func() string {
		if calls.Add(1) == 1 {
			panic(panicSecret)
		}
		return "healthy"
	})
	startBeating(t, c)

	r := waitReason(t, hc, componentHeartbeat)
	assertFixedPanicReason(t, r, componentHeartbeat, panicSecret)

	// The panicking tick ended; later ticks keep firing and the reason, cleared
	// by the first successful iteration, is gone from later heartbeats.
	require.Eventually(t, func() bool {
		beats := hc.snapshot()
		return len(beats) >= 3 && len(beats[len(beats)-1].Reasons) == 0 && len(c.HealthReasons()) == 0
	}, 5*time.Second, 5*time.Millisecond, "reason must clear after a successful iteration")
}

func TestGuard_DNARefresh_PanicRecordedAndHeartbeatContinues(t *testing.T) {
	c, hc := newGuardClient(t)
	c.dnaCollector = panicCollector{}
	c.dnaRefreshInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startBeating(t, c)
	c.StartDNARefreshLoop(ctx)

	r := waitReason(t, hc, componentDNARefresh)
	assertFixedPanicReason(t, r, componentDNARefresh, panicSecret)
	before := len(hc.snapshot())
	require.Eventually(t, func() bool { return len(hc.snapshot()) > before+1 }, 5*time.Second, 5*time.Millisecond,
		"heartbeat must keep firing after the DNA loop panicked repeatedly")
}

type panicCollector struct{}

func (panicCollector) CollectAttributes(context.Context) (map[string]string, error) {
	panic(panicSecret)
}
func (panicCollector) CollectFragments(context.Context) []*commonpb.Fragment { return nil }

func TestGuard_DNARefresh_ReasonClearsAfterSuccess(t *testing.T) {
	c, _ := newGuardClient(t)
	c.dnaCollector = panicCollector{}
	ctx := context.Background()
	require.False(t, c.guard(componentDNARefresh, func() { c.runDNARefreshTick(ctx, c.dnaCollector) }))
	require.Len(t, c.HealthReasons(), 1)

	good := &inMemoryDNACollector{attrs: map[string]string{"k": "v"}}
	require.True(t, c.guard(componentDNARefresh, func() { c.runDNARefreshTick(ctx, good) }))
	assert.Empty(t, c.HealthReasons())
}

func TestGuard_Convergence_PanicRecordedAndHeartbeatContinues(t *testing.T) {
	c, hc := newGuardClient(t)
	// A zero-value executor is the real execution.Executor without its logger:
	// applying a configuration through it panics.
	c.configExecutor = &execution.Executor{}
	c.lastConfigYAML = []byte("steward:\n  id: x\n")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); close(c.convergenceStop) })
	startBeating(t, c)
	c.StartConvergenceLoop(ctx)

	r := waitReason(t, hc, componentConvergence)
	assertFixedPanicReason(t, r, componentConvergence, panicSecret)
	before := len(hc.snapshot())
	require.Eventually(t, func() bool { return len(hc.snapshot()) > before+1 }, 5*time.Second, 5*time.Millisecond)
}

// panicSession is a data plane session whose ReceiveConfig panics.
type panicSession struct{ testDataPlaneSession }

func (*panicSession) ReceiveConfig(context.Context) (*dpTypes.ConfigTransfer, error) {
	panic(panicSecret)
}

func TestGuard_ConfigRefetch_PanicRecordedAndHeartbeatContinues(t *testing.T) {
	c, hc := newGuardClient(t)
	c.dataPlaneSession = &panicSession{*newTestSession()}
	startBeating(t, c)
	c.startConfigRefetch()

	r := waitReason(t, hc, componentConfigRefetch)
	assertFixedPanicReason(t, r, componentConfigRefetch, panicSecret)
	before := len(hc.snapshot())
	require.Eventually(t, func() bool { return len(hc.snapshot()) > before+1 }, 5*time.Second, 5*time.Millisecond)
}

func TestGuard_OnConnectSync_PanicRecordedAndHeartbeatContinues(t *testing.T) {
	c, hc := newGuardClient(t)
	c.dataPlaneSession = &panicSession{*newTestSession()}
	startBeating(t, c)
	c.startOnConnectSync()

	r := waitReason(t, hc, componentOnConnectSync)
	assertFixedPanicReason(t, r, componentOnConnectSync, panicSecret)
	before := len(hc.snapshot())
	require.Eventually(t, func() bool { return len(hc.snapshot()) > before+1 }, 5*time.Second, 5*time.Millisecond)
}

// A guard never records the panic value, and a reason with a different code under
// the same component survives a clean iteration.
func TestGuard_ClearOnlyOwnPanicReason(t *testing.T) {
	c, _ := newGuardClient(t)
	c.SetHealthReason("convergence", "other.code", "something else")
	require.True(t, c.guard("convergence", func() {}))
	require.Len(t, c.HealthReasons(), 1)
	assert.Equal(t, "other.code", c.HealthReasons()[0].Code)
}

func TestRecoverToError_ConvertsPanicToFixedError(t *testing.T) {
	var got string
	err := recoverToError(logging.NewNoopLogger(), componentEventEmitter, func(component string) { got = component },
		func() error { panic(panicSecret) })
	require.ErrorIs(t, err, errPanicRecovered)
	assert.NotContains(t, err.Error(), panicSecret)
	assert.Equal(t, componentEventEmitter, got)

	require.NoError(t, recoverToError(logging.NewNoopLogger(), componentEventEmitter, nil, func() error { return nil }))
}
