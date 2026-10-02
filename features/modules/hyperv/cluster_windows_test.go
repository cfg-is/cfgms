// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

// The cluster DNA Monitor (#2241) is Windows-only (it polls FailoverCluster via
// the S1 read consts), so its tests are build-tagged windows — the same split
// the existing monitor_windows_test.go / monitor_nonwindows_test.go uses. They
// drive monitorClusterLoop with an injected tick channel for deterministic
// hysteresis assertions (no real-timer flakiness) and exercise the real
// Monitor()/Close() lifecycle for the no-leak check.
package hyperv

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// seqClusterTransport returns a per-scriptBlock sequence of canned outputs (the
// last element repeats once the sequence is exhausted). This lets a test vary
// only the resource-owner response across polls — simulating an ownership change
// — without mutating shared state mid-flight. It implements the same
// winrmTransport seam as testWinRMTransport.
type seqClusterTransport struct {
	mu   sync.Mutex
	seqs map[string][]string
	idx  map[string]int
}

func newSeqClusterTransport() *seqClusterTransport {
	return &seqClusterTransport{seqs: map[string][]string{}, idx: map[string]int{}}
}

func (t *seqClusterTransport) set(scriptBlock string, outputs ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seqs[scriptBlock] = outputs
}

func (t *seqClusterTransport) ExecutePS(_ context.Context, scriptBlock string, _ map[string]string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.seqs[scriptBlock]
	if len(s) == 0 {
		return "", nil
	}
	i := t.idx[scriptBlock]
	if i >= len(s) {
		i = len(s) - 1
	}
	t.idx[scriptBlock]++
	return s[i], nil
}

const (
	clusterGetJSON   = `{"found":true,"Name":"lab-hv","MemberNodes":["NODE1","NODE2"],"CsvPaths":["C:\\ClusterStorage\\CSV01"]}`
	clusterOwnerJSON = `{"owner":"NODE1"}`
)

func resourceOwnerJSON(owner string) string {
	return `{"owners":{"web-01":"` + owner + `"}}`
}

// clusterMonitorModule builds a hypervModule wired for cluster monitoring with
// the given transport, registered interest in cluster:lab-hv, and an open
// changes channel.
func clusterMonitorModule(transport winrmTransport) *hypervModule {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"
	m.monChanges = make(chan modules.ChangeEvent, 16)
	m.monClusterInterest = map[string]struct{}{"cluster:lab-hv": {}}
	return m
}

// TestMonitorCluster_EmitsDetails verifies that an ownership change (the
// resource_owner map changing across polls), once stable across two consecutive
// polls (S8 dwell), produces exactly one ChangeTypeModified event whose
// Details.AsMap() carries member_nodes and resource_owner (the #415 contract).
func TestMonitorCluster_EmitsDetails(t *testing.T) {
	transport := newSeqClusterTransport()
	transport.set(psGetCluster, clusterGetJSON)
	transport.set(psGetClusterOwnerNode, clusterOwnerJSON)
	// poll 1 → NODE1 (baseline); poll 2+ → NODE2 (stable change).
	transport.set(psGetClusterResourceOwner, resourceOwnerJSON("NODE1"), resourceOwnerJSON("NODE2"))

	m := clusterMonitorModule(transport)

	tick := make(chan time.Time)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.monitorClusterLoop("lab-hv", tick, stop); close(done) }()

	tick <- time.Now() // poll 1: baseline (owner NODE1), no emit
	tick <- time.Now() // poll 2: candidate (owner NODE2), pending
	tick <- time.Now() // poll 3: confirm (owner NODE2 stable) → emit
	close(stop)
	<-done

	// Exactly one event, carrying the DNA payload.
	select {
	case ev := <-m.monChanges:
		assert.Equal(t, "cluster:lab-hv", ev.ResourceID)
		assert.Equal(t, modules.ChangeTypeModified, ev.ChangeType)
		require.NotNil(t, ev.Details, "cluster ChangeEvent must carry *ClusterStatus Details")
		assert.NotZero(t, ev.Timestamp, "receipt-time timestamp must be set")
		mp := ev.Details.AsMap()
		assert.NotEmpty(t, mp["member_nodes"], "member_nodes must be populated (#415 contract)")
		owners, ok := mp["resource_owner"].(map[string]string)
		require.True(t, ok, "resource_owner must be a map (#415 contract)")
		assert.Equal(t, "NODE2", owners["web-01"], "the emitted owner must reflect the change")
	default:
		t.Fatal("expected exactly one ChangeTypeModified event, got none")
	}

	// No second event.
	select {
	case ev := <-m.monChanges:
		t.Fatalf("expected exactly one event; got a second: %+v", ev)
	default:
	}
}

// TestMonitorCluster_AntiFlap verifies S8: a transient A→B→A within one dwell
// (the change reverts before two consecutive confirming polls) emits zero events.
func TestMonitorCluster_AntiFlap(t *testing.T) {
	transport := newSeqClusterTransport()
	transport.set(psGetCluster, clusterGetJSON)
	transport.set(psGetClusterOwnerNode, clusterOwnerJSON)
	// poll 1 → NODE1 (baseline); poll 2 → NODE2 (candidate); poll 3 → NODE1 (revert).
	transport.set(psGetClusterResourceOwner,
		resourceOwnerJSON("NODE1"), resourceOwnerJSON("NODE2"), resourceOwnerJSON("NODE1"))

	m := clusterMonitorModule(transport)

	tick := make(chan time.Time)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.monitorClusterLoop("lab-hv", tick, stop); close(done) }()

	tick <- time.Now() // baseline NODE1
	tick <- time.Now() // candidate NODE2 (pending)
	tick <- time.Now() // revert to NODE1 → suppress
	close(stop)
	<-done

	select {
	case ev := <-m.monChanges:
		t.Fatalf("a transient flap must emit zero events; got: %+v", ev)
	default:
	}
}

// TestMonitorCluster_PollFailureDuringDwell verifies that a transient poll
// failure between the candidate poll and its confirming poll does NOT drop the
// pending change nor spuriously emit: the dwell survives the failed poll, and
// the next successful confirming poll still emits exactly one event.
func TestMonitorCluster_PollFailureDuringDwell(t *testing.T) {
	transport := newSeqClusterTransport()
	// poll 3's getCluster fails (invalid JSON) — clusterOwnershipHelper is never
	// reached that poll, so the owner/resource-owner sequences do not advance.
	transport.set(psGetCluster, clusterGetJSON, clusterGetJSON, `not-json`, clusterGetJSON)
	transport.set(psGetClusterOwnerNode, clusterOwnerJSON)
	transport.set(psGetClusterResourceOwner,
		resourceOwnerJSON("NODE1"), resourceOwnerJSON("NODE2"), resourceOwnerJSON("NODE2"))

	m := clusterMonitorModule(transport)

	tick := make(chan time.Time)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.monitorClusterLoop("lab-hv", tick, stop); close(done) }()

	tick <- time.Now() // poll 1: baseline NODE1
	tick <- time.Now() // poll 2: candidate NODE2 (pending)
	tick <- time.Now() // poll 3: getCluster fails → skip, pending preserved
	tick <- time.Now() // poll 4: confirm NODE2 → emit
	close(stop)
	<-done

	select {
	case ev := <-m.monChanges:
		assert.Equal(t, modules.ChangeTypeModified, ev.ChangeType)
		require.NotNil(t, ev.Details)
		owners, _ := ev.Details.AsMap()["resource_owner"].(map[string]string)
		assert.Equal(t, "NODE2", owners["web-01"])
	default:
		t.Fatal("a failed poll mid-dwell must not drop the pending change; expected one event")
	}
	select {
	case ev := <-m.monChanges:
		t.Fatalf("expected exactly one event; got a second: %+v", ev)
	default:
	}
}

// TestMonitorCluster_CloseStopsPoller verifies the full Monitor()/Close()
// lifecycle: Close() stops the polling goroutine and closes the changes channel
// with no leak and no send on a closed channel (a leaked poller would hang
// Close()'s WaitGroup join or panic on the close).
func TestMonitorCluster_CloseStopsPoller(t *testing.T) {
	transport := newSeqClusterTransport()
	transport.set(psGetCluster, clusterGetJSON)
	transport.set(psGetClusterOwnerNode, clusterOwnerJSON)
	transport.set(psGetClusterResourceOwner, resourceOwnerJSON("NODE1")) // constant → no change, no emit

	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"
	m.clusterPollInterval = 2 * time.Millisecond // fast poll for the test

	ch := m.Changes() // capture the channel before Close
	require.NoError(t, m.Monitor(context.Background(), "cluster:lab-hv", nil))

	time.Sleep(30 * time.Millisecond) // let it poll several times (no ownership change)

	require.NoError(t, m.Close(), "Close must join the poller and return cleanly")

	// The channel must be closed (poller joined, no leak) and carry no events.
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("no event expected from a steady cluster; got: %+v", ev)
		}
		// ok == false: channel closed — the poller was stopped and joined.
	case <-time.After(2 * time.Second):
		t.Fatal("Changes channel was not closed after Close — poller leaked")
	}

	// Close is idempotent.
	require.NoError(t, m.Close())
}
