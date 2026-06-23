// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// The tests below exercise the interest registry, the manifest-grounded
// EventID->ChangeType decode, the single-subscription invariant, fan-out, and
// Close semantics WITHOUT touching the live Windows Event Log (which requires
// privilege and real VM churn). The OS subscription is established through the
// evtEstablish seam, which these tests replace with a hermetic fake; the decode
// path is driven directly with representative rendered-event XML.

// fakeEstablish installs a seam that records subscription creation and assigns a
// sentinel handle, without opening a real EvtSubscribe handle. It returns a
// pointer to the call counter and a restore func.
func fakeEstablish(t *testing.T) (calls *int, teardowns *int) {
	t.Helper()
	var c, td int
	orig := evtEstablish
	evtEstablish = func(m *hypervModule) error {
		c++
		m.monSub = 0xBEEF
		m.monTeardown = func() error { td++; return nil }
		return nil
	}
	t.Cleanup(func() { evtEstablish = orig })
	return &c, &td
}

// workerEventXML renders a representative Hyper-V Worker -Admin event in the
// shape the provider emits: VM name under UserData/VmlEventLog/VmName.
func workerEventXML(eventID int, vmName string) string {
	return fmt.Sprintf(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Hyper-V-Worker' Guid='{51ddfa29-d5c8-4803-be4b-2ecb715570fe}'/>
    <EventID>%d</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Channel>Microsoft-Windows-Hyper-V-Worker-Admin</Channel>
    <Computer>host.local</Computer>
  </System>
  <UserData>
    <VmlEventLog xmlns='http://www.microsoft.com/Windows/Virtualization/Events'>
      <VmName>%s</VmName>
      <VmId>5816C90A-0000-0000-0000-000000000000</VmId>
    </VmlEventLog>
  </UserData>
</Event>`, eventID, vmName)
}

// vmmsEventXML renders a representative Hyper-V VMMS -Admin event.
func vmmsEventXML(eventID int, vmName string) string {
	return fmt.Sprintf(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Hyper-V-VMMS' Guid='{6066f867-7ca1-4418-85fd-36e3f9c0600c}'/>
    <EventID>%d</EventID>
    <Channel>Microsoft-Windows-Hyper-V-VMMS-Admin</Channel>
    <Computer>host.local</Computer>
  </System>
  <UserData>
    <VmlEventLog xmlns='http://www.microsoft.com/Windows/Virtualization/Events'>
      <VmName>%s</VmName>
      <VmId>5816C90A-0000-0000-0000-000000000000</VmId>
    </VmlEventLog>
  </UserData>
</Event>`, eventID, vmName)
}

func recvWithin(t *testing.T, ch <-chan modules.ChangeEvent, d time.Duration) modules.ChangeEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(d):
		t.Fatalf("expected a ChangeEvent within %s, got none", d)
		return modules.ChangeEvent{}
	}
}

func assertNoEvent(t *testing.T, ch <-chan modules.ChangeEvent, d time.Duration) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("expected no ChangeEvent, got %+v", ev)
	case <-time.After(d):
	}
}

func newMonitorModule(t *testing.T) *hypervModule {
	t.Helper()
	m, ok := New(nil).(*hypervModule)
	require.True(t, ok, "New must return *hypervModule")
	return m
}

// AC#1: registering interest in N VMs creates exactly ONE host subscription.
func TestHypervMonitorSingleSubscription(t *testing.T) {
	calls, _ := fakeEstablish(t)
	m := newMonitorModule(t)

	for _, rid := range []string{"vm:alpha", "vm:bravo", "vm:charlie"} {
		require.NoError(t, m.Monitor(context.Background(), rid, nil))
	}

	require.Equal(t, 1, *calls, "exactly one EvtSubscribe host subscription for N VMs")
	require.NotZero(t, m.monSub, "subscription handle recorded")
	require.NotNil(t, m.Changes(), "Changes() channel is non-nil after Monitor")
}

// AC#2: a power-state change emits Modified; create emits Created; delete emits
// Deleted. Driven through the real decode path with representative event XML.
func TestHypervMonitorDecodeEmitsChangeEvents(t *testing.T) {
	fakeEstablish(t)
	m := newMonitorModule(t)
	require.NoError(t, m.Monitor(context.Background(), "vm:TestVM", nil))
	ch := m.Changes()

	cases := []struct {
		name string
		xml  string
		want modules.ChangeType
	}{
		{"started", workerEventXML(18500, "TestVM"), modules.ChangeTypeModified},
		{"turned-off", workerEventXML(18502, "TestVM"), modules.ChangeTypeModified},
		{"created", vmmsEventXML(13002, "TestVM"), modules.ChangeTypeCreated},
		{"deleted", vmmsEventXML(13003, "TestVM"), modules.ChangeTypeDeleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m.dispatchXML(tc.xml)
			ev := recvWithin(t, ch, 2*time.Second)
			require.Equal(t, "vm:TestVM", ev.ResourceID)
			require.Equal(t, tc.want, ev.ChangeType)
			require.Nil(t, ev.Details, "signal carries no actionable payload")
			require.NotZero(t, ev.Timestamp)
		})
	}
}

// AC#3: an event for a VM not registered in cfg is dropped — the monitor never
// fabricates an unmanaged resource as managed — and matched events carry no
// actionable Details.
func TestHypervMonitorForgedEvent(t *testing.T) {
	fakeEstablish(t)
	m := newMonitorModule(t)
	require.NoError(t, m.Monitor(context.Background(), "vm:real", nil))
	ch := m.Changes()

	// Forged/unrelated VM: not in the interest set -> no emission.
	m.dispatchXML(workerEventXML(18500, "evil-unmanaged"))
	assertNoEvent(t, ch, 300*time.Millisecond)

	// A genuinely registered VM still emits, with nil Details.
	m.dispatchXML(workerEventXML(18500, "real"))
	ev := recvWithin(t, ch, 2*time.Second)
	require.Equal(t, "vm:real", ev.ResourceID)
	require.Nil(t, ev.Details)
}

// AC: the event path produces no banned runtime-composition / PowerShell
// patterns. The monitor uses wevtapi syscalls exclusively; the only generated
// string is the structured subscription query.
func TestHypervMonitorBannedPatterns(t *testing.T) {
	q := strings.ToLower(monitorSubscriptionQuery())
	for _, banned := range []string{
		"iex", "invoke-expression", "-encodedcommand", "-command ",
		"bash -c", "eval", "powershell", "-executionpolicy",
	} {
		require.NotContainsf(t, q, banned, "subscription query must not contain %q", banned)
	}
}

// AC: Close releases the subscription handle and stops emission; it is
// idempotent.
func TestHypervMonitorCloseReleasesSubscription(t *testing.T) {
	_, teardowns := fakeEstablish(t)
	m := newMonitorModule(t)
	require.NoError(t, m.Monitor(context.Background(), "vm:x", nil))
	ch := m.Changes()
	require.NotZero(t, m.monSub)

	require.NoError(t, m.Close())
	require.Equal(t, 1, *teardowns, "teardown released the subscription exactly once")
	require.Zero(t, m.monSub, "subscription handle cleared")

	// The Changes() channel is closed so consumers unblock.
	_, open := <-ch
	require.False(t, open, "Changes() channel closed on Close")

	// Emission has stopped: dispatch after Close is a no-op and must not panic
	// (no send on a closed channel).
	require.NotPanics(t, func() { m.dispatch("x", modules.ChangeTypeModified) })

	// Close is idempotent.
	require.NoError(t, m.Close())
}

// changeTypeForEventID is the manifest-grounded core; assert the documented
// mappings directly so a future edit that drops an ID is caught.
func TestChangeTypeForEventID(t *testing.T) {
	created := []int{13002, 18302}
	deleted := []int{13003}
	modified := []int{18500, 18502, 18504, 18506, 18508, 18510, 18512, 18514,
		18516, 18518, 18524, 18526, 18528, 18592, 18594, 18596, 18608}

	for _, id := range created {
		ct, ok := changeTypeForEventID(id)
		require.Truef(t, ok, "event %d should be watched", id)
		require.Equalf(t, modules.ChangeTypeCreated, ct, "event %d -> Created", id)
	}
	for _, id := range deleted {
		ct, ok := changeTypeForEventID(id)
		require.Truef(t, ok, "event %d should be watched", id)
		require.Equalf(t, modules.ChangeTypeDeleted, ct, "event %d -> Deleted", id)
	}
	for _, id := range modified {
		ct, ok := changeTypeForEventID(id)
		require.Truef(t, ok, "event %d should be watched", id)
		require.Equalf(t, modules.ChangeTypeModified, ct, "event %d -> Modified", id)
	}
	// An unrelated/forged event ID is not watched.
	_, ok := changeTypeForEventID(1)
	require.False(t, ok, "unwatched event id must return ok=false")
}
