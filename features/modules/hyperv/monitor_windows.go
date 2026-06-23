// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hyperv

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/features/modules"
)

// Hyper-V VM-state Monitor (modules.Monitor, #2114).
//
// A single host-level Windows Event Log subscription (one EvtSubscribe handle)
// watches the Hyper-V VMMS and Worker *Admin* channels for VM lifecycle and
// power-state events and fans them out to per-VM modules.ChangeEvents on the one
// Changes() channel. There is no persistent helper process and no PowerShell —
// the subscription is driven entirely through wevtapi.dll via
// golang.org/x/sys/windows (already a direct dependency; no new dependency, no
// CGO).
//
// The EventID -> ChangeType map below is grounded in the provider event
// manifests (read non-privileged with `wevtutil gp <provider> /ge:true`):
//
//	Microsoft-Windows-Hyper-V-VMMS  (Admin channel)
//	  13002  "A new virtual machine '%1' was created"   -> Created
//	  13003  "The virtual machine '%1' was deleted"     -> Deleted
//	  18302  "The virtual machine '%1' was imported"    -> Created
//
//	Microsoft-Windows-Hyper-V-Worker (Admin channel) — EnabledState changes
//	  18500 started, 18502 turned off, 18504/18506/18508 shut down,
//	  18510 saved, 18512/18514 reset, 18516 paused, 18518 resumed,
//	  18524/18526/18528 critical-error transitions, 18592 fast-restored,
//	  18594 fast-saved, 18596 restored, 18608 hibernated  -> Modified
//
// In every one of these events %1 is the VM name and %2 the VM ID, so the
// emitted ChangeEvent.ResourceID is "vm:<name>".

// wevtapi.dll bindings. NewLazySystemDLL resolves from %SystemRoot%\System32,
// so this is not susceptible to working-directory DLL planting.
var (
	modwevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modwevtapi.NewProc("EvtNext")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	// monitorChannelDepth bounds the fan-out channel. The signal carries no
	// actionable payload (the consumer re-checks via Get), so a modest buffer
	// is sufficient; a slow consumer drops oldest-safe (see dispatch).
	monitorChannelDepth = 64
)

// changeTypeForEventID maps a Hyper-V event ID to the modules.ChangeType it
// represents, grounded in the provider manifests (see file header). The bool is
// false for event IDs outside the watched set (which the structured query
// already excludes; the check is defence in depth).
func changeTypeForEventID(id int) (modules.ChangeType, bool) {
	switch id {
	case 13002, 18302:
		return modules.ChangeTypeCreated, true
	case 13003:
		return modules.ChangeTypeDeleted, true
	case 18500, 18502, 18504, 18506, 18508, 18510, 18512, 18514,
		18516, 18518, 18524, 18526, 18528, 18592, 18594, 18596, 18608:
		return modules.ChangeTypeModified, true
	default:
		return 0, false
	}
}

// monitorSubscriptionQuery is the structured query for the single host
// subscription. Channel=NULL + a <QueryList> spanning both -Admin channels is
// what keeps this to ONE EvtSubscribe handle rather than one per channel or one
// per VM (the epic's single-subscription invariant).
func monitorSubscriptionQuery() string {
	worker := []int{18500, 18502, 18504, 18506, 18508, 18510, 18512, 18514,
		18516, 18518, 18524, 18526, 18528, 18592, 18594, 18596, 18608}
	vmms := []int{13002, 13003, 18302}
	return "<QueryList>\n" +
		"  <Query Id=\"0\">\n" +
		"    <Select Path=\"Microsoft-Windows-Hyper-V-Worker-Admin\">" + eventIDPredicate(worker) + "</Select>\n" +
		"    <Select Path=\"Microsoft-Windows-Hyper-V-VMMS-Admin\">" + eventIDPredicate(vmms) + "</Select>\n" +
		"  </Query>\n" +
		"</QueryList>"
}

func eventIDPredicate(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("EventID=%d", id)
	}
	return "*[System[(" + strings.Join(parts, " or ") + ")]]"
}

// evtEstablish creates the host subscription and starts the reader goroutine.
// It is a package-level seam so unit tests can exercise the interest registry,
// decode, fan-out, and Close logic without touching the live Event Log (which
// requires privilege and real VM churn). The real implementation is
// realEvtEstablish; tests swap it and restore it.
var evtEstablish = realEvtEstablish

// realEvtEstablish opens the single EvtSubscribe subscription in pull mode (a
// signalled auto-reset event + EvtNext loop) and wires teardown onto m. The
// caller holds m.monMu.
func realEvtEstablish(m *hypervModule) error {
	signal, err := windows.CreateEvent(nil, 0 /*auto-reset*/, 0 /*non-signalled*/, nil)
	if err != nil {
		return fmt.Errorf("hyperv monitor: create signal event: %w", err)
	}

	query, err := windows.UTF16PtrFromString(monitorSubscriptionQuery())
	if err != nil {
		windows.CloseHandle(signal)
		return fmt.Errorf("hyperv monitor: encode query: %w", err)
	}

	sub, _, callErr := procEvtSubscribe.Call(
		0,                              // Session = NULL (local)
		uintptr(signal),                // SignalEvent (pull mode)
		0,                              // ChannelPath = NULL (structured query)
		uintptr(unsafe.Pointer(query)), // Query = <QueryList>
		0,                              // Bookmark = NULL
		0,                              // Context = NULL
		0,                              // Callback = NULL (pull mode)
		uintptr(evtSubscribeToFutureEvents),
	)
	if sub == 0 {
		windows.CloseHandle(signal)
		return fmt.Errorf("hyperv monitor: EvtSubscribe failed: %w", callErr)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.pump(sub, signal, stop)
	}()

	m.monSub = sub
	m.monTeardown = func() error {
		close(stop)
		// Closing the subscription unblocks EvtNext; setting the signal unblocks
		// the wait. Then wait for the goroutine to return before closing handles.
		windows.SetEvent(signal)
		wg.Wait()
		procEvtClose.Call(sub)
		windows.CloseHandle(signal)
		return nil
	}
	return nil
}

// pump waits for the subscription signal and drains ready events, rendering and
// dispatching each, until stop is closed.
func (m *hypervModule) pump(sub uintptr, signal windows.Handle, stop <-chan struct{}) {
	const batch = 16
	events := make([]uintptr, batch)
	for {
		select {
		case <-stop:
			return
		default:
		}
		// Wait up to 1s so a closed stop channel is noticed promptly even when
		// no events arrive.
		_, _ = windows.WaitForSingleObject(signal, 1000)
		for {
			var returned uint32
			ok, _, _ := procEvtNext.Call(
				sub,
				uintptr(batch),
				uintptr(unsafe.Pointer(&events[0])),
				0, // Timeout: return immediately
				0,
				uintptr(unsafe.Pointer(&returned)),
			)
			if ok == 0 || returned == 0 {
				break // ERROR_NO_MORE_ITEMS or error: back to wait
			}
			for i := 0; i < int(returned); i++ {
				if xmlStr, err := renderEventXML(events[i]); err == nil {
					m.dispatchXML(xmlStr)
				}
				procEvtClose.Call(events[i])
			}
		}
	}
}

// renderEventXML renders one event handle to its XML form.
func renderEventXML(event uintptr) (string, error) {
	var bufUsed, propCount uint32
	// First call sizes the buffer: it returns FALSE with
	// ERROR_INSUFFICIENT_BUFFER and sets bufUsed to the required byte count. A
	// zero size means a different failure (e.g. ERROR_EVT_INVALID_EVENT_DATA);
	// surface that errno rather than lumping it into a generic message.
	_, _, sizeErr := procEvtRender.Call(0, event, uintptr(evtRenderEventXML), 0, 0,
		uintptr(unsafe.Pointer(&bufUsed)), uintptr(unsafe.Pointer(&propCount)))
	if bufUsed == 0 {
		return "", fmt.Errorf("hyperv monitor: EvtRender sizing returned 0: %w", sizeErr)
	}
	buf := make([]uint16, (bufUsed+1)/2)
	ok, _, callErr := procEvtRender.Call(0, event, uintptr(evtRenderEventXML),
		uintptr(bufUsed), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)), uintptr(unsafe.Pointer(&propCount)))
	if ok == 0 {
		return "", fmt.Errorf("hyperv monitor: EvtRender: %w", callErr)
	}
	return windows.UTF16ToString(buf), nil
}

// renderedEvent is the subset of the Windows event XML schema the monitor reads.
// Hyper-V emits the VM name under <UserData> (typically
// UserData/VmlEventLog/VmName); the EventData fallbacks cover providers that use
// the generic <EventData> shape instead.
type renderedEvent struct {
	System struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// dispatchXML decodes one rendered event and, if it is a watched VM event,
// dispatches it. Malformed XML or unwatched IDs are ignored.
func (m *hypervModule) dispatchXML(eventXML string) {
	var ev renderedEvent
	if err := xml.Unmarshal([]byte(eventXML), &ev); err != nil {
		return
	}
	ct, ok := changeTypeForEventID(ev.System.EventID)
	if !ok {
		return
	}
	name := vmNameFromEvent(ev)
	if name == "" {
		return
	}
	m.dispatch(name, ct)
}

// vmNameFromEvent extracts the VM name robustly across the event shapes Hyper-V
// uses: the UserData VmName element first, then a named EventData field, then the
// first positional EventData value (%1 is always the VM name in these events).
func vmNameFromEvent(ev renderedEvent) string {
	if name := firstElementText(ev.UserData.Inner, "VmName"); name != "" {
		return name
	}
	for _, d := range ev.EventData.Data {
		if strings.EqualFold(d.Name, "VmName") || strings.EqualFold(d.Name, "Name") {
			if v := strings.TrimSpace(d.Value); v != "" {
				return v
			}
		}
	}
	if len(ev.EventData.Data) > 0 {
		return strings.TrimSpace(ev.EventData.Data[0].Value)
	}
	return ""
}

// firstElementText returns the chardata of the first element with the given
// local name found in the XML fragment, ignoring namespaces.
func firstElementText(fragment, local string) string {
	if fragment == "" {
		return ""
	}
	dec := xml.NewDecoder(strings.NewReader(fragment))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == local {
			var text string
			if err := dec.DecodeElement(&text, &se); err != nil {
				return ""
			}
			return strings.TrimSpace(text)
		}
	}
}

// dispatch fans a decoded VM event out to the Changes() channel, but only for
// resourceIDs that were registered via Monitor — an event for an unregistered
// ("forged"/unrelated) VM is dropped, so the monitor never fabricates an
// unmanaged resource as managed. The ChangeEvent carries no actionable Details
// (Details is nil): the signal conveys only *which* resource changed, and the
// steward consumer re-checks via Get().
func (m *hypervModule) dispatch(vmName string, ct modules.ChangeType) {
	resourceID := "vm:" + vmName

	m.monMu.Lock()
	if m.monClosed || m.monChanges == nil {
		m.monMu.Unlock()
		return
	}
	if _, watched := m.monInterest[resourceID]; !watched {
		m.monMu.Unlock()
		return
	}
	ch := m.monChanges
	m.monMu.Unlock()

	ev := modules.ChangeEvent{
		ResourceID: resourceID,
		Timestamp:  time.Now().Unix(),
		ChangeType: ct,
		Details:    nil,
	}
	// Non-blocking send: a wedged consumer must not block the reader goroutine.
	select {
	case ch <- ev:
	default:
	}
}

// Monitor registers interest in a resource (resourceID "vm:<name>") and ensures
// the single host subscription exists. The config argument is unused: the event
// signal carries no actionable payload, so no per-resource configuration is
// retained. Satisfies modules.Monitor.
func (m *hypervModule) Monitor(_ context.Context, resourceID string, _ modules.ConfigState) error {
	m.monMu.Lock()
	defer m.monMu.Unlock()
	if m.monClosed {
		return fmt.Errorf("hyperv monitor: closed")
	}
	if m.monChanges == nil {
		m.monChanges = make(chan modules.ChangeEvent, monitorChannelDepth)
	}
	if m.monInterest == nil {
		m.monInterest = make(map[string]struct{})
	}
	m.monInterest[resourceID] = struct{}{}

	// Create the subscription on first interest; subsequent Monitor calls reuse
	// the one host subscription (single-subscription invariant).
	if m.monSub == 0 && m.monTeardown == nil {
		if err := evtEstablish(m); err != nil {
			return err
		}
	}
	return nil
}

// Changes returns the fan-out channel. It is created on first Monitor (or here,
// lazily) so a caller can select on it before registering interest.
func (m *hypervModule) Changes() <-chan modules.ChangeEvent {
	m.monMu.Lock()
	defer m.monMu.Unlock()
	if m.monChanges == nil {
		m.monChanges = make(chan modules.ChangeEvent, monitorChannelDepth)
	}
	return m.monChanges
}

// Close stops monitoring, releases the subscription and signal handles, and
// halts emission. It is idempotent. Satisfies modules.Monitor.
func (m *hypervModule) Close() error {
	m.monMu.Lock()
	teardown := m.monTeardown
	m.monTeardown = nil
	m.monSub = 0
	m.monClosed = true
	ch := m.monChanges
	m.monChanges = nil
	m.monMu.Unlock()

	var err error
	if teardown != nil {
		err = teardown()
	}
	if ch != nil {
		close(ch)
	}
	return err
}
