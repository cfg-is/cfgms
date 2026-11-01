// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume

// Test-support wrappers around the C ring primitives. cgo cannot be used directly
// in _test.go files, so these thin Go shims live in a regular (tagged) file and
// are called from consume_ring_windows_test.go to exercise the SPSC ring + drain
// without ETW privilege.
package dex

/*
#include "consume_etw_windows.h"
*/
import "C"

// ringEvent is the Go view of a drained CfgmsEvent, for test assertions.
type ringEvent struct {
	Timestamp   uint64
	PID         uint32
	TID         uint32
	ProviderIdx uint16
	EventID     uint16
	Opcode      uint8
}

func ringTestReset()              { C.cfgms_reset() }
func ringTestTotalSeen() uint64   { return uint64(C.cfgms_total_seen()) }
func ringTestDroppedRing() uint64 { return uint64(C.cfgms_dropped_ring()) }

func ringTestEnqueue(pid uint32, providerIdx, eventID uint16) {
	C.cfgms_test_enqueue(C.uint(pid), C.ushort(providerIdx), C.ushort(eventID))
}

func ringTestDrain(max int) []ringEvent {
	buf := make([]C.CfgmsEvent, max)
	n := int(C.cfgms_drain(&buf[0], C.int(max)))
	out := make([]ringEvent, n)
	for i := 0; i < n; i++ {
		out[i] = ringEvent{
			Timestamp:   uint64(buf[i].timestamp),
			PID:         uint32(buf[i].pid),
			TID:         uint32(buf[i].tid),
			ProviderIdx: uint16(buf[i].provider_idx),
			EventID:     uint16(buf[i].event_id),
			Opcode:      uint8(buf[i].opcode),
		}
	}
	return out
}
