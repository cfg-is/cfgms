// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume

// Non-live coverage of the SPSC ring buffer — the load-bearing concurrent core —
// exercised through the same producer path the ETW callback uses (via the
// ringTest* wrappers in consume_ringtest_windows.go), with no ETW privilege.
package dex

import "testing"

// ringCap mirrors RING_CAP in consume_etw_windows.c.
const ringCap = 1 << 16

func TestRing_PushDrainFIFO(t *testing.T) {
	ringTestReset()

	const n = 1000
	for i := 0; i < n; i++ {
		ringTestEnqueue(uint32(1000+i), uint16(i%4), uint16(i))
	}

	got := ringTestDrain(4096)
	if len(got) != n {
		t.Fatalf("drained %d events, want %d", len(got), n)
	}
	// Events come out in FIFO order with the fields the producer wrote.
	for i := 0; i < n; i++ {
		if got[i].PID != uint32(1000+i) {
			t.Fatalf("event %d: pid=%d, want %d (FIFO order broken)", i, got[i].PID, 1000+i)
		}
		if got[i].EventID != uint16(i) {
			t.Fatalf("event %d: event_id=%d, want %d", i, got[i].EventID, i)
		}
		if got[i].ProviderIdx != uint16(i%4) {
			t.Fatalf("event %d: provider_idx=%d, want %d", i, got[i].ProviderIdx, i%4)
		}
	}
	if seen := ringTestTotalSeen(); seen != n {
		t.Fatalf("total_seen=%d, want %d", seen, n)
	}
	if dropped := ringTestDroppedRing(); dropped != 0 {
		t.Fatalf("dropped_ring=%d, want 0", dropped)
	}
	// A second drain on an empty ring returns nothing.
	if got := ringTestDrain(4096); len(got) != 0 {
		t.Fatalf("second drain returned %d, want 0", len(got))
	}
}

func TestRing_DropsWhenFull(t *testing.T) {
	ringTestReset()

	const extra = 500
	for i := 0; i < ringCap+extra; i++ {
		ringTestEnqueue(uint32(i), 0, 0)
	}
	// Every event is seen; exactly the overflow beyond capacity is dropped.
	if seen := ringTestTotalSeen(); seen != ringCap+extra {
		t.Fatalf("total_seen=%d, want %d", seen, ringCap+extra)
	}
	if dropped := ringTestDroppedRing(); dropped != extra {
		t.Fatalf("dropped_ring=%d, want %d", dropped, extra)
	}
	// The ring holds exactly its capacity for the consumer to drain.
	if got := ringTestDrain(ringCap); len(got) != ringCap {
		t.Fatalf("drained %d, want %d (full ring)", len(got), ringCap)
	}
}

func TestRing_ResetClearsState(t *testing.T) {
	ringTestReset()
	for i := 0; i < 10; i++ {
		ringTestEnqueue(uint32(i), 0, 0)
	}
	ringTestReset()
	if seen := ringTestTotalSeen(); seen != 0 {
		t.Fatalf("reset must zero total_seen: got %d", seen)
	}
	if got := ringTestDrain(16); len(got) != 0 {
		t.Fatalf("reset must empty the ring: drained %d", len(got))
	}
}
