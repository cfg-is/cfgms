// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume

// Non-live unit tests for the consume PoC's pure Go logic (attribution ordering,
// provider selection, decode-sample parsing, well-known PID labelling). These
// need no ETW privilege, so they exercise the drain-side logic anywhere the
// dexconsume tag is built. The end-to-end consume proof is TestDexConsumeLive,
// which requires the SYSTEM StartTrace privilege.
package dex

import (
	"reflect"
	"testing"
)

func TestSelectConsumeProviders(t *testing.T) {
	// Empty want → the full set (4 collector providers + Kernel-File).
	all := selectConsumeProviders(nil)
	if len(all) != len(etwProviders)+1 {
		t.Fatalf("empty selector must return the full consume set: got %d, want %d", len(all), len(etwProviders)+1)
	}

	// Explicit subset → only the named providers, order preserved.
	got := selectConsumeProviders([]string{"Microsoft-Windows-Kernel-File", "Microsoft-Windows-DNS-Client"})
	var names []string
	for _, p := range got {
		names = append(names, p.name)
	}
	// Order follows consumeProviderSet (DNS-Client precedes Kernel-File there).
	want := []string{"Microsoft-Windows-DNS-Client", "Microsoft-Windows-Kernel-File"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("subset selection preserves set order: got %v, want %v", names, want)
	}

	// Unknown name → dropped, not an error.
	if len(selectConsumeProviders([]string{"Not-A-Provider"})) != 0 {
		t.Fatalf("unknown provider name must select nothing")
	}
}

func TestTopAttribution(t *testing.T) {
	counts := map[uint32]int{100: 5, 200: 50, 300: 1, 400: 20}
	images := map[uint32]string{100: "a.exe", 200: "b.exe", 300: "c.exe", 400: "d.exe"}

	top := topAttribution(counts, images, 2)
	if len(top) != 2 {
		t.Fatalf("n=2 must cap the result at 2: got %d", len(top))
	}
	// Descending by count: 200 (50) then 400 (20).
	if top[0].PID != 200 || top[0].Count != 50 || top[0].Image != "b.exe" {
		t.Fatalf("highest-count pid must sort first: got %+v", top[0])
	}
	if top[1].PID != 400 || top[1].Count != 20 {
		t.Fatalf("second-highest must follow: got %+v", top[1])
	}

	// n larger than the map returns all entries.
	if len(topAttribution(counts, images, 100)) != 4 {
		t.Fatalf("n greater than map size must return all entries")
	}
}

func TestImageForPID_WellKnown(t *testing.T) {
	// PID 0 and 4 are labelled without a syscall (they cannot be OpenProcess'd).
	if got := imageForPID(0); got != "System Idle (pid 0)" {
		t.Fatalf("pid 0 label: got %q", got)
	}
	if got := imageForPID(4); got != "System (pid 4)" {
		t.Fatalf("pid 4 label: got %q", got)
	}
}

func TestReadDecodeSample_EmptyBeforeRun(t *testing.T) {
	// With no consume run, the C decode buffer is empty and the reader returns nil
	// rather than a spurious empty line.
	if got := readDecodeSample(); got != nil {
		t.Fatalf("decode sample must be nil before any run: got %v", got)
	}
}
