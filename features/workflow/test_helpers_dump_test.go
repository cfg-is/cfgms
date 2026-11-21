// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"strings"
	"testing"
)

// TestAllGoroutineStacks_IsAllGoroutineAndNonEmpty proves the dump used on a
// wait timeout is non-empty, covers goroutines (not just the caller's), and
// names the calling test function.
func TestAllGoroutineStacks_IsAllGoroutineAndNonEmpty(t *testing.T) {
	// A second goroutine, parked until the dump is taken, proves all=true.
	release := make(chan struct{})
	parked := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(parked)
		<-release
	}()
	<-parked
	defer func() {
		close(release)
		<-done
	}()

	dump := string(allGoroutineStacks())

	if dump == "" {
		t.Fatal("dump is empty")
	}
	if !strings.Contains(dump, "goroutine ") {
		t.Errorf("dump has no goroutine header:\n%s", dump)
	}
	if !strings.Contains(dump, "TestAllGoroutineStacks_IsAllGoroutineAndNonEmpty") {
		t.Errorf("dump does not name the calling test function:\n%s", dump)
	}
	if got := strings.Count(dump, "goroutine "); got < 2 {
		t.Errorf("dump covers %d goroutine(s), want at least 2 (all=true)", got)
	}
}
