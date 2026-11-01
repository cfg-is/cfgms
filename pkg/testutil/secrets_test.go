// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testutil

import (
	"net"
	"strconv"
	"sync"
	"testing"
)

// TestReserveLoopbackAddress_AvoidsEphemeralRange pins the property that makes
// the reservation hold: a returned port must sit below the OS ephemeral range,
// so no concurrent ":0" bind anywhere on the host can be handed the same port
// in the gap between this reservation and the caller binding it. Returning an
// ephemeral port is what produced "bind: address already in use" on a
// merge-queue run.
func TestReserveLoopbackAddress_AvoidsEphemeralRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		address, err := ReserveLoopbackAddress()
		if err != nil {
			t.Fatalf("ReserveLoopbackAddress: %v", err)
		}
		_, portStr, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("SplitHostPort(%q): %v", address, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("port %q is not numeric: %v", portStr, err)
		}
		if port < reservedPortMin || port > reservedPortMax {
			t.Fatalf("port %d is outside the reserved band [%d, %d] — an ephemeral port can be "+
				"reassigned by any concurrent :0 bind on the host", port, reservedPortMin, reservedPortMax)
		}
	}
}

// TestReserveLoopbackAddress_NeverRepeatsWithinProcess pins the second half of
// the guarantee: two callers in one test binary must never receive the same
// port, including under concurrency. Without the reservation set, two tests in
// the same package could each be handed a port the other was about to bind.
func TestReserveLoopbackAddress_NeverRepeatsWithinProcess(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 25

	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*perGoroutine)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*perGoroutine)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				address, err := ReserveLoopbackAddress()
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				_, dup := seen[address]
				seen[address] = struct{}{}
				mu.Unlock()
				if dup {
					errs <- errDuplicate(address)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("ReserveLoopbackAddress: %v", err)
	}
	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("expected %d distinct addresses, got %d", goroutines*perGoroutine, len(seen))
	}
}

type duplicateAddressError string

func (e duplicateAddressError) Error() string {
	return "handed out " + string(e) + " twice within one process"
}

func errDuplicate(address string) error { return duplicateAddressError(address) }
