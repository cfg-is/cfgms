// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// resetGlobalLoggerFactory clears the global factory so a test can exercise the
// lazy-initialisation path rather than whatever an earlier test left behind. That
// ordering dependency is exactly why the data race was intermittent in CI: once any
// test had initialised the global, GetGlobalLoggerFactory never wrote again and the
// race window closed for the rest of the run.
func resetGlobalLoggerFactory(t *testing.T) {
	t.Helper()
	factoryMutex.Lock()
	previous := globalLoggerFactory
	globalLoggerFactory = nil
	factoryMutex.Unlock()

	t.Cleanup(func() {
		factoryMutex.Lock()
		globalLoggerFactory = previous
		factoryMutex.Unlock()
	})
}

// TestGetGlobalLoggerFactory_ConcurrentFirstUseIsRaceFree covers the lazy-init path
// that ForModule, ForComponent and GetLogger all funnel through.
//
// Before the mutex, concurrent first use raced on the nil check and the assignment in
// GetGlobalLoggerFactory. Reproduced from features/controller/server's concurrent
// server-creation test, where ten goroutines called api.NewSecretStore ->
// logging.ForComponent -> GetGlobalLoggerFactory at once. Run this package with
// -race to see the regression.
func TestGetGlobalLoggerFactory_ConcurrentFirstUseIsRaceFree(t *testing.T) {
	resetGlobalLoggerFactory(t)

	const goroutines = 32
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)

	factories := make([]*LoggerFactory, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(index int) {
			defer done.Done()
			start.Wait() // release everyone into the nil-check window together
			factories[index] = GetGlobalLoggerFactory()
		}(i)
	}

	start.Done()
	done.Wait()

	// Every caller must observe the same instance. Two goroutines each constructing
	// their own factory would silently split logging configuration between them.
	first := factories[0]
	require.NotNil(t, first, "lazy initialisation must yield a factory")
	for i, f := range factories {
		require.Same(t, first, f,
			"goroutine %d observed a different global factory instance", i)
	}
}

// TestGetGlobalLoggerFactory_ConcurrentWithInitializeIsRaceFree covers the writer side:
// InitializeGlobalLoggerFactory replacing the global while readers are calling
// GetGlobalLoggerFactory. Run with -race.
func TestGetGlobalLoggerFactory_ConcurrentWithInitializeIsRaceFree(t *testing.T) {
	resetGlobalLoggerFactory(t)

	const iterations = 64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			InitializeGlobalLoggerFactory("race-test", "writer")
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			require.NotNil(t, GetGlobalLoggerFactory(),
				"a reader must never observe a nil factory")
		}
	}()

	wg.Wait()
}
