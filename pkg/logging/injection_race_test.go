// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"path/filepath"
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

// newRaceTestModuleLogger initialises a real file-backed global logging manager and
// returns a module logger bound to it. A manager is required for this test to mean
// anything: logWithProvider returns early when ml.manager is nil, so without one the
// read side of the map race (its range over defaultFields) never executes.
func newRaceTestModuleLogger(t *testing.T, moduleName string) *ModuleLogger {
	t.Helper()

	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":      filepath.Join(t.TempDir(), "logs"),
			"file_prefix":    "injection-race-test",
			"retention_days": 1,
		},
		Level:       "INFO",
		ServiceName: "injection-race-test",
		Component:   "controller",
		AsyncWrites: false,
	}

	require.NoError(t, InitializeGlobalLogging(config))
	t.Cleanup(func() {
		if manager := GetGlobalLoggingManager(); manager != nil {
			_ = manager.Close()
		}
	})

	logger := NewModuleLogger(moduleName, "controller")
	require.True(t, logger.IsProviderAvailable(),
		"module logger must be bound to the initialised manager")
	return logger
}

// TestModuleLogger_ConcurrentWithTenantIsRaceFree covers the shape every component that
// spawns workers from a Start method has: one shared *ModuleLogger field, and several
// goroutines each deriving a per-request logger from it while others log through it.
//
// Before With* became copy-on-write, WithTenant wrote ml.defaultFields["tenant_id"] into
// the shared receiver, so these goroutines performed concurrent map writes against each
// other and against logWithProvider's range over the same map. It was latent only while
// the tenant ID was always "" (Issue #4326) and the guard skipped the write. Reproduced
// from SIEMProcessor.Start (features/workflow/trigger/siem.go) and CronScheduler.Start
// (features/workflow/trigger/scheduler.go). Run with -race to see the regression.
func TestModuleLogger_ConcurrentWithTenantIsRaceFree(t *testing.T) {
	shared := newRaceTestModuleLogger(t, "concurrent-tenant")
	ctx := context.Background()

	const goroutines = 16
	const iterations = 20

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(index int) {
			defer done.Done()
			start.Wait() // release everyone into the same window
			tenantID := "tenant-" + string(rune('a'+index))
			for j := 0; j < iterations; j++ {
				// Writer side: derive a per-tenant logger from the shared instance.
				tenantLogger := shared.WithTenant(tenantID).WithSession("session").
					WithField("iteration", j)
				tenantLogger.InfoCtx(ctx, "derived logger write")

				// Reader side: log straight through the shared instance, which ranges
				// over the very map the derivations used to mutate.
				shared.InfoCtx(ctx, "shared logger read")
			}
		}(i)
	}

	start.Done()
	done.Wait()

	// The shared logger must be exactly as constructed: no tenancy, no session and no
	// per-request field may have leaked onto it from any derivation.
	require.Equal(t, map[string]interface{}{
		"module":    "concurrent-tenant",
		"component": "controller",
	}, shared.defaultFields, "derivations must not write to the shared logger's fields")
}

// TestModuleLogger_WithMethodsDeriveInsteadOfMutating pins the semantics the race fix
// depends on. Two derivations from one base logger must be independent: when With*
// mutated the receiver, the second derivation's tenant overwrote the first's, so a log
// line written for one tenant carried another tenant's ID — a tenancy leak as well as a
// race.
func TestModuleLogger_WithMethodsDeriveInsteadOfMutating(t *testing.T) {
	base := NewModuleLogger("derive-test", "controller")

	tenantA := base.WithTenant("tenant-a").WithField("request", "a")
	tenantB := base.WithTenant("tenant-b").WithField("request", "b")

	require.NotSame(t, base, tenantA, "WithTenant must return a derived logger")
	require.NotSame(t, tenantA, tenantB, "each derivation must be independent")

	require.Equal(t, "tenant-a", tenantA.defaultFields["tenant_id"])
	require.Equal(t, "a", tenantA.defaultFields["request"])
	require.Equal(t, "tenant-b", tenantB.defaultFields["tenant_id"])
	require.Equal(t, "b", tenantB.defaultFields["request"])

	require.NotContains(t, base.defaultFields, "tenant_id",
		"tenant must not leak back onto the base logger")
	require.NotContains(t, base.defaultFields, "request",
		"per-request field must not leak back onto the base logger")

	// WithFields and WithSession derive on the same terms.
	withFields := base.WithFields(map[string]interface{}{"a": 1, "b": 2})
	require.Equal(t, 1, withFields.defaultFields["a"])
	require.NotContains(t, base.defaultFields, "a")

	withSession := base.WithSession("session-1")
	require.Equal(t, "session-1", withSession.defaultFields["session_id"])
	require.NotContains(t, base.defaultFields, "session_id")

	// An empty value adds nothing, and must not derive a needless copy.
	require.Same(t, base, base.WithTenant(""), "empty tenant adds no tenancy")
	require.Same(t, base, base.WithSession(""), "empty session adds no session")

	// The base logger itself keeps only its construction-time identity fields.
	require.Equal(t, map[string]interface{}{
		"module":    "derive-test",
		"component": "controller",
	}, base.defaultFields)
}
