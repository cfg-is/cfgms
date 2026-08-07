// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The logging provider registry is populated by package init() functions, so it
// runs in every binary AND every test binary. It used to report registration with
// fmt.Printf, putting provider chatter on stdout for every `go test -v` run: two
// lines per run here, and 701 such lines were measured being carried through
// agent context. A library writing to a process's stdout is wrong regardless of
// who reads it.
//
// These tests pin both halves of the fix, because a change that only silenced the
// output would pass a stdout assertion while destroying the diagnostic:
//   - nothing reaches stdout, and
//   - the message still reaches a configured sink.

// stubLoggingProvider is a test implementation of LoggingProvider — enough surface
// to pass validateLoggingProvider and reach the registration message. Zero-value
// LoggingCapabilities satisfies every bound the validator checks.
type stubLoggingProvider struct {
	name      string
	available bool
	availErr  error
}

func (s *stubLoggingProvider) Name() string        { return s.name }
func (s *stubLoggingProvider) Description() string { return "stub provider for registry tests" }
func (s *stubLoggingProvider) GetVersion() string  { return "0.0.1" }
func (s *stubLoggingProvider) Available() (bool, error) {
	return s.available, s.availErr
}
func (s *stubLoggingProvider) GetCapabilities() LoggingCapabilities { return LoggingCapabilities{} }
func (s *stubLoggingProvider) Initialize(map[string]interface{}) error {
	return nil
}
func (s *stubLoggingProvider) Close() error                               { return nil }
func (s *stubLoggingProvider) WriteEntry(context.Context, LogEntry) error { return nil }
func (s *stubLoggingProvider) WriteBatch(context.Context, []LogEntry) error {
	return nil
}
func (s *stubLoggingProvider) QueryTimeRange(context.Context, TimeRangeQuery) ([]LogEntry, error) {
	return nil, nil
}
func (s *stubLoggingProvider) QueryCount(context.Context, CountQuery) (int64, error) {
	return 0, nil
}
func (s *stubLoggingProvider) QueryLevels(context.Context, LevelQuery) ([]LogEntry, error) {
	return nil, nil
}
func (s *stubLoggingProvider) ApplyRetentionPolicy(context.Context, RetentionPolicy) error {
	return nil
}
func (s *stubLoggingProvider) GetStats(context.Context) (ProviderStats, error) {
	return ProviderStats{}, nil
}
func (s *stubLoggingProvider) Flush(context.Context) error { return nil }

// recordingSink captures what the registry reports. Mutex-guarded because
// SetRegistryLogger advertises concurrency safety.
type recordingSink struct {
	mu    sync.Mutex
	infos []string
	warns []string
}

func (r *recordingSink) Info(msg string, _ ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos = append(r.infos, msg)
}

func (r *recordingSink) Warn(msg string, _ ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warns = append(r.warns, msg)
}

func (r *recordingSink) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append(append([]string{}, r.infos...), r.warns...)
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns everything fn
// wrote. Restores os.Stdout even if fn panics, so one failure cannot silence the
// rest of the suite.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	func() {
		defer func() {
			_ = w.Close()
		}()
		fn()
	}()
	out := <-done
	_ = r.Close()
	return out
}

// uniqueName keeps each test's registration out of the others' way: the registry
// is process-global and shared with whatever the package's init()s registered.
func uniqueName(t *testing.T) string {
	t.Helper()
	return "stub-" + strings.ReplaceAll(t.Name(), "/", "-")
}

func TestRegisterLoggingProvider_WritesNothingToStdout(t *testing.T) {
	t.Cleanup(func() { SetRegistryLogger(nil) })
	SetRegistryLogger(&recordingSink{})

	out := captureStdout(t, func() {
		RegisterLoggingProvider(&stubLoggingProvider{name: uniqueName(t), available: true})
	})
	assert.Empty(t, out, "registration must not write to stdout; a library owns no process's stdout")
}

func TestRegisterLoggingProviderFactory_WritesNothingToStdout(t *testing.T) {
	t.Cleanup(func() { SetRegistryLogger(nil) })
	SetRegistryLogger(&recordingSink{})

	name := uniqueName(t)
	out := captureStdout(t, func() {
		RegisterLoggingProviderFactory(func() LoggingProvider {
			return &stubLoggingProvider{name: name, available: true}
		})
	})
	assert.Empty(t, out, "factory registration must not write to stdout")
}

func TestUnavailableProvider_WritesNothingToStdout(t *testing.T) {
	// The "reports as unavailable" line was one of the two printed on every run.
	t.Cleanup(func() { SetRegistryLogger(nil) })
	sink := &recordingSink{}
	SetRegistryLogger(sink)

	name := uniqueName(t)
	out := captureStdout(t, func() {
		RegisterLoggingProvider(&stubLoggingProvider{
			name:      name,
			available: false,
			availErr:  errors.New("provider not configured"),
		})
	})
	assert.Empty(t, out, "the unavailable notice must not reach stdout")
	assert.True(t, containsSubstr(sink.all(), "reports as unavailable"),
		"the unavailable notice must still be reported somewhere: %v", sink.all())
}

func TestRegistrationIsStillReportedToTheSink(t *testing.T) {
	// The other half: silencing stdout must not mean losing the diagnostic.
	t.Cleanup(func() { SetRegistryLogger(nil) })
	sink := &recordingSink{}
	SetRegistryLogger(sink)

	name := uniqueName(t)
	RegisterLoggingProvider(&stubLoggingProvider{name: name, available: true})

	require.NotEmpty(t, sink.infos, "a successful registration must be reported")
	assert.True(t, containsSubstr(sink.infos, "Registered logging provider: "+name),
		"the message must name the provider: %v", sink.infos)
}

func TestInvalidProviderIsReportedAsAWarning(t *testing.T) {
	t.Cleanup(func() { SetRegistryLogger(nil) })
	sink := &recordingSink{}
	SetRegistryLogger(sink)

	// An empty name fails validateLoggingProvider.
	out := captureStdout(t, func() {
		RegisterLoggingProvider(&stubLoggingProvider{name: "", available: true})
	})
	assert.Empty(t, out, "a rejected registration must not write to stdout either")
	assert.True(t, containsSubstr(sink.warns, "Failed to register logging provider"),
		"a rejected registration must warn: %v", sink.warns)
}

func TestNilFactoryIsReportedAsAWarning(t *testing.T) {
	t.Cleanup(func() { SetRegistryLogger(nil) })
	sink := &recordingSink{}
	SetRegistryLogger(sink)

	out := captureStdout(t, func() {
		RegisterLoggingProviderFactory(func() LoggingProvider { return nil })
	})
	assert.Empty(t, out)
	assert.True(t, containsSubstr(sink.warns, "returned nil instance"),
		"a nil factory instance must warn: %v", sink.warns)
}

func TestSetRegistryLoggerNilRestoresTheNoopSink(t *testing.T) {
	// Passing nil must not leave a nil interface behind for the next registration
	// to dereference — every binary that never configures a logger relies on this.
	SetRegistryLogger(&recordingSink{})
	SetRegistryLogger(nil)

	name := uniqueName(t)
	out := captureStdout(t, func() {
		assert.NotPanics(t, func() {
			RegisterLoggingProvider(&stubLoggingProvider{name: name, available: true})
		})
	})
	assert.Empty(t, out, "the default sink must be silent, not stdout")
}

func TestRegistrySinkIsSatisfiedByAFullLogger(t *testing.T) {
	// RegistrySink exists only because pkg/logging imports this package, so the
	// dependency cannot run the other way. Its whole value is that a real
	// pkg/logging.Logger satisfies it implicitly — assert the shape that makes
	// that true, so a signature drift here is caught in this package rather than
	// as a confusing failure at a call site.
	var _ RegistrySink = (*recordingSink)(nil)
	var sink RegistrySink = &fullLoggerShape{}
	assert.NotNil(t, sink)
}

// fullLoggerShape mirrors pkg/logging.Logger's method set. Compiling proves a
// value with that surface is assignable to RegistrySink.
type fullLoggerShape struct{}

func (fullLoggerShape) Debug(string, ...interface{})                     {}
func (fullLoggerShape) Info(string, ...interface{})                      {}
func (fullLoggerShape) Warn(string, ...interface{})                      {}
func (fullLoggerShape) Error(string, ...interface{})                     {}
func (fullLoggerShape) Fatal(string, ...interface{})                     {}
func (fullLoggerShape) DebugCtx(context.Context, string, ...interface{}) {}
func (fullLoggerShape) InfoCtx(context.Context, string, ...interface{})  {}
func (fullLoggerShape) WarnCtx(context.Context, string, ...interface{})  {}
func (fullLoggerShape) ErrorCtx(context.Context, string, ...interface{}) {}
func (fullLoggerShape) FatalCtx(context.Context, string, ...interface{}) {}

func containsSubstr(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
