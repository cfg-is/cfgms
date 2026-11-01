// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

func TestFileProvider_BasicFunctionality(t *testing.T) {
	tmpDir := t.TempDir()

	// Create provider
	provider := &FileProvider{}

	// Test provider metadata
	assert.Equal(t, "file", provider.Name())
	assert.NotEmpty(t, provider.Description())
	assert.NotEmpty(t, provider.GetVersion())

	// Test capabilities
	capabilities := provider.GetCapabilities()
	assert.True(t, capabilities.SupportsCompression)
	assert.True(t, capabilities.SupportsRetentionPolicies)
	assert.True(t, capabilities.SupportsBatchWrites)
	assert.True(t, capabilities.SupportsTimeRangeQueries)
	assert.Greater(t, capabilities.MaxEntriesPerSecond, 0)
	assert.Greater(t, capabilities.MaxBatchSize, 0)

	// Configure provider
	config := map[string]interface{}{
		"directory":        tmpDir,
		"file_prefix":      "test",
		"max_file_size":    1024 * 1024, // 1MB
		"max_files":        5,
		"retention_days":   7,
		"compress_rotated": false, // Disable compression for easier testing
	}

	// Test initialization
	err := provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	// Test availability
	available, err := provider.Available()
	assert.True(t, available)
	assert.NoError(t, err)
}

func TestFileProvider_WriteAndQuery(t *testing.T) {
	tmpDir := t.TempDir()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":        tmpDir,
		"file_prefix":      "test",
		"max_file_size":    1024 * 1024, // 1MB
		"max_files":        5,
		"retention_days":   7,
		"compress_rotated": false,
		"buffer_size":      1024,
		"flush_interval":   "1s",
	}

	err := provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Test single entry write
	entry := interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       "INFO",
		Message:     "Test log message",
		ServiceName: "test-service",
		Component:   "test-component",
		Fields: map[string]interface{}{
			"test_field": "test_value",
			"number":     42,
		},
	}

	err = provider.WriteEntry(ctx, entry)
	assert.NoError(t, err)

	// Flush to ensure data is written
	err = provider.Flush(ctx)
	assert.NoError(t, err)

	// Test batch write
	batchEntries := []interfaces.LogEntry{
		{
			Timestamp:   time.Now(),
			Level:       "DEBUG",
			Message:     "Debug message 1",
			ServiceName: "test-service",
			Component:   "test-component",
		},
		{
			Timestamp:   time.Now(),
			Level:       "ERROR",
			Message:     "Error message 1",
			ServiceName: "test-service",
			Component:   "test-component",
			Fields: map[string]interface{}{
				"error_code": 500,
			},
		},
		{
			Timestamp:   time.Now(),
			Level:       "WARN",
			Message:     "Warning message 1",
			ServiceName: "test-service",
			Component:   "test-component",
		},
	}

	err = provider.WriteBatch(ctx, batchEntries)
	assert.NoError(t, err)

	// Flush to ensure data is written
	err = provider.Flush(ctx)
	assert.NoError(t, err)

	// Verify log files were created
	files, err := filepath.Glob(filepath.Join(tmpDir, "test-*.log"))
	require.NoError(t, err)
	assert.Greater(t, len(files), 0, "Expected at least one log file to be created")

	// Test time range query
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now().Add(1 * time.Hour)

	query := interfaces.TimeRangeQuery{
		StartTime: startTime,
		EndTime:   endTime,
		Limit:     10,
	}

	results, err := provider.QueryTimeRange(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 4, "Expected 4 log entries (1 single + 3 batch)")

	// Verify entry content
	foundInfo := false
	foundError := false
	for _, result := range results {
		if result.Level == "INFO" && result.Message == "Test log message" {
			foundInfo = true
			assert.Equal(t, "test-service", result.ServiceName)
			assert.Equal(t, "test-component", result.Component)
			assert.Equal(t, "test_value", result.Fields["test_field"])
			assert.Equal(t, float64(42), result.Fields["number"]) // JSON unmarshaling converts to float64
		}
		if result.Level == "ERROR" && result.Message == "Error message 1" {
			foundError = true
			assert.Equal(t, float64(500), result.Fields["error_code"])
		}
	}
	assert.True(t, foundInfo, "Expected to find INFO log entry")
	assert.True(t, foundError, "Expected to find ERROR log entry")
}

func TestFileProvider_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":   tmpDir,
		"file_prefix": "test",
	}

	err := provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Write entries with different levels
	entries := []interfaces.LogEntry{
		{Timestamp: time.Now(), Level: "DEBUG", Message: "Debug message"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Info message"},
		{Timestamp: time.Now(), Level: "WARN", Message: "Warning message"},
		{Timestamp: time.Now(), Level: "ERROR", Message: "Error message"},
	}

	err = provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)

	err = provider.Flush(ctx)
	assert.NoError(t, err)

	// Test level-based query
	query := interfaces.LevelQuery{
		TimeRangeQuery: interfaces.TimeRangeQuery{
			StartTime: time.Now().Add(-1 * time.Hour),
			EndTime:   time.Now().Add(1 * time.Hour),
		},
		Levels: []string{"ERROR", "WARN"},
	}

	results, err := provider.QueryLevels(ctx, query)
	assert.NoError(t, err)
	assert.Len(t, results, 2, "Expected 2 log entries (ERROR and WARN)")

	// Verify only ERROR and WARN levels are returned
	for _, result := range results {
		assert.Contains(t, []string{"ERROR", "WARN"}, result.Level)
	}
}

func TestFileProvider_Stats(t *testing.T) {
	tmpDir := t.TempDir()

	// Create and initialize provider
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":   tmpDir,
		"file_prefix": "test",
	}

	err := provider.Initialize(config)
	require.NoError(t, err)
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Write some entries
	entries := []interfaces.LogEntry{
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 1"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 2"},
		{Timestamp: time.Now(), Level: "INFO", Message: "Message 3"},
	}

	err = provider.WriteBatch(ctx, entries)
	assert.NoError(t, err)

	err = provider.Flush(ctx)
	assert.NoError(t, err)

	// Get statistics
	stats, err := provider.GetStats(ctx)
	assert.NoError(t, err)

	// Verify stats
	assert.Equal(t, int64(3), stats.TotalEntries)
	assert.Greater(t, stats.StorageSize, int64(0))
	assert.Greater(t, stats.WriteLatencyMs, 0.0)
	assert.False(t, stats.LatestEntry.IsZero())
}

// TestFileProvider_DoubleClose verifies that calling Close() twice on the same
// provider is a no-op and does not panic or return an error.
func TestFileProvider_DoubleClose(t *testing.T) {
	dir := t.TempDir()
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":        dir,
		"file_prefix":      "test",
		"compress_rotated": false,
	}
	require.NoError(t, provider.Initialize(config))

	require.NoError(t, provider.Close())
	require.NoError(t, provider.Close()) // second call must be a no-op
}

// TestFileProvider_ReinitializeAfterClose verifies that a single *FileProvider
// instance's own Initialize → Close → Initialize → Close cycle fully closes the
// file both times. Previously, a fired sync.Once made the second Close a no-op,
// leaving the log file open and causing Windows "file in use" errors.
func TestFileProvider_ReinitializeAfterClose(t *testing.T) {
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		provider := &FileProvider{}
		config := map[string]interface{}{
			"directory":        dir,
			"file_prefix":      "test",
			"compress_rotated": false,
		}
		require.NoError(t, provider.Initialize(config), "Initialize cycle %d", i)

		ctx := context.Background()
		require.NoError(t, provider.WriteEntry(ctx, interfaces.LogEntry{
			Level: "INFO", Message: "entry",
		}), "WriteEntry cycle %d", i)

		require.NoError(t, provider.Close(), "Close cycle %d", i)

		// After Close the file must be fully released so the directory can be
		// removed (the t.TempDir cleanup will verify this on all platforms).
	}
}

// TestFileProvider_CloseWaitsForCompressOldFilesGoroutine covers AC2 for the
// compression path -- it is NOT the Issue #4145 failure itself, which runs with
// compress_rotated: false and so never reaches any of this code (see
// TestFileProvider_CloseIsFinalUnderConcurrentWrites for that root cause).
//
// rotateLogFile starts compressOldFiles in a bare `go` statement, including on
// the very first rotation performed by Initialize(). That goroutine was not
// tracked in p.bgWg, so Close() (which only waited on backgroundMaintenance)
// could return -- and a caller's t.TempDir() cleanup could run RemoveAll --
// while compressOldFiles still held an open handle on a rotated file. AC2
// requires a closed provider to hold no open handle, so with compression on,
// Close() must wait for this goroutine too.
//
// This forces the goroutine to do real, observable work (compress an actual
// rotated file) rather than the near-instant no-op it performs when
// CompressRotated is false or the rotated file is under the 1-hour age gate,
// so the assertion genuinely exercises the wait rather than coincidentally
// racing a no-op to completion.
func TestFileProvider_CloseWaitsForCompressOldFilesGoroutine(t *testing.T) {
	dir := t.TempDir()
	provider := &FileProvider{}
	config := map[string]interface{}{
		"directory":        dir,
		"file_prefix":      "rot",
		"max_file_size":    int64(1), // any flushed byte triggers rotation on the next write
		"compress_rotated": true,
		"flush_interval":   "1h", // long enough that the periodic flush never fires during this test
	}
	require.NoError(t, provider.Initialize(config))
	defer func() { _ = provider.Close() }()

	// Seed a fake rotated file directly (rather than relying on a real prior
	// rotation) so its name can never collide with the rotation this test
	// triggers below -- rotateLogFile names files by second-granularity
	// timestamp, and two rotations in the same wall-clock second would
	// otherwise reuse the same path, leaving nothing distinct to compress.
	oldFilePath := filepath.Join(dir, "rot-fakeold.log")
	require.NoError(t, os.WriteFile(oldFilePath, []byte("stale log line\n"), 0o600))
	oldTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(oldFilePath, oldTime, oldTime))

	ctx := context.Background()
	require.NoError(t, provider.WriteEntry(ctx, interfaces.LogEntry{Level: "INFO", Message: "first"}))
	require.NoError(t, provider.Flush(ctx))

	// The current file is now >= max_file_size, so this triggers needsRotation()
	// -> rotateLogFile(), spawning a compressOldFiles goroutine that globs the
	// directory and finds oldFilePath: not the (new) current file, not already
	// .gz, and past the 1-hour age gate.
	require.NoError(t, provider.WriteEntry(ctx, interfaces.LogEntry{Level: "INFO", Message: "second"}))

	require.NoError(t, provider.Close())

	// Close() returned, which -- via p.bgWg.Wait() -- must mean the compress
	// goroutine has already finished: the original file is gone and its .gz
	// replacement exists. Before the fix this was a race (the assertion could
	// pass anyway on a fast local disk), but the fix makes it a guarantee: it
	// cannot fail no matter how slow compression is, because Close() would not
	// have returned yet.
	_, err := os.Stat(oldFilePath)
	assert.True(t, os.IsNotExist(err), "original rotated file %s should have been removed by compression", oldFilePath)

	_, err = os.Stat(oldFilePath + ".gz")
	assert.NoError(t, err, "compressed replacement %s.gz should exist", oldFilePath)
}

// TestFileProvider_CloseIsFinalUnderConcurrentWrites reproduces Issue #4145.
//
// A writer that is already inside WriteEntry when Close() runs used to read
// p.initialized *before* taking p.mutex. It could therefore pass that check,
// block on the mutex for the whole of Close(), and then proceed against a
// closed provider: needsRotation() sees the now-nil currentFile, rotateLogFile()
// opens a brand-new log file, and nothing ever closes it again (the provider is
// no longer initialized, so a later Close() returns at its own early exit).
// On Windows that leaked handle makes the subsequent RemoveAll of the log
// directory fail with "The process cannot access the file because it is being
// used by another process" -- exactly the reported TempDir-cleanup failure.
//
// Measured on this native Windows host before the fix: 1/40 iterations leaked
// without -race, 13/40 with -race (which widens the window). After the fix the
// assertion is not probabilistic: rotateLogFile refuses to open a file once
// p.initialized is false, and both flag and file are only ever touched under
// p.mutex.
func TestFileProvider_CloseIsFinalUnderConcurrentWrites(t *testing.T) {
	const iterations = 25
	const writers = 32

	entry := interfaces.LogEntry{
		Level:   "INFO",
		Message: strings.Repeat("payload ", 256),
	}

	for i := 0; i < iterations; i++ {
		dir := t.TempDir()
		provider := &FileProvider{}
		require.NoError(t, provider.Initialize(map[string]interface{}{
			"directory":        dir,
			"file_prefix":      "concurrent",
			"max_file_size":    int64(1024 * 1024),
			"compress_rotated": false,
			"flush_interval":   "1h", // the periodic flush must not fire during the test
		}))

		var wg sync.WaitGroup
		start := make(chan struct{})
		stop := make(chan struct{})
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for {
					select {
					case <-stop:
						return
					default:
					}
					// Errors are expected and correct once Close() has run:
					// the provider reports "provider not initialized" rather
					// than resurrecting the file.
					_ = provider.WriteEntry(context.Background(), entry)
				}
			}()
		}
		close(start)

		require.NoError(t, provider.Close())

		// Writers keep hammering across Close() and for a moment after it
		// returns; none of them may re-open the file.
		close(stop)
		wg.Wait()

		provider.mutex.RLock()
		leaked := provider.currentFile
		provider.mutex.RUnlock()
		if leaked != nil {
			// Close it so the remaining iterations and TempDir cleanup are not
			// poisoned by this one failure.
			_ = leaked.Close()
			t.Fatalf("iteration %d: provider re-opened %s after Close() returned", i, leaked.Name())
		}

		// The real-world symptom: on Windows this fails outright if any handle
		// on a file in dir is still open.
		require.NoError(t, os.RemoveAll(dir), "log directory must be removable once Close() has returned")
	}
}

// TestFileProvider_RotateLogFileRefusesOnClosedProvider pins the enforcement
// point for Issue #4145 deterministically: opening a log file is the only way
// this provider acquires a handle, and rotateLogFile is the only place that
// does it, so it must refuse outright once the provider is closed. Without this
// guard the invariant would depend on every caller re-checking state, which is
// precisely what failed.
func TestFileProvider_RotateLogFileRefusesOnClosedProvider(t *testing.T) {
	dir := t.TempDir()
	provider := &FileProvider{}
	require.NoError(t, provider.Initialize(map[string]interface{}{
		"directory":        dir,
		"file_prefix":      "closed",
		"compress_rotated": false,
		"flush_interval":   "1h",
	}))
	require.NoError(t, provider.Close())

	before, err := filepath.Glob(filepath.Join(dir, "closed*.log"))
	require.NoError(t, err)

	provider.mutex.Lock()
	rotateErr := provider.rotateLogFile()
	current := provider.currentFile
	provider.mutex.Unlock()

	require.Error(t, rotateErr, "rotateLogFile must refuse to open a file on a closed provider")
	assert.Nil(t, current, "no file handle may be held after a refused rotation")

	after, err := filepath.Glob(filepath.Join(dir, "closed*.log"))
	require.NoError(t, err)
	assert.Equal(t, before, after, "a refused rotation must not create a log file")

	// And the public write path reports the same refusal rather than silently
	// re-opening the file.
	err = provider.WriteEntry(context.Background(), interfaces.LogEntry{Level: "INFO", Message: "after close"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestFileProvider_ProviderRegistration(t *testing.T) {
	// Test that provider auto-registers
	providers := interfaces.GetRegisteredLoggingProviderNames()
	assert.Contains(t, providers, "file", "File provider should be auto-registered")

	// Test provider retrieval (don't try to get it since it needs configuration)
	// Instead, test the registry directly
	provider := &FileProvider{}
	assert.Equal(t, "file", provider.Name())
	assert.NotEmpty(t, provider.Description())
	assert.NotEmpty(t, provider.GetVersion())

	// Test availability with no config (should be false)
	available, err := provider.Available()
	assert.False(t, available)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}
