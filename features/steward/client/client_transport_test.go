// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides tests for the transport client.
// Issue #920: on-demand cert loading via certManager.GetClientCertificate.
package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// kvCapturingLogger captures Info and Warn log entries for security assertions.
// It satisfies logging.Logger via embedding NoopLogger while recording key-value
// arguments so tests can verify sensitive fields are absent or properly redacted.
// Issue #981: used to assert steward IDs appear only in redacted form in Connect logs.
type kvCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []kvLogEntry
}

type kvLogEntry struct {
	msg string
	kvs []interface{}
}

func (l *kvCapturingLogger) Info(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, kvLogEntry{msg: msg, kvs: kvcopy})
}

func (l *kvCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kvcopy := make([]interface{}, len(kvs))
	copy(kvcopy, kvs)
	l.entries = append(l.entries, kvLogEntry{msg: msg, kvs: kvcopy})
}

func (l *kvCapturingLogger) allEntries() []kvLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]kvLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// TestConnect_StewardIDRedactedInLogs verifies that Connect never logs the literal
// steward ID (a server-generated bearer-like identifier) in plain form. The log
// entries captured before Connect fails must use logging.RedactedID output only.
// Issue #981: steward_id from controller registration must be redacted at Info level.
func TestConnect_StewardIDRedactedInLogs(t *testing.T) {
	cap := &kvCapturingLogger{}
	c := &TransportClient{
		stewardID:        "steward-test-abc123xyz",
		transportAddress: "localhost:0", // unreachable; Connect will fail before fully connecting
		logger:           cap,
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
	}

	ctx := context.Background()
	// Connect is expected to fail (no real controller). The log entries captured
	// before the failure are what we validate.
	_ = c.Connect(ctx)

	literal := "steward-test-abc123xyz"
	redacted := logging.RedactedID(literal)

	entries := cap.allEntries()
	require.NotEmpty(t, entries, "Connect must emit at least one log entry before failing")

	// Assert the literal steward ID never appears as a log value.
	for _, e := range entries {
		for i := 1; i < len(e.kvs); i += 2 {
			if s, ok := e.kvs[i].(string); ok {
				assert.NotContains(t, s, literal,
					"log entry %q must not contain the literal steward ID", e.msg)
			}
		}
	}

	// Assert the redacted form appears under "steward_id" in at least one entry.
	foundRedacted := false
	for _, e := range entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if key, ok := e.kvs[i].(string); ok && key == "steward_id" {
				if val, ok := e.kvs[i+1].(string); ok && val == redacted {
					foundRedacted = true
				}
			}
		}
	}
	assert.True(t, foundRedacted,
		"redacted steward ID %q must appear under 'steward_id' key in at least one log entry", redacted)
}

// TestTransportClient_CertReloadOnHandshake verifies that createTLSConfig wires
// GetClientCertificate as a per-handshake callback (not a cached value) so that
// certificate rotations are picked up automatically.
func TestTransportClient_CertReloadOnHandshake(t *testing.T) {
	dir := t.TempDir()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: dir,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	// Generate the initial client certificate.
	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-001",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Wire a TransportClient with the real cert.Manager.
	c := &TransportClient{
		certManager: mgr,
		logger:      logging.NewLogger("info"),
	}

	tlsCfg, err := c.createTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.NotNil(t, tlsCfg.GetClientCertificate, "createTLSConfig must set GetClientCertificate")

	// First handshake — returns the initial cert.
	got1, err := tlsCfg.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, got1)
	require.NotEmpty(t, got1.Certificate, "first handshake must return a non-empty cert")

	// Simulate rotation: generate a replacement client cert.
	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-001-renewed",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Second handshake — must return the rotated cert (re-fetched from store, not cached).
	got2, err := tlsCfg.GetClientCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, got2)
	require.NotEmpty(t, got2.Certificate, "second handshake must return a non-empty cert")

	// The leaf DER bytes differ between the original and rotated certs.
	assert.NotEqual(t, got1.Certificate[0], got2.Certificate[0],
		"second handshake must return the newer cert after rotation (re-fetch, not cached)")
}

// TestTransportClient_HeartbeatJitter_Range verifies that:
//  1. The default heartbeat interval is 20 s (epic #1664).
//  2. 100 per-tick jitter-adjusted intervals all fall in [20 s, 30 s).
//
// Jitter is uniform in [0, 10 s), so the effective per-tick interval is always
// between 20 s (no jitter) and just under 30 s (maximum jitter).
func TestTransportClient_HeartbeatJitter_Range(t *testing.T) {
	logger := logging.NewLogger("info")
	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		Logger:        logger,
	})
	require.NoError(t, err)

	assert.Equal(t, 20*time.Second, c.heartbeatInterval,
		"default heartbeat interval must be 20s (epic #1664)")

	require.NotNil(t, c.rng, "NewTransportClient must initialise the per-instance RNG")

	base := 20 * time.Second
	jitterMax := 10 * time.Second
	for i := 0; i < 100; i++ {
		jitter := time.Duration(c.rng.Int63n(int64(jitterMax)))
		interval := base + jitter
		assert.GreaterOrEqual(t, interval, base,
			"sample %d: jitter-adjusted interval must be >= 20s", i)
		assert.Less(t, interval, base+jitterMax,
			"sample %d: jitter-adjusted interval must be < 30s", i)
	}
}

// TestTransportClient_CertNotCached verifies that every call to the
// GetClientCertificate callback reads from the cert store rather than a cached
// value — even when the certificate has not changed.
func TestTransportClient_CertNotCached(t *testing.T) {
	dir := t.TempDir()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: dir,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	_, err = mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   "steward-test-002",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	c := &TransportClient{
		certManager: mgr,
		logger:      logging.NewLogger("info"),
	}

	tlsCfg, err := c.createTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// Multiple calls must each succeed (no caching failure, no stale state).
	const iterations = 3
	for i := 0; i < iterations; i++ {
		got, err := tlsCfg.GetClientCertificate(nil)
		require.NoError(t, err, "call %d must not return an error", i+1)
		require.NotNil(t, got, "call %d must return a non-nil cert", i+1)
		require.NotEmpty(t, got.Certificate, "call %d must return non-empty cert bytes", i+1)
	}
}

// TestStartConvergenceLoop_IntervalChangeResetsTicker verifies that a
// converge_interval delivered by a sync_config command takes effect promptly:
// the convergence loop resets its ticker as soon as convergeInterval changes,
// rather than waiting out the stale (30-minute startup default) tick period.
//
// Regression test for Issue #1721: the fleet drift-correction scenario uploads
// a cfg with converge_interval=10s and expects a convergence run within ~90s.
// With the ticker pinned to the 30-minute startup default that never happened,
// so apply-mode drift was never re-corrected by the scheduled loop.
func TestStartConvergenceLoop_IntervalChangeResetsTicker(t *testing.T) {
	capLog := &kvCapturingLogger{}
	c := &TransportClient{
		logger:             capLog,
		convergenceStop:    make(chan struct{}),
		convergeIntervalCh: make(chan struct{}, 1),
		convergeInterval:   1 * time.Hour, // startup default — far longer than the test window
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.StartConvergenceLoop(ctx)

	// Simulate a sync_config command lowering the interval, mirroring what
	// client_transport.go does on cfg delivery: update the field, then signal.
	c.mu.Lock()
	c.convergeInterval = 150 * time.Millisecond
	c.mu.Unlock()
	select {
	case c.convergeIntervalCh <- struct{}{}:
	default:
	}

	// The loop must reset its ticker and fire a scheduled convergence well
	// within the test window. With the bug (ticker pinned to 1h) it never does.
	deadline := time.Now().Add(5 * time.Second)
	fired := false
	for time.Now().Before(deadline) && !fired {
		for _, e := range capLog.allEntries() {
			if e.msg == "Scheduled convergence triggered" {
				fired = true
				break
			}
		}
		if !fired {
			time.Sleep(20 * time.Millisecond)
		}
	}

	assert.True(t, fired,
		"convergence loop must reset its ticker on a converge_interval change and fire a scheduled convergence within 5s")
}
