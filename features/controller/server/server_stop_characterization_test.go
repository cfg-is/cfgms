// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for Server.Stop (Issue #5866). They pin the observable
// behavior of Stop (it always returns nil, a failing step only warns and never
// skips the steps after it, the order of the teardown steps, and the audit
// drain that must reach storage before the storage manager closes) so Stop can
// be split into one helper per step without changing it. They reuse the
// recordingLogger, the serverstartChar fixtures and the servernewChar config
// builders of the sibling tests; every new helper, type and test carries the
// serverstopChar prefix.

// serverstopCharAssertInOrder asserts that every message in want appears in
// msgs, each after the one before it.
func serverstopCharAssertInOrder(t *testing.T, msgs []string, want []string) {
	t.Helper()
	last := -1
	for _, w := range want {
		idx := -1
		for i := last + 1; i < len(msgs); i++ {
			if msgs[i] == w {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("message %q missing or out of order after position %d in %v", w, last, msgs)
		}
		last = idx
	}
}

// serverstopCharResetLog drops everything the recording logger captured so far.
func serverstopCharResetLog(rec *recordingLogger) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.entries = nil
}

// serverstopCharCloseSnapshot records what the audit store held, and how often
// it was closed, at the moment the storage manager closed it.
type serverstopCharCloseSnapshot struct {
	closes  int
	actions []string
	err     error
}

// serverstopCharProvider wraps the real registered flatfile provider and hands
// out an audit store that lists its own entries when it is closed. The listing
// runs before the inner Close, so it shows exactly what had reached storage by
// the time the storage manager released it.
type serverstopCharProvider struct {
	interfaces.StorageProvider
	snap *serverstopCharCloseSnapshot
}

type serverstopCharAuditStore struct {
	business.AuditStore
	snap *serverstopCharCloseSnapshot
}

func (s serverstopCharAuditStore) Close() error {
	s.snap.closes++
	entries, err := s.ListAuditEntries(context.Background(), &business.AuditFilter{})
	s.snap.err = err
	for _, e := range entries {
		s.snap.actions = append(s.snap.actions, e.Action)
	}
	return s.AuditStore.Close()
}

func (p *serverstopCharProvider) CreateAuditStore(c map[string]interface{}) (business.AuditStore, error) {
	store, err := p.StorageProvider.CreateAuditStore(c)
	if err != nil {
		return store, err
	}
	return serverstopCharAuditStore{AuditStore: store, snap: p.snap}, nil
}

// serverstopCharInstallSnapshotProvider swaps the registered flatfile provider
// for the wrapper above and restores the original on cleanup.
func serverstopCharInstallSnapshotProvider(t *testing.T) *serverstopCharCloseSnapshot {
	t.Helper()
	original, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err, "the flatfile provider must be registered for this test")
	snap := &serverstopCharCloseSnapshot{}
	interfaces.RegisterStorageProvider(&serverstopCharProvider{StorageProvider: original, snap: snap})
	t.Cleanup(func() { interfaces.RegisterStorageProvider(original) })
	return snap
}

func TestServerstopChar_AbsentComponents(t *testing.T) {
	t.Run("a Server with no optional component stops without error", func(t *testing.T) {
		rec := &recordingLogger{}
		srv := &Server{logger: rec}

		require.NoError(t, srv.Stop())
		assert.Equal(t, []string{"Shutting down controller server"}, serverstartCharMessages(rec),
			"with nothing to stop, Stop logs only its opening message")
	})

	t.Run("a Server that was never started stops every component New built", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)

		require.NoError(t, srv.Stop())
		msgs := serverstartCharMessages(rec)
		// The health collector, alert manager and trigger manager were never
		// started, so their Stop reports an error that only warns.
		serverstopCharAssertInOrder(t, msgs, []string{
			"Shutting down controller server",
			"Failed to stop health collector",
			"Failed to stop alert manager",
			"Failed to stop trigger manager",
			"Command publisher stopped",
			"Stopping heartbeat monitoring service",
			"Job dispatcher stopped",
			"IP-trust expiry job stopped",
			"Pending-registration expiry job stopped",
			"Shutting down DNA storage manager",
			"git-sync syncer stopped",
			"Shutting down REST API server",
		})
		assert.False(t, rec.containsAny("Failed to stop terminal session manager"),
			"the terminal session manager only exists after Start")
		assert.False(t, rec.containsAny("Failed to record shutdown audit event"))
	})
}

func TestServerstopChar_StartedServerStepOrder(t *testing.T) {
	srv, rec := serverstartCharNewServer(t)
	require.NoError(t, srv.Start())
	require.NotNil(t, srv.terminalSessionMgr)
	require.NotNil(t, srv.grpcServer)
	serverstopCharResetLog(rec)

	require.NoError(t, srv.Stop())

	msgs := serverstartCharMessages(rec)
	// Terminal sessions close before the HA manager; the HA manager stops before
	// the services that follow the audit drain; the REST API server closes last.
	serverstopCharAssertInOrder(t, msgs, []string{
		"Shutting down controller server",
		"Session manager stopped",
		"Stopping HA Manager",
		"HA Manager stopped successfully",
		"Command publisher stopped",
		"Stopping heartbeat monitoring service",
		"Job dispatcher stopped",
		"IP-trust expiry job stopped",
		"Pending-registration expiry job stopped",
		"Shutting down DNA storage manager",
		"git-sync syncer stopped",
		"Shutting down REST API server",
	})
	for _, warn := range []string{
		"Failed to stop health collector",
		"Failed to stop alert manager",
		"Failed to stop trigger manager",
		"Failed to stop terminal session manager",
		"Failed to stop HA manager",
		"Failed to record shutdown audit event",
		"Failed to stop audit manager",
		"Failed to close storage manager",
		"Failed to stop HTTP server",
	} {
		assert.False(t, rec.containsAny(warn), "a clean shutdown must not warn: %s", warn)
	}
}

func TestServerstopChar_AuditDrainReachesStorageBeforeItCloses(t *testing.T) {
	snap := serverstopCharInstallSnapshotProvider(t)
	srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())
	require.NotNil(t, srv.auditManager)

	ctx := context.Background()
	for _, action := range []string{"serverstop_char_a", "serverstop_char_b", "serverstop_char_c"} {
		event := audit.SystemEvent(audit.SystemTenantID, action, "queued before Stop")
		require.NoError(t, srv.auditManager.RecordEvent(ctx, event))
	}
	require.Zero(t, snap.closes, "the audit store stays open until Stop")

	require.NoError(t, srv.Stop())

	assert.Equal(t, 1, snap.closes, "the storage manager closes the audit store once")
	require.NoError(t, snap.err)
	assert.Contains(t, snap.actions, "serverstop_char_a")
	assert.Contains(t, snap.actions, "serverstop_char_b")
	assert.Contains(t, snap.actions, "serverstop_char_c")
	assert.Contains(t, snap.actions, "controller_stop",
		"the shutdown event recorded by Stop reaches storage before the storage manager closes")
}

func TestServerstopChar_StoppedTwice(t *testing.T) {
	t.Run("a second Stop returns nil and warns on the steps that cannot repeat", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.Start())
		require.NoError(t, srv.Stop())
		serverstopCharResetLog(rec)

		require.NoError(t, srv.Stop())

		msgs := serverstartCharMessages(rec)
		// Steps that fail on the second call warn, and the steps after them
		// still run: the last teardown steps log after the first warning.
		serverstopCharAssertInOrder(t, msgs, []string{
			"Shutting down controller server",
			"Failed to stop health collector",
			"Failed to stop alert manager",
			"Failed to stop trigger manager",
			"Failed to record shutdown audit event",
			"Command publisher stopped",
			"Job dispatcher stopped",
			"Pending-registration expiry job stopped",
			"Shutting down DNA storage manager",
			"git-sync syncer stopped",
			"Shutting down REST API server",
		})
	})

	t.Run("a second Stop of a Server that was never started returns nil", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.Stop())
		serverstopCharResetLog(rec)

		require.NoError(t, srv.Stop())
		assert.True(t, rec.containsAny("Shutting down REST API server"), "the last step still runs")
	})
}

func TestServerstopChar_FailingStepDoesNotSkipLaterSteps(t *testing.T) {
	t.Run("a stopped trigger manager warns and the audit drain still runs", func(t *testing.T) {
		snap := serverstopCharInstallSnapshotProvider(t)
		rec := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), rec)
		require.NotNil(t, srv.triggerManager)

		// Stopping the never-started trigger manager returns an error. Every
		// step after it must still run, and Stop must still return nil.
		require.NoError(t, srv.Stop())

		assert.True(t, rec.containsAny("Failed to stop trigger manager"))
		assert.Equal(t, 1, snap.closes, "the storage manager still closed the audit store")
		assert.Contains(t, snap.actions, "controller_stop", "the audit drain still ran after the failing step")
		assert.True(t, rec.containsAny("Shutting down REST API server"), "the final step still ran")
	})
}

func TestServerstopChar_SessionStore(t *testing.T) {
	t.Run("the in-memory store is closed without a warning", func(t *testing.T) {
		rec := &recordingLogger{}
		store := session.NewMemStore(session.DefaultConfig(), nil)
		srv := &Server{logger: rec, sessionStore: store}

		require.NoError(t, srv.Stop())
		assert.False(t, rec.containsAny("Failed to close session store"))
	})

	t.Run("the durable store New builds is closed without a warning", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NotNil(t, srv.sessionStore)

		require.NoError(t, srv.Stop())
		assert.False(t, rec.containsAny("Failed to close session store"))
	})
}
