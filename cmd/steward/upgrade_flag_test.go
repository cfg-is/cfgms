// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for checkUpgradeFlagFiles (Issue #1943).
package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUpgradePublisher implements upgradeEventPublisher and
// PublishUpgradeLifecycleEvent so publishUpgradeLifecycleEvent routes through
// the real interface assertion path. Captures dispatched events for assertions.
type testUpgradePublisher struct {
	mu     sync.Mutex
	events []upgradeEvent
}

type upgradeEvent struct {
	eventType string
	version   string
}

func (p *testUpgradePublisher) GetStewardID() string { return "test-steward" }
func (p *testUpgradePublisher) GetTenantID() string  { return "test-tenant" }
func (p *testUpgradePublisher) PublishUpgradeLifecycleEvent(_ context.Context, eventType, version string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, upgradeEvent{eventType: eventType, version: version})
	return nil
}

func (p *testUpgradePublisher) captured() []upgradeEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]upgradeEvent, len(p.events))
	copy(out, p.events)
	return out
}

// TestCheckUpgradeFlagFiles_CommittedAndRolledBack verifies that both flag
// files are read, the matching events are dispatched, and both files are deleted.
func TestCheckUpgradeFlagFiles_CommittedAndRolledBack(t *testing.T) {
	certStoreDir := t.TempDir()
	logger := logging.NewLogger("error")

	// Write both flag files.
	require.NoError(t, os.WriteFile(
		filepath.Join(certStoreDir, "upgrade-committed"),
		[]byte("v1.2.3\n"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(certStoreDir, "upgrade-rolled-back"),
		[]byte("v1.2.2\n"), 0o600))

	pub := &testUpgradePublisher{}
	checkUpgradeFlagFiles(context.Background(), certStoreDir, pub, logger)

	events := pub.captured()
	require.Len(t, events, 2, "one event per flag file")

	byType := make(map[string]string, len(events))
	for _, e := range events {
		byType[e.eventType] = e.version
	}
	assert.Equal(t, "v1.2.3", byType["steward.upgrade.committed"],
		"committed event must carry committed version")
	assert.Equal(t, "v1.2.2", byType["steward.upgrade.rolled_back"],
		"rolled-back event must carry rolled-back version")

	// Flag files must be deleted after processing.
	_, err := os.Stat(filepath.Join(certStoreDir, "upgrade-committed"))
	assert.True(t, os.IsNotExist(err), "upgrade-committed must be deleted")
	_, err = os.Stat(filepath.Join(certStoreDir, "upgrade-rolled-back"))
	assert.True(t, os.IsNotExist(err), "upgrade-rolled-back must be deleted")
}

// TestCheckUpgradeFlagFiles_OnlyCommitted verifies that only the committed
// event fires when only that file is present.
func TestCheckUpgradeFlagFiles_OnlyCommitted(t *testing.T) {
	certStoreDir := t.TempDir()
	logger := logging.NewLogger("error")

	require.NoError(t, os.WriteFile(
		filepath.Join(certStoreDir, "upgrade-committed"),
		[]byte("v2.0.0"), 0o600))

	pub := &testUpgradePublisher{}
	checkUpgradeFlagFiles(context.Background(), certStoreDir, pub, logger)

	events := pub.captured()
	require.Len(t, events, 1)
	assert.Equal(t, "steward.upgrade.committed", events[0].eventType)
	assert.Equal(t, "v2.0.0", events[0].version)

	_, err := os.Stat(filepath.Join(certStoreDir, "upgrade-committed"))
	assert.True(t, os.IsNotExist(err), "flag file must be deleted")
}

// TestCheckUpgradeFlagFiles_NoFiles verifies that no events fire when neither
// flag file exists (clean first-boot path).
func TestCheckUpgradeFlagFiles_NoFiles(t *testing.T) {
	certStoreDir := t.TempDir()
	logger := logging.NewLogger("error")

	pub := &testUpgradePublisher{}
	checkUpgradeFlagFiles(context.Background(), certStoreDir, pub, logger)

	assert.Empty(t, pub.captured(), "no events must fire when no flag files exist")
}
