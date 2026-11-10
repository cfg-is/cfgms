// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

// newSignalPublisher returns a publisher wired to a fresh signal registry.
func newSignalPublisher(t *testing.T) (*commands.Publisher, *health.SignalRegistry) {
	t.Helper()
	pub, _ := newTestPublisher(t, nil)
	reg := health.NewSignalRegistry()
	sig, err := commands.NewSignals(reg)
	require.NoError(t, err)
	pub.SetSignals(sig)
	t.Cleanup(func() { _ = pub.Stop(context.Background()) })
	return pub, reg
}

func scrapeSignals(t *testing.T, reg *health.SignalRegistry) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, reg.WriteText(&sb))
	return sb.String()
}

func sendLine(cmdType, outcome string, n int) string {
	return `cfgms_command_send_total{command_type="` + cmdType + `",outcome="` + outcome + `"} ` + string(rune('0'+n))
}

func completionCount(cmdType, outcome string, n int) string {
	return `cfgms_command_completion_seconds_count{command_type="` + cmdType + `",outcome="` + outcome + `"} ` + string(rune('0'+n))
}

func TestPublisherRecordsSendOutcome(t *testing.T) {
	pub, reg := newSignalPublisher(t)
	ctx := context.Background()

	// PublishCommandWithID (also the path PublishCommand and config push use).
	require.NoError(t, pub.PublishCommandWithID(ctx, "cmd-1", "steward-test", types.CommandSyncConfig, nil))
	require.Error(t, pub.PublishCommandWithID(ctx, "cmd-2", "steward-missing", types.CommandSyncConfig, nil))

	// PublishCommandWithSigner.
	_, err := pub.PublishCommandWithSigner(ctx, "steward-test", types.CommandPushSigningCert, nil, nil)
	require.NoError(t, err)
	_, err = pub.PublishCommandWithSigner(ctx, "steward-missing", types.CommandPushSigningCert, nil, nil)
	require.Error(t, err)

	// PublishCommandWithSignerAndCallback.
	_, err = pub.PublishCommandWithSignerAndCallback(ctx, "steward-test", types.CommandSyncDNA, nil, nil, time.Minute, nil, nil)
	require.NoError(t, err)
	_, err = pub.PublishCommandWithSignerAndCallback(ctx, "steward-missing", types.CommandSyncDNA, nil, nil, time.Minute, nil, nil)
	require.Error(t, err)

	out := scrapeSignals(t, reg)
	assert.Contains(t, out, sendLine("sync_config", "sent", 1))
	assert.Contains(t, out, sendLine("sync_config", "send_failed", 1))
	assert.Contains(t, out, sendLine("push_signing_cert", "sent", 1))
	assert.Contains(t, out, sendLine("push_signing_cert", "send_failed", 1))
	assert.Contains(t, out, sendLine("sync_dna", "sent", 1))
	assert.Contains(t, out, sendLine("sync_dna", "send_failed", 1))
	assert.NotContains(t, out, "steward-", "labels must not carry steward identifiers")
	assert.NotContains(t, out, "cmd-", "labels must not carry command identifiers")
}

func TestPublisherRecordsCompletionLatency(t *testing.T) {
	pub, reg := newSignalPublisher(t)
	ctx := context.Background()

	id, err := pub.PublishCommandWithCallback(ctx, "steward-test", types.CommandSyncConfig, nil, time.Minute, nil, nil)
	require.NoError(t, err)

	// A non-terminal event resolves nothing and records no latency.
	require.NoError(t, pub.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandReceived, StewardID: "steward-test", CommandID: id,
	}))
	assert.NotContains(t, scrapeSignals(t, reg), "cfgms_command_completion_seconds_count")

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, pub.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandCompleted, StewardID: "steward-test", CommandID: id,
	}))

	out := scrapeSignals(t, reg)
	assert.Contains(t, out, completionCount("sync_config", "completed", 1))
	// The 20ms sleep puts the observation above the 10ms bucket and the sum
	// at or above it.
	assert.Contains(t, out, `cfgms_command_completion_seconds_bucket{command_type="sync_config",outcome="completed",le="0.01"} 0`)
	assert.Contains(t, out, `cfgms_command_completion_seconds_bucket{command_type="sync_config",outcome="completed",le="+Inf"} 1`)

	// A repeat terminal event for a resolved command records nothing more.
	require.NoError(t, pub.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandCompleted, StewardID: "steward-test", CommandID: id,
	}))
	assert.Contains(t, scrapeSignals(t, reg), completionCount("sync_config", "completed", 1))
}

func TestPublisherRecordsFailedAndTimeout(t *testing.T) {
	pub, reg := newSignalPublisher(t)
	ctx := context.Background()

	failedID, err := pub.PublishCommandWithCallback(ctx, "steward-test", types.CommandSyncDNA, nil, time.Minute, nil, nil)
	require.NoError(t, err)
	require.NoError(t, pub.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandFailed, StewardID: "steward-test", CommandID: failedID,
	}))

	var timedOut atomic.Bool
	_, err = pub.PublishCommandWithCallback(ctx, "steward-test", types.CommandReconnect, nil,
		20*time.Millisecond, nil, func() { timedOut.Store(true) })
	require.NoError(t, err)
	require.Eventually(t, timedOut.Load, 5*time.Second, 5*time.Millisecond)

	out := scrapeSignals(t, reg)
	assert.Contains(t, out, completionCount("sync_dna", "failed", 1))
	assert.Contains(t, out, completionCount("reconnect", "timeout", 1))
	assert.NotContains(t, out, `outcome="completed"} 1`)
}

func TestPublisherUnknownCommandTypeIsBounded(t *testing.T) {
	pub, reg := newSignalPublisher(t)

	require.NoError(t, pub.PublishCommandWithID(context.Background(), "cmd-x", "steward-test", types.CommandType("tenant-acme-secret"), nil))

	out := scrapeSignals(t, reg)
	assert.Contains(t, out, sendLine("other", "sent", 1))
	assert.NotContains(t, out, "tenant-acme-secret")
}

func TestPublisherNilSignals(t *testing.T) {
	pub, _ := newTestPublisher(t, nil)
	t.Cleanup(func() { _ = pub.Stop(context.Background()) })
	ctx := context.Background()

	// No recorder set, and one explicitly set to nil: every path still works.
	pub.SetSignals(nil)
	require.NoError(t, pub.PublishCommandWithID(ctx, "cmd-1", "steward-test", types.CommandSyncConfig, nil))
	require.Error(t, pub.PublishCommandWithID(ctx, "cmd-2", "steward-missing", types.CommandSyncConfig, nil))

	var completed atomic.Bool
	id, err := pub.PublishCommandWithCallback(ctx, "steward-test", types.CommandSyncDNA, nil, time.Minute,
		func(*types.Event) { completed.Store(true) }, nil)
	require.NoError(t, err)
	require.NoError(t, pub.HandleEventUpdate(ctx, &types.Event{Type: types.EventCommandCompleted, CommandID: id}))
	assert.True(t, completed.Load())

	var timedOut atomic.Bool
	_, err = pub.PublishCommandWithCallback(ctx, "steward-test", types.CommandReconnect, nil,
		10*time.Millisecond, nil, func() { timedOut.Store(true) })
	require.NoError(t, err)
	require.Eventually(t, timedOut.Load, 5*time.Second, 5*time.Millisecond)
}

func TestNewSignalsRejectsNilAndDuplicateRegistry(t *testing.T) {
	_, err := commands.NewSignals(nil)
	require.Error(t, err)

	reg := health.NewSignalRegistry()
	_, err = commands.NewSignals(reg)
	require.NoError(t, err)
	_, err = commands.NewSignals(reg)
	require.Error(t, err, "a second registration on the same registry must fail")
}
