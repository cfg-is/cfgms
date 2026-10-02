// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCapturingLogger_ImplementsLogger is a compile-time assertion via interface
// assignment that CapturingLogger satisfies Logger.
var _ Logger = (*CapturingLogger)(nil)

func TestCapturingLogger_RecordsWarnEntries(t *testing.T) {
	l := NewCapturingLogger()

	l.Warn("first warning", "k1", "v1", "k2", 42)
	l.WarnCtx(context.Background(), "second warning", "k3", "v3")

	require.Len(t, l.WarnEntries, 2, "must record one entry per Warn/WarnCtx call")

	assert.Equal(t, "v1", l.WarnEntries[0]["k1"])
	assert.Equal(t, 42, l.WarnEntries[0]["k2"])
	assert.Equal(t, "v3", l.WarnEntries[1]["k3"])
}

func TestCapturingLogger_RecordsWarnMessages(t *testing.T) {
	l := NewCapturingLogger()

	l.Warn("first warning", "k1", "v1")
	l.WarnCtx(context.Background(), "second warning", "k2", "v2")

	require.Len(t, l.WarnMessages, 2, "WarnMessages must parallel WarnEntries")
	assert.Equal(t, "first warning", l.WarnMessages[0])
	assert.Equal(t, "second warning", l.WarnMessages[1])
}

func TestCapturingLogger_RecordsInfoEntries(t *testing.T) {
	l := NewCapturingLogger()

	l.Info("first info", "k1", "v1", "k2", 42)
	l.InfoCtx(context.Background(), "second info", "k3", "v3")

	require.Len(t, l.InfoEntries, 2, "must record one entry per Info/InfoCtx call")
	require.Len(t, l.InfoMessages, 2, "InfoMessages must parallel InfoEntries")

	assert.Equal(t, "first info", l.InfoMessages[0])
	assert.Equal(t, "second info", l.InfoMessages[1])
	assert.Equal(t, "v1", l.InfoEntries[0]["k1"])
	assert.Equal(t, 42, l.InfoEntries[0]["k2"])
	assert.Equal(t, "v3", l.InfoEntries[1]["k3"])
}

// TestCapturingLogger_InfoAndWarnAreSeparate proves levels do not bleed into one
// another: the level of a captured call is unambiguous from which slice holds it.
func TestCapturingLogger_InfoAndWarnAreSeparate(t *testing.T) {
	l := NewCapturingLogger()

	l.Info("audit event", "actor", "controller")
	l.Warn("fallback event", "ring_value", "bogus")

	assert.Len(t, l.InfoEntries, 1, "Info must not populate WarnEntries")
	assert.Len(t, l.WarnEntries, 1, "Warn must not populate InfoEntries")
	assert.Equal(t, []string{"audit event"}, l.InfoMessages)
	assert.Equal(t, []string{"fallback event"}, l.WarnMessages)
}

func TestCapturingLogger_FindByMessage(t *testing.T) {
	l := NewCapturingLogger()

	l.Info("ring_set_changed", "actor", "controller", "after", "default=v1")
	l.Warn("deployment_ring_fallback", "fallback_ring", "default")

	info, ok := l.FindInfo("ring_set_changed")
	require.True(t, ok, "FindInfo must locate a recorded Info call by message")
	assert.Equal(t, "controller", info["actor"])
	assert.Equal(t, "default=v1", info["after"])

	warn, ok := l.FindWarn("deployment_ring_fallback")
	require.True(t, ok, "FindWarn must locate a recorded Warn call by message")
	assert.Equal(t, "default", warn["fallback_ring"])

	_, ok = l.FindInfo("deployment_ring_fallback")
	assert.False(t, ok, "FindInfo must not match a Warn-level message")
	_, ok = l.FindWarn("ring_set_changed")
	assert.False(t, ok, "FindWarn must not match an Info-level message")
}

func TestCapturingLogger_Counts(t *testing.T) {
	l := NewCapturingLogger()

	assert.Equal(t, 0, l.InfoCount())
	assert.Equal(t, 0, l.WarnCount())

	l.Info("one")
	l.InfoCtx(context.Background(), "two")
	l.Warn("three")

	assert.Equal(t, 2, l.InfoCount())
	assert.Equal(t, 1, l.WarnCount())
}

func TestCapturingLogger_DiscardsSilentLevels(t *testing.T) {
	l := NewCapturingLogger()

	l.Debug("debug msg")
	l.Error("error msg")
	l.DebugCtx(context.Background(), "debug ctx")
	l.ErrorCtx(context.Background(), "error ctx")

	assert.Empty(t, l.WarnEntries, "non-Warn levels must not populate WarnEntries")
	assert.Empty(t, l.InfoEntries, "non-Info levels must not populate InfoEntries")
}

func TestCapturingLogger_EmptyKVProducesEmptyEntry(t *testing.T) {
	l := NewCapturingLogger()
	l.Warn("no fields")

	require.Len(t, l.WarnEntries, 1)
	assert.Empty(t, l.WarnEntries[0], "warn with no key-value pairs must produce an empty entry")
}
