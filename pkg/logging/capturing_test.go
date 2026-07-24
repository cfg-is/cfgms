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

func TestCapturingLogger_DiscardsSilentLevels(t *testing.T) {
	l := NewCapturingLogger()

	l.Debug("debug msg")
	l.Info("info msg")
	l.Error("error msg")
	l.DebugCtx(context.Background(), "debug ctx")
	l.InfoCtx(context.Background(), "info ctx")
	l.ErrorCtx(context.Background(), "error ctx")

	assert.Empty(t, l.WarnEntries, "non-Warn levels must not populate WarnEntries")
}

func TestCapturingLogger_EmptyKVProducesEmptyEntry(t *testing.T) {
	l := NewCapturingLogger()
	l.Warn("no fields")

	require.Len(t, l.WarnEntries, 1)
	assert.Empty(t, l.WarnEntries[0], "warn with no key-value pairs must produce an empty entry")
}
