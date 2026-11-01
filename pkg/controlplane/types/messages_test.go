// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpgradeConstants(t *testing.T) {
	assert.Equal(t, "push_steward_binary", string(CommandPushStewardBinary))
	assert.Equal(t, "steward.upgrade.dispatched", string(EventStewardUpgradeDispatched))
	assert.Equal(t, "steward.upgrade.downloaded", string(EventStewardUpgradeDownloaded))
	assert.Equal(t, "steward.upgrade.swapped", string(EventStewardUpgradeSwapped))
	assert.Equal(t, "steward.upgrade.committed", string(EventStewardUpgradeCommitted))
	assert.Equal(t, "steward.upgrade.rolled_back", string(EventStewardUpgradeRolledBack))
}

func TestEventFilter_Match(t *testing.T) {
	tests := []struct {
		name     string
		filter   *EventFilter
		event    *Event
		expected bool
	}{
		{
			name:   "empty filter matches all",
			filter: &EventFilter{},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "steward ID filter matches",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1", "steward-2"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: true,
		},
		{
			name: "steward ID filter no match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-2", "steward-3"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: false,
		},
		{
			name: "tenant ID filter matches",
			filter: &EventFilter{
				TenantIDs: []string{"tenant-1", "tenant-2"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "tenant ID filter no match",
			filter: &EventFilter{
				TenantIDs: []string{"tenant-2", "tenant-3"},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: false,
		},
		{
			name: "event type filter matches",
			filter: &EventFilter{
				EventTypes: []EventType{EventConfigApplied, EventDNASynced},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: true,
		},
		{
			name: "event type filter no match",
			filter: &EventFilter{
				EventTypes: []EventType{EventDNASynced, EventTaskCompleted},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
			},
			expected: false,
		},
		{
			name: "multiple filters all match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1"},
				TenantIDs:  []string{"tenant-1"},
				EventTypes: []EventType{EventConfigApplied},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: true,
		},
		{
			name: "multiple filters one doesn't match",
			filter: &EventFilter{
				StewardIDs: []string{"steward-1"},
				TenantIDs:  []string{"tenant-2"}, // Different tenant
				EventTypes: []EventType{EventConfigApplied},
			},
			event: &Event{
				ID:        "evt-1",
				Type:      EventConfigApplied,
				StewardID: "steward-1",
				TenantID:  "tenant-1",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Match(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCommandSigningBytes_TermIsNotSigned pins the recorded #3390 trade-off: the
// fencing term is transport-trusted, not signature-authenticated. Signing bytes must
// be byte-identical regardless of Command.Term so that stewards predating #3436 —
// which compute signing bytes without the field — keep verifying commands from a
// term-stamping controller during a rolling upgrade.
//
// This holds for the version-1 payload only; SigningPayloadV2 (#5174) covers the
// term, see TestCommandSigningBytesV2_CoversTerm.
func TestCommandSigningBytes_TermIsNotSigned(t *testing.T) {
	base := Command{
		ID:        "cmd-1",
		Type:      CommandSyncConfig,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	zeroTerm := base
	withTerm := base
	withTerm.Term = 99

	zeroBytes, err := CommandSigningBytes(&zeroTerm, nil)
	require.NoError(t, err)

	termBytes, err := CommandSigningBytes(&withTerm, nil)
	require.NoError(t, err)

	assert.Equal(t, string(zeroBytes), string(termBytes),
		"Command.Term must not affect signing bytes — it is transport-trusted only (#3390)")
	assert.NotContains(t, string(termBytes), "term",
		"signing payload must not carry a term field")
}

// TestCommandSigningBytes_V1GoldenUnchanged pins the v1 payload to bytes captured
// from the pre-#5174 implementation, so signatures already issued keep verifying.
func TestCommandSigningBytes_V1GoldenUnchanged(t *testing.T) {
	cmd := Command{
		ID:        "cmd-golden",
		Type:      CommandSyncConfig,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Term:      7,
	}
	raw := map[string]string{"a": "1", "b": "two"}
	const golden = `{"id":"cmd-golden","type":"sync_config","steward_id":"steward-1","tenant_id":"tenant-1","timestamp":"2026-01-02T03:04:05Z","params":{"a":"1","b":"two"}}`

	got, err := CommandSigningBytes(&cmd, raw)
	require.NoError(t, err)
	assert.Equal(t, golden, string(got))

	viaVersion, err := CommandSigningBytesVersion(&cmd, raw, SigningPayloadV1)
	require.NoError(t, err)
	assert.Equal(t, golden, string(viaVersion))
}

// TestCommandSigningBytesV2_CoversTerm: under v2 the term and the payload version
// are part of the signed bytes, and every v1 field is still covered.
func TestCommandSigningBytesV2_CoversTerm(t *testing.T) {
	base := Command{
		ID:        "cmd-1",
		Type:      CommandSyncConfig,
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Term:      5,
	}
	raw := map[string]string{"k": "v"}

	baseBytes, err := CommandSigningBytesVersion(&base, raw, SigningPayloadV2)
	require.NoError(t, err)

	changed := base
	changed.Term = 6
	termBytes, err := CommandSigningBytesVersion(&changed, raw, SigningPayloadV2)
	require.NoError(t, err)
	assert.NotEqual(t, string(baseBytes), string(termBytes), "changing only Term must change v2 bytes")

	v1Bytes, err := CommandSigningBytesVersion(&base, raw, SigningPayloadV1)
	require.NoError(t, err)
	assert.NotEqual(t, string(v1Bytes), string(baseBytes))
	assert.Contains(t, string(baseBytes), `"payload_version":2`)

	mutators := map[string]func(c *Command){
		"id":        func(c *Command) { c.ID = "other" },
		"type":      func(c *Command) { c.Type = CommandSyncDNA },
		"steward":   func(c *Command) { c.StewardID = "other" },
		"tenant":    func(c *Command) { c.TenantID = "other" },
		"timestamp": func(c *Command) { c.Timestamp = c.Timestamp.Add(time.Second) },
	}
	for name, mutate := range mutators {
		c := base
		mutate(&c)
		b, err := CommandSigningBytesVersion(&c, raw, SigningPayloadV2)
		require.NoError(t, err)
		assert.NotEqual(t, string(baseBytes), string(b), "v2 must cover %s", name)
	}
	paramBytes, err := CommandSigningBytesVersion(&base, map[string]string{"k": "x"}, SigningPayloadV2)
	require.NoError(t, err)
	assert.NotEqual(t, string(baseBytes), string(paramBytes), "v2 must cover params")
}

func TestCommandSigningBytesVersion_UnknownVersionRejected(t *testing.T) {
	cmd := Command{ID: "c", Timestamp: time.Now()}
	for _, v := range []uint32{0, 3, 99} {
		_, err := CommandSigningBytesVersion(&cmd, nil, v)
		assert.ErrorIs(t, err, ErrUnknownSigningPayloadVersion, "version %d", v)
	}
}
