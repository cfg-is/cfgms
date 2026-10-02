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
// If a future story puts the term under the signature (behind a negotiated
// signing-payload version), this test is the thing that must change with it, together
// with the hazard note on commandSigningPayload.
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
