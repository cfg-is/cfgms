// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
