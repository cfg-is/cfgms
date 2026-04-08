// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticDeviceSource is a test DeviceSource backed by a fixed device list.
type staticDeviceSource struct {
	devices []Device
}

func (s *staticDeviceSource) ListDevices() ([]Device, error) { return s.devices, nil }

func TestFilter_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"empty filter", Filter{}, true},
		{"os set", Filter{OS: "linux"}, false},
		{"tags set", Filter{Tags: []string{"prod"}}, false},
		{"groups set", Filter{Groups: []string{"servers"}}, false},
		{"dna_query set", Filter{DNAQuery: map[string]string{"env": "prod"}}, false},
		{"all fields set", Filter{OS: "windows", Tags: []string{"a"}, Groups: []string{"b"}, DNAQuery: map[string]string{"k": "v"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.filter.IsEmpty())
		})
	}
}

func TestStewardFleetQuery_Search_EmptyFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", OS: "linux"},
			{ID: "d2", OS: "windows"},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1", "d2"}, ids)
}

func TestStewardFleetQuery_Search_OSFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "linux-1", OS: "linux"},
			{ID: "linux-2", OS: "Linux"}, // case-insensitive
			{ID: "win-1", OS: "windows"},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{OS: "linux"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"linux-1", "linux-2"}, ids)
}

func TestStewardFleetQuery_Search_TagFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", Tags: []string{"prod", "web"}},
			{ID: "d2", Tags: []string{"prod", "db"}},
			{ID: "d3", Tags: []string{"staging"}},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{Tags: []string{"prod"}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1", "d2"}, ids)
}

func TestStewardFleetQuery_Search_MultipleTagsAndSemantics(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", Tags: []string{"prod", "web"}},
			{ID: "d2", Tags: []string{"prod", "db"}},
			{ID: "d3", Tags: []string{"prod"}},
		},
	}
	q := NewStewardFleetQuery(src)

	// Device must have BOTH tags
	ids, err := q.Search(Filter{Tags: []string{"prod", "web"}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1"}, ids)
}

func TestStewardFleetQuery_Search_GroupFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", Groups: []string{"servers", "eu-west"}},
			{ID: "d2", Groups: []string{"servers", "us-east"}},
			{ID: "d3", Groups: []string{"workstations"}},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{Groups: []string{"servers"}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1", "d2"}, ids)
}

func TestStewardFleetQuery_Search_DNAQueryFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", Attributes: map[string]string{"env": "prod", "tier": "web"}},
			{ID: "d2", Attributes: map[string]string{"env": "prod", "tier": "db"}},
			{ID: "d3", Attributes: map[string]string{"env": "staging"}},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{DNAQuery: map[string]string{"env": "prod", "tier": "web"}})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1"}, ids)
}

func TestStewardFleetQuery_Search_CombinedFilter(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", OS: "linux", Tags: []string{"prod"}, Groups: []string{"eu"}, Attributes: map[string]string{"role": "web"}},
			{ID: "d2", OS: "linux", Tags: []string{"prod"}, Groups: []string{"us"}, Attributes: map[string]string{"role": "db"}},
			{ID: "d3", OS: "windows", Tags: []string{"prod"}, Groups: []string{"eu"}, Attributes: map[string]string{"role": "web"}},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{
		OS:       "linux",
		Tags:     []string{"prod"},
		Groups:   []string{"eu"},
		DNAQuery: map[string]string{"role": "web"},
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1"}, ids)
}

func TestStewardFleetQuery_Search_ZeroMatch(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", OS: "linux"},
		},
	}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{OS: "windows"})
	require.NoError(t, err)
	assert.Empty(t, ids, "zero matches should return empty slice, not error")
}

func TestStewardFleetQuery_Search_EmptyFleet(t *testing.T) {
	src := &staticDeviceSource{devices: nil}
	q := NewStewardFleetQuery(src)

	ids, err := q.Search(Filter{OS: "linux"})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// TestStewardFleetQuery_Search_LiveEvaluation verifies that Search re-evaluates
// against the current DeviceSource on each call (required for recurring workflows).
func TestStewardFleetQuery_Search_LiveEvaluation(t *testing.T) {
	src := &staticDeviceSource{
		devices: []Device{
			{ID: "d1", OS: "linux"},
		},
	}
	q := NewStewardFleetQuery(src)

	// First call: one match
	ids, err := q.Search(Filter{OS: "linux"})
	require.NoError(t, err)
	assert.Equal(t, []string{"d1"}, ids)

	// Simulate fleet change (new device comes online)
	src.devices = append(src.devices, Device{ID: "d2", OS: "linux"})

	// Second call: two matches — filter re-evaluated against current state
	ids, err = q.Search(Filter{OS: "linux"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1", "d2"}, ids)
}
