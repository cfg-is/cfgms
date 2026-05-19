// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// testConfigState is a real implementation of modules.ConfigState used in tests.
// No mocks — state is held in a plain map, matching the genericConfigState pattern.
type testConfigState struct {
	data          map[string]interface{}
	managedFields []string
}

func (s *testConfigState) AsMap() map[string]interface{} {
	return s.data
}

func (s *testConfigState) GetManagedFields() []string {
	return s.managedFields
}

func (s *testConfigState) ToYAML() ([]byte, error) {
	return yaml.Marshal(s.data)
}

func (s *testConfigState) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, &s.data)
}

func (s *testConfigState) Validate() error {
	return nil
}

func TestNewStateComparator(t *testing.T) {
	comparator := NewStateComparator()
	assert.NotNil(t, comparator)
}

func TestCompareStates_NoDrift(t *testing.T) {
	comparator := NewStateComparator()

	managedFields := []string{"field1", "field2", "field3"}
	sharedData := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
	}

	current := &testConfigState{data: sharedData, managedFields: managedFields}
	desired := &testConfigState{data: sharedData, managedFields: managedFields}

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.False(t, driftDetected)
	assert.True(t, diff.IsEmpty())
	assert.Len(t, diff.ChangedFields, 0)
	assert.Len(t, diff.AddedFields, 0)
	assert.Len(t, diff.RemovedFields, 0)
}

func TestCompareStates_DriftDetected(t *testing.T) {
	comparator := NewStateComparator()

	managedFields := []string{"field1", "field2", "field3", "field4"}

	current := &testConfigState{
		data: map[string]interface{}{
			"field1": "old_value",
			"field2": 42,
			"field3": true,
		},
		managedFields: managedFields,
	}
	desired := &testConfigState{
		data: map[string]interface{}{
			"field1": "new_value", // Changed
			"field2": 42,          // Same
			"field4": "added",     // Added
			// field3 removed (not in desired)
		},
		managedFields: managedFields,
	}

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.True(t, driftDetected)
	assert.False(t, diff.IsEmpty())

	assert.Len(t, diff.ChangedFields, 1)
	assert.Contains(t, diff.ChangedFields, "field1")
	assert.Equal(t, "old_value", diff.ChangedFields["field1"].Current)
	assert.Equal(t, "new_value", diff.ChangedFields["field1"].Desired)

	assert.Len(t, diff.AddedFields, 1)
	assert.Contains(t, diff.AddedFields, "field4")
	assert.Equal(t, "added", diff.AddedFields["field4"])

	assert.Len(t, diff.RemovedFields, 1)
	assert.Contains(t, diff.RemovedFields, "field3")
	assert.Equal(t, true, diff.RemovedFields["field3"])
}

func TestCompareStates_OnlyManagedFields(t *testing.T) {
	comparator := NewStateComparator()

	managedFields := []string{"managed1", "managed2"}

	current := &testConfigState{
		data: map[string]interface{}{
			"managed1":   "value1",
			"managed2":   "value2",
			"unmanaged1": "should_be_ignored",
			"unmanaged2": "also_ignored",
		},
		managedFields: managedFields,
	}
	desired := &testConfigState{
		data: map[string]interface{}{
			"managed1": "value1",
			"managed2": "changed_value",
		},
		managedFields: managedFields,
	}

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.True(t, driftDetected)
	assert.Len(t, diff.ChangedFields, 1)
	assert.Contains(t, diff.ChangedFields, "managed2")
	assert.Equal(t, "value2", diff.ChangedFields["managed2"].Current)
	assert.Equal(t, "changed_value", diff.ChangedFields["managed2"].Desired)
	assert.NotContains(t, diff.ChangedFields, "unmanaged1")
	assert.NotContains(t, diff.ChangedFields, "unmanaged2")
}

func TestGetManagedFieldValues(t *testing.T) {
	comparator := NewStateComparator()

	state := &testConfigState{
		data: map[string]interface{}{
			"field1": "value1",
			"field2": 42,
			"field3": true,
			"field4": "not_managed",
		},
	}

	result := comparator.GetManagedFieldValues(state, []string{"field1", "field2", "field3"})

	assert.Len(t, result, 3)
	assert.Equal(t, "value1", result["field1"])
	assert.Equal(t, 42, result["field2"])
	assert.Equal(t, true, result["field3"])
	assert.NotContains(t, result, "field4")
}

func TestValuesEqual(t *testing.T) {
	comparator := NewStateComparator()

	tests := []struct {
		name     string
		current  interface{}
		desired  interface{}
		expected bool
	}{
		{"identical strings", "value", "value", true},
		{"different strings", "old", "new", false},
		{"identical numbers", 42, 42, true},
		{"different numbers", 42, 43, false},
		{"both nil", nil, nil, true},
		{"one nil", nil, "value", false},
		{"identical slices", []string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{"different slices", []string{"a", "b", "c"}, []string{"a", "b", "d"}, false},
		{"identical maps", map[string]int{"a": 1, "b": 2}, map[string]int{"a": 1, "b": 2}, true},
		{"different maps", map[string]int{"a": 1, "b": 2}, map[string]int{"a": 1, "b": 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := comparator.valuesEqual(tt.current, tt.desired)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDiffType(t *testing.T) {
	comparator := NewStateComparator()

	tests := []struct {
		name     string
		current  interface{}
		desired  interface{}
		expected DiffType
	}{
		{"same type different value", "old", "new", DiffTypeChanged},
		{"different types", "42", 42, DiffTypeTypeChanged},
		{"same type same value", 42, 42, DiffTypeChanged},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := comparator.getDiffType(tt.current, tt.desired)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStateDiff_Methods(t *testing.T) {
	emptyDiff := StateDiff{
		ChangedFields: map[string]FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}

	assert.True(t, emptyDiff.IsEmpty())
	assert.Equal(t, "No configuration drift detected", emptyDiff.GetDriftSummary())
	assert.Len(t, emptyDiff.GetChangedFieldNames(), 0)
	assert.Len(t, emptyDiff.GetAddedFieldNames(), 0)
	assert.Len(t, emptyDiff.GetRemovedFieldNames(), 0)

	diff := StateDiff{
		ChangedFields: map[string]FieldDiff{
			"field1": {Current: "old", Desired: "new", Type: DiffTypeChanged},
			"field2": {Current: 42, Desired: 43, Type: DiffTypeChanged},
		},
		AddedFields: map[string]interface{}{
			"field3": "added_value",
		},
		RemovedFields: map[string]interface{}{
			"field4": "removed_value",
		},
	}

	assert.False(t, diff.IsEmpty())
	assert.Contains(t, diff.GetDriftSummary(), "2 changed, 1 added, 1 removed")

	changedFields := diff.GetChangedFieldNames()
	assert.Len(t, changedFields, 2)
	assert.Contains(t, changedFields, "field1")
	assert.Contains(t, changedFields, "field2")

	addedFields := diff.GetAddedFieldNames()
	assert.Len(t, addedFields, 1)
	assert.Contains(t, addedFields, "field3")

	removedFields := diff.GetRemovedFieldNames()
	assert.Len(t, removedFields, 1)
	assert.Contains(t, removedFields, "field4")

	detailedDiff := diff.GetDetailedDiff()
	assert.Contains(t, detailedDiff, "Changed: field1: old -> new")
	assert.Contains(t, detailedDiff, "Changed: field2: 42 -> 43")
	assert.Contains(t, detailedDiff, "Added: field3: added_value")
	assert.Contains(t, detailedDiff, "Removed: field4: removed_value")
}

// TestStateDiff_EventType asserts that the EventType field propagates correctly
// through the StateDiff struct and is available to DriftEventHandler receivers.
func TestStateDiff_EventType(t *testing.T) {
	diff := StateDiff{
		ChangedFields: map[string]FieldDiff{},
		AddedFields:   map[string]interface{}{},
		RemovedFields: map[string]interface{}{},
	}

	assert.Empty(t, diff.EventType, "EventType defaults to empty")

	diff.EventType = "drift.detected"
	assert.Equal(t, "drift.detected", diff.EventType)

	diff.EventType = "drift.detected.monitor"
	assert.Equal(t, "drift.detected.monitor", diff.EventType,
		"drift.detected.monitor must be storable for monitor-mode telemetry")
}
