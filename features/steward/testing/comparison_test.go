package testing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockConfigState implements ConfigState interface for testing
type mockConfigState struct {
	mock.Mock
	data          map[string]interface{}
	managedFields []string
}

func (m *mockConfigState) AsMap() map[string]interface{} {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(map[string]interface{})
	}
	return m.data
}

func (m *mockConfigState) GetManagedFields() []string {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).([]string)
	}
	return m.managedFields
}

func (m *mockConfigState) ToYAML() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockConfigState) FromYAML(data []byte) error {
	args := m.Called(data)
	return args.Error(0)
}

func (m *mockConfigState) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewStateComparator(t *testing.T) {
	comparator := NewStateComparator()
	assert.NotNil(t, comparator)
}

func TestCompareStates_NoDrift(t *testing.T) {
	comparator := NewStateComparator()

	// Create mock states with identical managed fields
	currentData := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
	}

	desiredData := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
	}

	managedFields := []string{"field1", "field2", "field3"}

	current := &mockConfigState{data: currentData, managedFields: managedFields}
	desired := &mockConfigState{data: desiredData, managedFields: managedFields}

	current.On("AsMap").Return(currentData)
	desired.On("AsMap").Return(desiredData)
	desired.On("GetManagedFields").Return(managedFields)

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.False(t, driftDetected)
	assert.True(t, diff.IsEmpty())
	assert.Len(t, diff.ChangedFields, 0)
	assert.Len(t, diff.AddedFields, 0)
	assert.Len(t, diff.RemovedFields, 0)

	current.AssertExpectations(t)
	desired.AssertExpectations(t)
}

func TestCompareStates_DriftDetected(t *testing.T) {
	comparator := NewStateComparator()

	// Create mock states with different values
	currentData := map[string]interface{}{
		"field1": "old_value",
		"field2": 42,
		"field3": true,
	}

	desiredData := map[string]interface{}{
		"field1": "new_value", // Changed
		"field2": 42,          // Same
		"field4": "added",     // Added
		// field3 removed (not in desired)
	}

	managedFields := []string{"field1", "field2", "field3", "field4"}

	current := &mockConfigState{data: currentData, managedFields: managedFields}
	desired := &mockConfigState{data: desiredData, managedFields: managedFields}

	current.On("AsMap").Return(currentData)
	desired.On("AsMap").Return(desiredData)
	desired.On("GetManagedFields").Return(managedFields)

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.True(t, driftDetected)
	assert.False(t, diff.IsEmpty())

	// Check changed fields
	assert.Len(t, diff.ChangedFields, 1)
	assert.Contains(t, diff.ChangedFields, "field1")
	assert.Equal(t, "old_value", diff.ChangedFields["field1"].Current)
	assert.Equal(t, "new_value", diff.ChangedFields["field1"].Desired)

	// Check added fields
	assert.Len(t, diff.AddedFields, 1)
	assert.Contains(t, diff.AddedFields, "field4")
	assert.Equal(t, "added", diff.AddedFields["field4"])

	// Check removed fields
	assert.Len(t, diff.RemovedFields, 1)
	assert.Contains(t, diff.RemovedFields, "field3")
	assert.Equal(t, true, diff.RemovedFields["field3"])

	current.AssertExpectations(t)
	desired.AssertExpectations(t)
}

func TestCompareStates_OnlyManagedFields(t *testing.T) {
	comparator := NewStateComparator()

	// Current has more fields, but only managed fields should be compared
	currentData := map[string]interface{}{
		"managed1":   "value1",
		"managed2":   "value2",
		"unmanaged1": "should_be_ignored",
		"unmanaged2": "also_ignored",
	}

	desiredData := map[string]interface{}{
		"managed1": "value1",
		"managed2": "changed_value", // This should be detected
	}

	managedFields := []string{"managed1", "managed2"} // Only these should be compared

	current := &mockConfigState{data: currentData, managedFields: managedFields}
	desired := &mockConfigState{data: desiredData, managedFields: managedFields}

	current.On("AsMap").Return(currentData)
	desired.On("AsMap").Return(desiredData)
	desired.On("GetManagedFields").Return(managedFields)

	driftDetected, diff := comparator.CompareStates(current, desired)

	assert.True(t, driftDetected)

	// Only managed2 should show as changed
	assert.Len(t, diff.ChangedFields, 1)
	assert.Contains(t, diff.ChangedFields, "managed2")
	assert.Equal(t, "value2", diff.ChangedFields["managed2"].Current)
	assert.Equal(t, "changed_value", diff.ChangedFields["managed2"].Desired)

	// Unmanaged fields should not appear in diff
	assert.NotContains(t, diff.ChangedFields, "unmanaged1")
	assert.NotContains(t, diff.ChangedFields, "unmanaged2")

	current.AssertExpectations(t)
	desired.AssertExpectations(t)
}

func TestGetManagedFieldValues(t *testing.T) {
	comparator := NewStateComparator()

	stateData := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
		"field4": "not_managed",
	}

	state := &mockConfigState{data: stateData}
	state.On("AsMap").Return(stateData)

	managedFields := []string{"field1", "field2", "field3"}

	result := comparator.GetManagedFieldValues(state, managedFields)

	assert.Len(t, result, 3)
	assert.Equal(t, "value1", result["field1"])
	assert.Equal(t, 42, result["field2"])
	assert.Equal(t, true, result["field3"])
	assert.NotContains(t, result, "field4") // Should not include unmanaged field

	state.AssertExpectations(t)
}

func TestValuesEqual(t *testing.T) {
	comparator := NewStateComparator()

	tests := []struct {
		name     string
		current  interface{}
		desired  interface{}
		expected bool
	}{
		{
			name:     "identical strings",
			current:  "value",
			desired:  "value",
			expected: true,
		},
		{
			name:     "different strings",
			current:  "old",
			desired:  "new",
			expected: false,
		},
		{
			name:     "identical numbers",
			current:  42,
			desired:  42,
			expected: true,
		},
		{
			name:     "different numbers",
			current:  42,
			desired:  43,
			expected: false,
		},
		{
			name:     "both nil",
			current:  nil,
			desired:  nil,
			expected: true,
		},
		{
			name:     "one nil",
			current:  nil,
			desired:  "value",
			expected: false,
		},
		{
			name:     "identical slices",
			current:  []string{"a", "b", "c"},
			desired:  []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different slices",
			current:  []string{"a", "b", "c"},
			desired:  []string{"a", "b", "d"},
			expected: false,
		},
		{
			name:     "identical maps",
			current:  map[string]int{"a": 1, "b": 2},
			desired:  map[string]int{"a": 1, "b": 2},
			expected: true,
		},
		{
			name:     "different maps",
			current:  map[string]int{"a": 1, "b": 2},
			desired:  map[string]int{"a": 1, "b": 3},
			expected: false,
		},
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
		{
			name:     "same type different value",
			current:  "old",
			desired:  "new",
			expected: DiffTypeChanged,
		},
		{
			name:     "different types",
			current:  "42",
			desired:  42,
			expected: DiffTypeTypeChanged,
		},
		{
			name:     "same type same value",
			current:  42,
			desired:  42,
			expected: DiffTypeChanged, // Still marked as changed since this is called when values differ
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := comparator.getDiffType(tt.current, tt.desired)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStateDiff_Methods(t *testing.T) {
	// Test empty diff
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

	// Test diff with changes
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
