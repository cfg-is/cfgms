// Package testing provides intelligent configuration state comparison for steward.
//
// This package implements system-level testing logic that compares ConfigState
// objects to detect configuration drift. It only compares managed fields,
// provides detailed diff information, and supports type-aware value comparison.
//
// The comparison engine is designed for efficiency and accuracy:
//   - Only compares fields that are actually managed by the module
//   - Provides detailed diff information for debugging and logging
//   - Handles complex data types with deep equality checking
//   - Distinguishes between value changes and type changes
//
// Basic usage:
//
//	// Create comparator
//	comparator := testing.NewStateComparator()
//
//	// Compare two ConfigState objects
//	current := getCurrentState()
//	desired := getDesiredState()
//	driftDetected, diff := comparator.CompareStates(current, desired)
//
//	if driftDetected {
//		log.Printf("Configuration drift: %s", diff.GetDriftSummary())
//		log.Printf("Details: %s", diff.GetDetailedDiff())
//	}
//
// The comparison process:
//  1. Extract managed fields from the desired state
//  2. Get field values for both current and desired states
//  3. Compare only the managed fields using deep equality
//  4. Generate detailed diff with change information
package testing

import (
	"fmt"
	"reflect"

	"github.com/cfgis/cfgms/features/modules"
)

// StateComparator provides intelligent field-level comparison of ConfigStates.
//
// The comparator implements the core logic for detecting configuration drift
// by comparing only managed fields between current and desired states.
type StateComparator struct {
	// Add configuration options if needed in the future
}

// StateDiff represents the differences between two configuration states.
//
// This structure provides detailed information about what changed, was added,
// or was removed between the current and desired configuration states.
type StateDiff struct {
	// ChangedFields maps field names to their specific differences
	ChangedFields map[string]FieldDiff

	// AddedFields contains fields present in desired but not in current
	AddedFields map[string]interface{}

	// RemovedFields contains fields present in current but not in desired
	RemovedFields map[string]interface{}
}

// FieldDiff represents a difference in a specific configuration field.
//
// This captures both the old and new values along with metadata about
// the type of change that occurred.
type FieldDiff struct {
	// Current is the existing field value
	Current interface{}

	// Desired is the target field value
	Desired interface{}

	// Type indicates the kind of difference detected
	Type DiffType
}

// DiffType represents the type of difference detected between field values.
type DiffType int

const (
	// DiffTypeChanged indicates the field value changed but type remained the same
	DiffTypeChanged DiffType = iota

	// DiffTypeAdded indicates the field was added to the configuration
	DiffTypeAdded

	// DiffTypeRemoved indicates the field was removed from the configuration
	DiffTypeRemoved

	// DiffTypeTypeChanged indicates both the value and type changed
	DiffTypeTypeChanged
)

// NewStateComparator creates a new StateComparator instance.
//
// The returned comparator is ready to use for comparing ConfigState objects
// and detecting configuration drift.
func NewStateComparator() *StateComparator {
	return &StateComparator{}
}

// CompareStates compares current and desired states and detects configuration drift.
//
// This method implements the core comparison logic:
//  1. Extracts managed fields from the desired state
//  2. Compares only those fields between current and desired states
//  3. Generates detailed diff information for any differences
//
// Returns true if drift is detected (any managed fields differ), along with
// a detailed StateDiff containing information about all differences found.
//
// The comparison only considers fields listed in desired.GetManagedFields(),
// ensuring that unmanaged fields don't trigger false drift detection.
func (c *StateComparator) CompareStates(current, desired modules.ConfigState) (bool, StateDiff) {
	diff := StateDiff{
		ChangedFields: make(map[string]FieldDiff),
		AddedFields:   make(map[string]interface{}),
		RemovedFields: make(map[string]interface{}),
	}

	// Get managed fields from desired state to determine what to compare
	managedFields := desired.GetManagedFields()

	// Only compare managed fields
	managedFieldValues := c.GetManagedFieldValues(current, managedFields)
	desiredFieldValues := c.GetManagedFieldValues(desired, managedFields)

	// Calculate differences
	c.calculateDifferences(managedFieldValues, desiredFieldValues, &diff)

	// Return true if any differences were found
	driftDetected := len(diff.ChangedFields) > 0 || len(diff.AddedFields) > 0 || len(diff.RemovedFields) > 0

	return driftDetected, diff
}

// GetManagedFieldValues extracts values for managed fields from a ConfigState
func (c *StateComparator) GetManagedFieldValues(state modules.ConfigState, managedFields []string) map[string]interface{} {
	stateMap := state.AsMap()
	result := make(map[string]interface{})

	for _, field := range managedFields {
		if value, exists := stateMap[field]; exists {
			result[field] = value
		}
	}

	return result
}

// calculateDifferences compares two field value maps and populates the StateDiff
func (c *StateComparator) calculateDifferences(current, desired map[string]interface{}, diff *StateDiff) {
	// Check for changed and removed fields
	for field, currentValue := range current {
		if desiredValue, exists := desired[field]; exists {
			// Field exists in both - check if values are different
			if !c.valuesEqual(currentValue, desiredValue) {
				diff.ChangedFields[field] = FieldDiff{
					Current: currentValue,
					Desired: desiredValue,
					Type:    c.getDiffType(currentValue, desiredValue),
				}
			}
		} else {
			// Field exists in current but not in desired - will be removed
			diff.RemovedFields[field] = currentValue
		}
	}

	// Check for added fields
	for field, desiredValue := range desired {
		if _, exists := current[field]; !exists {
			// Field exists in desired but not in current - will be added
			diff.AddedFields[field] = desiredValue
		}
	}
}

// valuesEqual compares two values for equality, handling different types appropriately
func (c *StateComparator) valuesEqual(current, desired interface{}) bool {
	// Handle nil values
	if current == nil && desired == nil {
		return true
	}
	if current == nil || desired == nil {
		return false
	}

	// Use reflect.DeepEqual for comprehensive comparison
	return reflect.DeepEqual(current, desired)
}

// getDiffType determines the type of difference between two values
func (c *StateComparator) getDiffType(current, desired interface{}) DiffType {
	// Check if types are different
	if reflect.TypeOf(current) != reflect.TypeOf(desired) {
		return DiffTypeTypeChanged
	}

	// Default to changed value
	return DiffTypeChanged
}

// CalculateDrift analyzes the differences between managed field values
func (c *StateComparator) CalculateDrift(current, desired map[string]interface{}) StateDiff {
	diff := StateDiff{
		ChangedFields: make(map[string]FieldDiff),
		AddedFields:   make(map[string]interface{}),
		RemovedFields: make(map[string]interface{}),
	}

	c.calculateDifferences(current, desired, &diff)
	return diff
}

// GetDriftSummary returns a human-readable summary of the differences
func (d *StateDiff) GetDriftSummary() string {
	if d.IsEmpty() {
		return "No configuration drift detected"
	}

	summary := fmt.Sprintf("Configuration drift detected: %d changed, %d added, %d removed fields",
		len(d.ChangedFields), len(d.AddedFields), len(d.RemovedFields))

	return summary
}

// IsEmpty returns true if no differences were detected
func (d *StateDiff) IsEmpty() bool {
	return len(d.ChangedFields) == 0 && len(d.AddedFields) == 0 && len(d.RemovedFields) == 0
}

// GetChangedFieldNames returns a slice of field names that have changed
func (d *StateDiff) GetChangedFieldNames() []string {
	fields := make([]string, 0, len(d.ChangedFields))
	for field := range d.ChangedFields {
		fields = append(fields, field)
	}
	return fields
}

// GetAddedFieldNames returns a slice of field names that were added
func (d *StateDiff) GetAddedFieldNames() []string {
	fields := make([]string, 0, len(d.AddedFields))
	for field := range d.AddedFields {
		fields = append(fields, field)
	}
	return fields
}

// GetRemovedFieldNames returns a slice of field names that were removed
func (d *StateDiff) GetRemovedFieldNames() []string {
	fields := make([]string, 0, len(d.RemovedFields))
	for field := range d.RemovedFields {
		fields = append(fields, field)
	}
	return fields
}

// GetDetailedDiff returns a detailed string representation of all differences
func (d *StateDiff) GetDetailedDiff() string {
	if d.IsEmpty() {
		return "No differences detected"
	}

	result := "Detected differences:\n"

	// Changed fields
	for field, diff := range d.ChangedFields {
		result += fmt.Sprintf("  Changed: %s: %v -> %v\n", field, diff.Current, diff.Desired)
	}

	// Added fields
	for field, value := range d.AddedFields {
		result += fmt.Sprintf("  Added: %s: %v\n", field, value)
	}

	// Removed fields
	for field, value := range d.RemovedFields {
		result += fmt.Sprintf("  Removed: %s: %v\n", field, value)
	}

	return result
}
