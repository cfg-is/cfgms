// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import "fmt"

// AssignStepIDs sets a deterministic structural ID on every Step in the tree.
// The ID encodes the step's position as a dotted sibling-index path:
//
//	root step 0 → "s0"
//	root step 1, child 0 → "s1.s0"
//	root step 1, child 2, child 1 → "s1.s2.s1"
//
// AssignStepIDs recurses into the Steps field of each step (the primary
// container field used by sequential, parallel, conditional, and loop steps).
// It is a pure function of tree position, is idempotent, and never reads an
// existing ID. The field must be set on the slice element (not a copy), so we
// range by index.
func AssignStepIDs(steps []Step) {
	assignStepIDsRec(steps, "")
}

func assignStepIDsRec(steps []Step, prefix string) {
	for i := range steps {
		var id string
		if prefix == "" {
			id = fmt.Sprintf("s%d", i)
		} else {
			id = fmt.Sprintf("%s.s%d", prefix, i)
		}
		steps[i].ID = id
		if len(steps[i].Steps) > 0 {
			assignStepIDsRec(steps[i].Steps, id)
		}
	}
}

// CloneSteps returns a deep copy of the steps slice so callers can safely
// mutate field values (e.g. ID assignment) without racing against goroutines
// that hold a reference to the original underlying array.
func CloneSteps(steps []Step) []Step {
	if steps == nil {
		return nil
	}
	out := make([]Step, len(steps))
	for i, s := range steps {
		out[i] = s
		out[i].Steps = CloneSteps(s.Steps)
	}
	return out
}

// StepResultKey returns the key used to store this step's result in StepResults.
// Steps that went through AssignStepIDs have a structural ID; steps in
// switch/try/catch branches that are not in the main step.Steps tree fall back
// to the step name for backward-compatible keying.
func StepResultKey(step Step) string {
	if step.ID != "" {
		return step.ID
	}
	return step.Name
}
