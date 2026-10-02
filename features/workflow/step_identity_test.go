// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAssignStepIDs_FlatSiblings verifies that top-level steps receive s0, s1, s2, ...
func TestAssignStepIDs_FlatSiblings(t *testing.T) {
	steps := []Step{
		{Name: "a", Type: StepTypeTask},
		{Name: "b", Type: StepTypeTask},
		{Name: "c", Type: StepTypeTask},
	}
	AssignStepIDs(steps)

	assert.Equal(t, "s0", steps[0].ID)
	assert.Equal(t, "s1", steps[1].ID)
	assert.Equal(t, "s2", steps[2].ID)
}

// TestAssignStepIDs_NestedContainers verifies that child steps get dotted paths.
func TestAssignStepIDs_NestedContainers(t *testing.T) {
	steps := []Step{
		{
			Name: "outer",
			Type: StepTypeSequential,
			Steps: []Step{
				{Name: "child-a", Type: StepTypeTask},
				{
					Name: "child-b",
					Type: StepTypeSequential,
					Steps: []Step{
						{Name: "grandchild", Type: StepTypeTask},
					},
				},
			},
		},
	}
	AssignStepIDs(steps)

	assert.Equal(t, "s0", steps[0].ID)
	assert.Equal(t, "s0.s0", steps[0].Steps[0].ID)
	assert.Equal(t, "s0.s1", steps[0].Steps[1].ID)
	assert.Equal(t, "s0.s1.s0", steps[0].Steps[1].Steps[0].ID)
}

// TestAssignStepIDs_LoopBodiesAtDifferentPositions verifies that two structurally-identical
// loop body steps at different positions in the top-level slice get distinct IDs.
func TestAssignStepIDs_LoopBodiesAtDifferentPositions(t *testing.T) {
	steps := []Step{
		{
			Name:  "loop-a",
			Type:  StepTypeFor,
			Steps: []Step{{Name: "body-step", Type: StepTypeTask}},
		},
		{
			Name:  "loop-b",
			Type:  StepTypeFor,
			Steps: []Step{{Name: "body-step", Type: StepTypeTask}},
		},
	}
	AssignStepIDs(steps)

	assert.Equal(t, "s0", steps[0].ID)
	assert.Equal(t, "s1", steps[1].ID)
	// The loop bodies share the same name and structure, but their parent
	// positions differ — so their full positional IDs are distinct.
	assert.Equal(t, "s0.s0", steps[0].Steps[0].ID)
	assert.Equal(t, "s1.s0", steps[1].Steps[0].ID)
	assert.NotEqual(t, steps[0].Steps[0].ID, steps[1].Steps[0].ID)
}

// TestAssignStepIDs_Idempotent verifies that calling AssignStepIDs twice yields
// the same IDs as calling it once.
func TestAssignStepIDs_Idempotent(t *testing.T) {
	steps := []Step{
		{
			Name: "top",
			Type: StepTypeSequential,
			Steps: []Step{
				{Name: "first", Type: StepTypeTask},
				{Name: "second", Type: StepTypeTask},
			},
		},
		{Name: "sibling", Type: StepTypeTask},
	}

	AssignStepIDs(steps)
	firstPass := []string{
		steps[0].ID,
		steps[0].Steps[0].ID,
		steps[0].Steps[1].ID,
		steps[1].ID,
	}

	AssignStepIDs(steps)
	secondPass := []string{
		steps[0].ID,
		steps[0].Steps[0].ID,
		steps[0].Steps[1].ID,
		steps[1].ID,
	}

	assert.Equal(t, firstPass, secondPass)
}
