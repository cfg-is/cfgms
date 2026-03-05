// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package initialization

import "fmt"

// RollbackTracker tracks cleanup functions that should be executed
// in reverse order if initialization fails partway through.
type RollbackTracker struct {
	steps []rollbackStep
}

type rollbackStep struct {
	name    string
	cleanup func() error
}

// NewRollbackTracker creates a new rollback tracker.
func NewRollbackTracker() *RollbackTracker {
	return &RollbackTracker{}
}

// Add registers a cleanup function to be called on rollback.
// Steps are executed in reverse order (LIFO).
func (r *RollbackTracker) Add(name string, cleanup func() error) {
	r.steps = append(r.steps, rollbackStep{name: name, cleanup: cleanup})
}

// Execute runs all registered cleanup functions in reverse order.
// It collects all errors rather than stopping at the first failure.
func (r *RollbackTracker) Execute() error {
	var errs []error
	for i := len(r.steps) - 1; i >= 0; i-- {
		step := r.steps[i]
		if err := step.cleanup(); err != nil {
			errs = append(errs, fmt.Errorf("rollback step '%s' failed: %w", step.name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("rollback encountered %d error(s): %v", len(errs), errs)
	}
	return nil
}
