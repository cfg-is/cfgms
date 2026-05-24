// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package execution

import (
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
)

// ExecutorFactory exposes the factory field of Executor for package execution_test inspection.
var ExecutorFactory = func(e *Executor) *factory.ModuleFactory { return e.factory }

// ExecutorComparator exposes the comparator field of Executor for package execution_test inspection.
var ExecutorComparator = func(e *Executor) *stewardtesting.StateComparator { return e.comparator }

// HandleResourceError exposes the unexported handleResourceError method for package execution_test files.
var HandleResourceError = (*Executor).handleResourceError

// ExecutorDriftMode exposes the driftMode field of Executor for package execution_test inspection.
var ExecutorDriftMode = func(e *Executor) config.DriftMode { return e.driftMode }
