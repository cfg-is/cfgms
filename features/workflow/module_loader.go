// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"

	"github.com/cfgis/cfgms/features/modules"
)

// ModuleLoader creates module instances by name for use by the workflow engine.
// Placing this interface here (rather than in features/modules/) keeps it
// workflow-internal — only Engine consumes it, so no central-provider
// interfaces/ subdirectory is required.
type ModuleLoader interface {
	CreateModuleInstance(moduleName string) (modules.Module, error)
}

// NullModuleFactory is a ModuleLoader for contexts (e.g. the controller) where
// steward modules must not be loaded.  Every call returns an error.
type NullModuleFactory struct{}

// NewNullModuleFactory returns a ModuleLoader that rejects every module name.
func NewNullModuleFactory() ModuleLoader {
	return &NullModuleFactory{}
}

// CreateModuleInstance always returns an error documenting that the controller
// workflow engine does not load steward modules.
func (n *NullModuleFactory) CreateModuleInstance(moduleName string) (modules.Module, error) {
	return nil, fmt.Errorf("controller workflow engine does not load steward modules: %s", moduleName)
}
