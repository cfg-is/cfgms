// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"

	"github.com/cfgis/cfgms/features/modules"
	contractpkg "github.com/cfgis/cfgms/pkg/modules/contract"
)

// workflowModuleClient is a local alias for the gRPC contract type that the
// controller workflow engine expects.  It anchors this file's dependency on
// pkg/modules/contract so the import is compile-checked rather than a bare string.
type workflowModuleClient = contractpkg.WorkflowModuleClient

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

// CreateModuleInstance always returns an error: the controller workflow engine
// uses workflowModuleClient (WorkflowModuleClient) and must not load steward-kind
// modules.
func (n *NullModuleFactory) CreateModuleInstance(moduleName string) (modules.Module, error) {
	return nil, fmt.Errorf("controller workflow engine uses WorkflowModuleClient; got steward-kind module: %s", moduleName)
}

// Ensure workflowModuleClient alias is referenced so the compiler sees it as used.
var _ workflowModuleClient
