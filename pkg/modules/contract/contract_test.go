// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package contract_test

import (
	modules "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
)

// Compile-time assertions: verify the contract aliases correctly re-export
// the generated gRPC interfaces.  If either type alias is wrong or the
// underlying generated type changes incompatibly, these var declarations will
// fail to compile.

// --- Server-side assertions ---
// Embed the generated Unimplemented* stub to get a concrete type, then check
// it satisfies the wrapper interface.

type stewardServerImpl struct {
	modules.UnimplementedModuleServiceServer
}

var _ contract.StewardModuleServer = (*stewardServerImpl)(nil)

type workflowServerImpl struct {
	modules.UnimplementedWorkflowModuleServiceServer
}

var _ contract.WorkflowModuleServer = (*workflowServerImpl)(nil)

// --- Client-side assertions ---
// A nil of the generated interface type must be assignable to the wrapper
// interface (which is a type alias for that same generated interface).

var _ contract.StewardModuleClient = (modules.ModuleServiceClient)(nil)

var _ contract.WorkflowModuleClient = (modules.WorkflowModuleServiceClient)(nil)
