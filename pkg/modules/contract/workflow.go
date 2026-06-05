// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package contract

import modules "github.com/cfgis/cfgms/api/proto/modules"

// WorkflowModuleClient is the client-side contract for controller workflow
// modules.  The workflow engine holds one of these per active module session.
type WorkflowModuleClient = modules.WorkflowModuleServiceClient

// WorkflowModuleServer is the server-side contract that each workflow module
// binary must implement.
type WorkflowModuleServer = modules.WorkflowModuleServiceServer
