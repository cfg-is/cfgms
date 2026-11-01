// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// cfgms-module-m365-entra-group is the out-of-process gRPC binary for the
// workflow-kind (controller-executed) Entra ID group module. It reads
// CFGMS_MODULE_SOCKET from the environment, registers the ModuleService
// gRPC server, and handles SIGTERM for graceful shutdown — the same
// out-of-process module pattern as the stdlib modules (see
// features/modules/stdlib/hostname/cmd/main.go) and the entra_user workflow
// module (features/workflow/modules/m365/entra_user/cmd/main.go), adapted
// for a workflow-kind module that needs a Microsoft Graph auth provider and
// API client rather than local-host access.
package main

import (
	entragroup "github.com/cfgis/cfgms/features/workflow/modules/m365/entra_group"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/moduleserver"
)

const moduleName = "m365-entra-group"

// main serves the module over the contract socket. The Microsoft Graph access
// token and execution tenant arrive in the controller's handshake; this
// process reads no secret store and no M365 environment settings.
func main() {
	moduleserver.Run(moduleName, entragroup.New)
}
