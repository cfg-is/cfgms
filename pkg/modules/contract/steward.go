// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package contract re-exports the generated gRPC types under stable names that
// the steward runtime (S7) and outpost runtime can import without depending
// directly on the generated package path.
package contract

import modules "github.com/cfgis/cfgms/api/proto/modules"

// StewardModuleClient is the client-side contract for steward/outpost modules.
// The steward runtime dials each out-of-process module binary and holds one of
// these per active module session.
type StewardModuleClient = modules.ModuleServiceClient

// StewardModuleServer is the server-side contract that each module binary must
// implement.  Module authors embed UnimplementedModuleServiceServer for forward
// compatibility.
type StewardModuleServer = modules.ModuleServiceServer
