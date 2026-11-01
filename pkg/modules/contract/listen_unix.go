// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package contract

import "net"

// Listen returns a listener for a module binary's out-of-process gRPC
// server: a Unix domain socket at addr on this platform. addr is the value
// the module read from CFGMS_MODULE_SOCKET, which the launching runtime
// (features/workflow/runtime or features/steward/modules/runtime) constructed
// for this platform's transport.
func Listen(addr string) (net.Listener, error) {
	return net.Listen("unix", addr)
}
