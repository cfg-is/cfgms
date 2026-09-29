// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Command exit_module is a test fixture for the workflow module runtime: it
// exits immediately with a failure status and never listens on
// CFGMS_MODULE_SOCKET.
//
// This is the shape of a module that fails closed at startup — most importantly
// the case where the address it was told to listen on is already taken (on
// Windows, a named pipe whose name another local process created first), where
// contract.Listen cannot bind and the module's main log.Fatalf's. The runtime
// must report that exit rather than keep waiting on, and then trusting, whatever
// else is serving that address.
package main

import "os"

func main() {
	os.Exit(1)
}
