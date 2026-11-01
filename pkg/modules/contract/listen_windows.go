// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package contract

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// modulePipeSDDL is the security descriptor applied to every module named
// pipe: a protected DACL (P — the NPFS default ACL is not inherited) whose
// single allow ACE grants GENERIC_ALL to the pipe's owner (OW).
//
// This DACL is the trust boundary for inbound clients on the module gRPC
// channel: the module server registers no per-caller authentication and both
// runtimes dial with insecure.NewCredentials. go-winio's default — what a nil
// PipeConfig selects — is rtlDefaultNpAcl, which grants Everyone and ANONYMOUS
// LOGON read/write. Since the steward runs modules with its own LocalSystem
// token, that default would let any unprivileged local user invoke
// ModuleService.Apply against a SYSTEM module.
//
// It is not full parity with the mode-0700 socket directory on Unix (see
// features/steward/modules/runtime/socket_unix.go), and must not be read as
// such: that directory also stops another user from *creating* the endpoint,
// whereas an NPFS name belongs to whichever process creates it first and this
// DACL only applies once the module has created the pipe. The opposite
// direction — a local user pre-creating a module's pipe name and serving the
// runtime itself — is closed in the runtimes, which put 128 crypto/rand bits in
// every pipe name and verify the pipe's server process on every connection
// (features/steward/modules/runtime/socket_windows.go,
// features/workflow/runtime/socket_windows.go).
//
// The owner is the launching runtime's own account — the runtime fork/execs
// the module with its own token — so the runtime can still connect and the
// server can still create further pipe instances. Matches the decision already
// made for the script relay in features/steward/script_relay/relay_windows.go.
const modulePipeSDDL = "D:P(A;;GA;;;OW)"

// Listen returns a listener for a module binary's out-of-process gRPC
// server: a named pipe at addr on this platform. addr is the value the
// module read from CFGMS_MODULE_SOCKET, which the launching runtime
// (features/workflow/runtime or features/steward/modules/runtime) constructed
// as a \\.\pipe\... path for this platform's transport.
//
// The pipe is created with modulePipeSDDL so that only the launching runtime's
// account can connect.
func Listen(addr string) (net.Listener, error) {
	return winio.ListenPipe(addr, &winio.PipeConfig{
		SecurityDescriptor: modulePipeSDDL,
	})
}
