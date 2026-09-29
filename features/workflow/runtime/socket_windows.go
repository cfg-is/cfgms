// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// pipeNonceBytes is how many crypto/rand bytes are mixed into every module pipe
// name. 128 bits makes the name unguessable, which is what stops a local user
// from pre-creating it (see makeSocketPath).
const pipeNonceBytes = 16

// errPipeServerMismatch reports that the named pipe was opened successfully but
// is served by some process other than the module binary this runtime
// fork/exec'd — i.e. another local process owns the name.
var errPipeServerMismatch = errors.New("named pipe is served by a foreign process")

// makeSocketPath returns the named pipe path for a module instance.
// Format: \\.\pipe\cfgms-wf-module-${name}-${id}-${nonce}
//
// runtimeDir is unused on Windows: named pipes live in NPFS, not the
// filesystem, so there is no parent directory whose permissions can be
// tightened the way socket_unix.go tightens ${runtimeDir}/sockets to 0700.
//
// The nonce is not cosmetic uniqueness — it is the access control that the
// missing directory would otherwise provide. An NPFS name belongs to whichever
// process creates it first, and a name built only from the module name and a
// per-process counter is fully predictable
// (`cfgms-wf-module-m365-entra_user-1`), so any local user could pre-create the
// names of the shipped workflow modules and wait. The module's own
// contract.Listen fails closed on the collision (go-winio requests FILE_CREATE
// for a listener's first instance) and the module exits, which leaves the
// squatter as the only server on that name: it would answer the runtime's
// handshake and then receive Apply payloads — including directory credentials —
// from the controller. 128 random bits per instance make the name unguessable
// before creation, and verifyPipeServer rejects a foreign server on every
// connection afterwards.
func makeSocketPath(runtimeDir, moduleName string, id int64) (string, error) {
	nonce := make([]byte, pipeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate module pipe nonce: %w", err)
	}
	return fmt.Sprintf(`\\.\pipe\cfgms-wf-module-%s-%d-%s`,
		sanitizeName(moduleName), id, hex.EncodeToString(nonce)), nil
}

// waitForSocket polls the named pipe at socketPath until it is served by
// process serverPID (the fork/exec'd module) or ctx is cancelled.
//
// A pipe served by any other process ends the wait immediately rather than
// counting as ready. An NPFS name belongs to whichever process created it first,
// so a foreign server on this name is terminal, not a startup transient: the
// module can never listen on it. Returning right away also makes a squatting
// attempt surface as itself instead of as a 30 s timeout.
func waitForSocket(ctx context.Context, socketPath string, serverPID int) error {
	for {
		conn, err := dialVerifiedPipe(ctx, socketPath, serverPID)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if errors.Is(err, errPipeServerMismatch) {
			return fmt.Errorf("named pipe %q is not served by the module: %w", socketPath, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("named pipe %q not ready: %w (last dial: %v)", socketPath, ctx.Err(), err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dialGRPCSocket creates a gRPC client connection over the Windows named pipe.
//
// The target is wrapped in the "passthrough" scheme so gRPC's default (DNS)
// resolver never sees the raw pipe path: DNS would treat
// `\\.\pipe\cfgms-wf-module-...` as a hostname to resolve, fail to produce any
// address, and the dial would never reach dialContext at all ("name resolver
// error: produced zero addresses"). passthrough hands the target straight to
// the ContextDialer below, unresolved.
//
// The dialer verifies the pipe's server process on every connection, not just
// the first: gRPC re-dials the target whenever the transport breaks, so a
// module that dies would otherwise let whoever grabs the freed name next serve
// the runtime's subsequent RPCs.
func dialGRPCSocket(socketPath string, serverPID int) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		"passthrough:///"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialVerifiedPipe(ctx, addr, serverPID)
		}),
	)
}

// dialVerifiedPipe opens the named pipe at addr and returns the connection only
// if its server is process serverPID. On any mismatch the connection is closed
// before it is used, so no module payload ever reaches a foreign server.
func dialVerifiedPipe(ctx context.Context, addr string, serverPID int) (net.Conn, error) {
	conn, err := winio.DialPipeContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	if err := verifyPipeServer(conn, serverPID); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// verifyPipeServer checks that the process serving conn's named pipe is
// wantPID, the module process this runtime started.
//
// The module gRPC channel carries no per-caller authentication (both sides use
// insecure.NewCredentials), so the runtime's only assurance that it is talking
// to its own child is the identity of the pipe's server. The pipe DACL
// constrains who may connect to a pipe the module created; it says nothing
// about who created the pipe, which is the direction this check covers.
func verifyPipeServer(conn net.Conn, wantPID int) error {
	// go-winio's pipe connections expose the underlying handle via Fd(); the
	// concrete type is unexported, so assert on the method set.
	handleConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("%w: connection type %T exposes no handle to identify the server process",
			errPipeServerMismatch, conn)
	}
	var gotPID uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(handleConn.Fd()), &gotPID); err != nil {
		return fmt.Errorf("%w: cannot read server process id: %w", errPipeServerMismatch, err)
	}
	if int(gotPID) != wantPID {
		return fmt.Errorf("%w: served by process %d, want module process %d",
			errPipeServerMismatch, gotPID, wantPID)
	}
	return nil
}
