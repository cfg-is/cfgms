// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package contract_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/contract"
)

// listenTestBaseDir returns a base directory for Unix socket paths that is
// short enough to bind.
//
// t.TempDir() cannot be used here: on macOS it returns a
// /var/folders/<...>/T/<test-name>/ path that is already 80+ bytes before the
// sockets subdirectory and filename are appended, which overflows
// sockaddr_un.sun_path (103 usable bytes — socket_unix.go's
// unixSocketPathMax) and makes net.Listen("unix", ...) fail with
// "bind: invalid argument". The sibling runtime tests adopted this same /tmp
// base for exactly that reason; see shortBaseDir in
// features/steward/modules/runtime/runtime_test.go.
//
// Only called on non-Windows platforms, where /tmp always exists.
func listenTestBaseDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "cfgms-listen-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// listenTestAddr returns a platform-appropriate address for Listen: a named
// pipe path on Windows (not backed by a filesystem, so no temp dir is
// involved), a Unix domain socket path in a private mode-0700 directory
// elsewhere — the layout the steward runtime uses for real module sockets
// (features/steward/modules/runtime/socket_unix.go).
func listenTestAddr(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return `\\.\pipe\cfgms-contract-` + strings.NewReplacer(`\`, "-", "/", "-").Replace(t.Name())
	}
	sockDir := filepath.Join(listenTestBaseDir(t), "sockets")
	// #nosec G301 -- 0700 is the restrictive mode under test; the execute bit
	// is required for the owning process to traverse to the socket.
	require.NoError(t, os.Mkdir(sockDir, 0o700))
	return filepath.Join(sockDir, "listen-test.sock")
}

// TestListen_AcceptsConnection verifies that Listen returns a net.Listener
// that a client can actually connect to and exchange bytes over — proving the
// address is valid for the platform's real transport, not just well-formed.
func TestListen_AcceptsConnection(t *testing.T) {
	addr := listenTestAddr(t)

	lis, err := contract.Listen(addr)
	require.NoError(t, err)
	defer closeTestPipeListener(t, addr, lis)

	serverDone := make(chan struct{})
	var serverErr error
	go func() {
		defer close(serverDone)
		conn, acceptErr := lis.Accept()
		if acceptErr != nil {
			serverErr = acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 5)
		if _, readErr := conn.Read(buf); readErr != nil {
			serverErr = readErr
			return
		}
		if string(buf) != "hello" {
			serverErr = assert.AnError
		}
	}()

	conn, err := dialTestAddr(t, addr)
	require.NoError(t, err)
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept connection within timeout")
	}
	assert.NoError(t, serverErr)
}

// TestListen_ErrorsOnInvalidAddr verifies Listen surfaces an error rather
// than panicking when the address cannot be bound (parent directory does not
// exist on Unix; malformed pipe path on Windows).
func TestListen_ErrorsOnInvalidAddr(t *testing.T) {
	addr := "not-a-valid-pipe-path"
	if goruntime.GOOS != "windows" {
		// Base the path on the short /tmp dir so the bind fails because the
		// parent directory is missing — the condition under test — and not
		// because the path overflowed sun_path.
		addr = filepath.Join(listenTestBaseDir(t), "no-such-dir", "test.sock")
	}
	_, err := contract.Listen(addr)
	assert.Error(t, err)
}

// TestListen_RestrictsAccessToOwner verifies that the endpoint Listen creates
// is reachable only by the account that created it.
//
// The module gRPC server registers no per-caller authentication and both
// runtimes dial it with insecure.NewCredentials, so the endpoint's own access
// control is the trust boundary for inbound clients on this channel. The steward
// runs modules with its own (LocalSystem, on Windows) token, so an endpoint any
// local user can open is a local privilege escalation. The runtimes additionally
// put crypto/rand entropy in each address, but that keeps an address from being
// guessed or pre-created — it does not restrict who may connect to one that
// leaks, which is what this test covers. Accepting a connection is not enough to
// prove the boundary holds; assertOwnerOnlyAccess inspects the platform's
// actual access control (the pipe DACL on Windows, the private socket
// directory on Unix).
func TestListen_RestrictsAccessToOwner(t *testing.T) {
	addr := listenTestAddr(t)

	lis, err := contract.Listen(addr)
	require.NoError(t, err)
	defer closeTestPipeListener(t, addr, lis)

	// On Windows, a connectable named pipe instance only exists once something
	// calls Accept: go-winio creates the listener's first instance without
	// read/write access, which deliberately leaves it disconnected, so every
	// client-side open -- including the one GetNamedSecurityInfo makes
	// internally to read the descriptor below -- fails with ERROR_PIPE_BUSY
	// ("all pipe instances are busy") until Accept runs. Keep accepting for
	// the duration of the check. This is a no-op on Unix, where Lstat/Stat
	// never dial.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := lis.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	assertOwnerOnlyAccess(t, addr)

	// Close before waiting: the accept loop only returns once the listener is
	// closed. Bounded per pipeCloseTimeout so a go-winio Close/Accept deadlock
	// (#4438) fails this test loudly instead of hanging it.
	closeTestPipeListener(t, addr, lis)
	<-acceptDone
}

// dialTestAddr dials the address using the same transport Listen used to
// create it, so the round trip proves both sides agree on the address.
func dialTestAddr(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dialPlatform(ctx, addr)
}

// pipeCloseTimeout bounds how long a test's cleanup waits for
// win32PipeListener.Close (go-winio) to return.
//
// See #4438: go-winio v0.6.2's win32PipeListener can leave Close blocked
// forever on <-l.doneCh when Close races a concurrent Accept, because the
// abort error surfaced to listenerRoutine is not always the sentinel it
// checks for. Close takes no context, so nothing above it can bound the call
// except racing it on its own goroutine, as closeTestPipeListener does. This
// is a no-op cost on non-Windows platforms, where net.Listener.Close does not
// have this failure mode, so the helper is defined here unconditionally
// rather than split across a windows/!windows pair.
const pipeCloseTimeout = 5 * time.Second

// closeTestPipeListener closes lis with a hard bound; see pipeCloseTimeout.
func closeTestPipeListener(t *testing.T, addr string, lis net.Listener) {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		_ = lis.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(pipeCloseTimeout):
		t.Errorf("pipe listener for %s did not close within %s (see pipeCloseTimeout)", addr, pipeCloseTimeout)
	}
}
