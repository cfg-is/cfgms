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

// listenTestAddr returns a platform-appropriate address for Listen: a named
// pipe path on Windows (not backed by a filesystem, so t.TempDir() is not
// involved), a Unix domain socket path in a private mode-0700 directory
// elsewhere — the layout the steward runtime uses for real module sockets
// (features/steward/modules/runtime/socket_unix.go).
func listenTestAddr(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return `\\.\pipe\cfgms-contract-` + strings.NewReplacer(`\`, "-", "/", "-").Replace(t.Name())
	}
	sockDir := filepath.Join(t.TempDir(), "sockets")
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
	defer func() { _ = lis.Close() }()

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
	addr := filepath.Join(t.TempDir(), "no-such-dir", "test.sock")
	if goruntime.GOOS == "windows" {
		addr = "not-a-valid-pipe-path"
	}
	_, err := contract.Listen(addr)
	assert.Error(t, err)
}

// TestListen_RestrictsAccessToOwner verifies that the endpoint Listen creates
// is reachable only by the account that created it.
//
// The module gRPC server registers no per-caller authentication and both
// runtimes dial it with insecure.NewCredentials, so the endpoint's own access
// control is the sole trust boundary on this channel. Module names — and
// therefore addresses — are predictable, and the steward runs modules with its
// own (LocalSystem, on Windows) token, so an endpoint any local user can open
// is a local privilege escalation. Accepting a connection is not enough to
// prove the boundary holds; assertOwnerOnlyAccess inspects the platform's
// actual access control (the pipe DACL on Windows, the private socket
// directory on Unix).
func TestListen_RestrictsAccessToOwner(t *testing.T) {
	addr := listenTestAddr(t)

	lis, err := contract.Listen(addr)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	assertOwnerOnlyAccess(t, addr)
}

// dialTestAddr dials the address using the same transport Listen used to
// create it, so the round trip proves both sides agree on the address.
func dialTestAddr(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dialPlatform(ctx, addr)
}
