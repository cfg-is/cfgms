// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package contract_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dialPlatform dials a Unix domain socket, the transport contract.Listen uses
// on this platform.
func dialPlatform(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

// assertOwnerOnlyAccess asserts the Unix access boundary on the module socket.
//
// A Unix domain socket's own mode is not honoured by every kernel, so the
// runtime places module sockets in a mode-0700 private directory and documents
// that directory as the trust boundary on the module gRPC channel
// (features/steward/modules/runtime/socket_unix.go). The invariant Listen must
// hold up is therefore that it binds inside the directory it was handed,
// without creating anything outside it and without relaxing its mode.
func assertOwnerOnlyAccess(t *testing.T, addr string) {
	t.Helper()

	fi, err := os.Lstat(addr)
	require.NoError(t, err, "stat socket %s", addr)
	assert.NotZero(t, fi.Mode()&os.ModeSocket, "%s is not a socket", addr)

	dir := filepath.Dir(addr)
	di, err := os.Stat(dir)
	require.NoError(t, err, "stat socket directory %s", dir)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm(),
		"module socket directory %s must stay private to its owner; Listen must not relax it", dir)
}
