// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// unixSocketPathMax is the maximum Unix domain socket path length set by the
// strictest mainstream platform. macOS sockaddr_un.sun_path is 104 bytes
// (including the null terminator), so the usable path length is 103 chars.
// Linux allows 108. Picking the smaller value keeps cross-platform behavior
// predictable.
const unixSocketPathMax = 103

// socketsSubdir is the name of the steward-private directory created under
// runtimeDir for all module sockets. Mode 0700 restricts access to the steward
// process owner, which is the sole trust boundary on the module gRPC channel
// (the dialer uses insecure.NewCredentials with no per-caller authentication).
const socketsSubdir = "sockets"

// makeSocketPath returns the Unix domain socket path for a module instance,
// creating the steward-private socket directory if it does not already exist.
//
// All sockets live under ${runtimeDir}/sockets (mode 0700). The mode is
// re-asserted on every call to guard against a pre-existing directory with
// looser permissions. When the natural path would exceed the platform's
// sun_path limit, the name is hashed into the same private directory — never
// into /tmp or any world-writable location. If even the hashed path would
// exceed sun_path, an error is returned; the operator must configure a shorter
// runtimeDir (production deployments typically use /var/run/cfgms or similar).
func makeSocketPath(runtimeDir, moduleName string, id int64) (string, error) {
	sockDir := filepath.Join(runtimeDir, socketsSubdir)
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		return "", fmt.Errorf("create module socket dir %q: %w", sockDir, err)
	}
	// Re-assert mode in case the directory already existed with looser permissions.
	if err := os.Chmod(sockDir, 0o700); err != nil { // #nosec G302 -- 0700 on a directory is intentional hardening; execute bit is required for traversal
		return "", fmt.Errorf("chmod module socket dir %q: %w", sockDir, err)
	}

	name := fmt.Sprintf("cfgms-module-%s-%d.sock", sanitizeName(moduleName), id)
	natural := filepath.Join(sockDir, name)
	if len(natural) <= unixSocketPathMax {
		return natural, nil
	}

	// Hash the natural path (including sockDir and id) to retain uniqueness
	// across runtime instances. 12 hex chars give 48 bits of entropy — ample
	// for collision avoidance within a host. The hash stays in the private
	// directory so socket permissions remain the access control boundary.
	sum := sha256.Sum256([]byte(natural))
	hash := hex.EncodeToString(sum[:6])
	hashed := filepath.Join(sockDir, fmt.Sprintf("cfgms-%s.sock", hash))
	if len(hashed) <= unixSocketPathMax {
		return hashed, nil
	}

	return "", fmt.Errorf(
		"module socket path %q (%d bytes) exceeds sun_path limit (%d); "+
			"configure a shorter runtimeDir (e.g. /var/run/cfgms)",
		hashed, len(hashed), unixSocketPathMax,
	)
}

// waitForSocket polls the Unix socket at socketPath until it accepts a
// connection or ctx is cancelled.
func waitForSocket(ctx context.Context, socketPath string) error {
	for {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("socket %q not ready: %w", socketPath, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dialGRPCSocket creates a gRPC client connection over the Unix socket at socketPath.
func dialGRPCSocket(socketPath string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}
