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

// makeSocketPath returns the Unix domain socket path for a module instance.
// Format: ${runtimeDir}/cfgms-module-${name}-${id}.sock
//
// If the natural path would exceed the platform's sun_path limit, it falls
// back to a short hashed path under /tmp. This handles long temp dirs on
// macOS (/var/folders/xx/yyy/T/...), where t.TempDir() in tests produces
// paths that exceed the 104-byte sun_path limit.
//
// TODO(production-wiring): when ModuleRuntime is wired into the steward boot
// path, ensure the configured runtimeDir is short enough that the fallback is
// never reached on macOS — or replace this fallback with a steward-owned,
// mode-0700 subdirectory so /tmp predictability cannot be exploited locally.
func makeSocketPath(runtimeDir, moduleName string, id int64) string {
	name := fmt.Sprintf("cfgms-module-%s-%d.sock", sanitizeName(moduleName), id)
	natural := filepath.Join(runtimeDir, name)
	if len(natural) <= unixSocketPathMax {
		return natural
	}
	// Hash the natural path (including runtimeDir and id) to retain uniqueness
	// across runtime instances. 12 hex chars gives 48 bits of entropy — ample
	// for collision avoidance within a host.
	sum := sha256.Sum256([]byte(natural))
	hash := hex.EncodeToString(sum[:6])
	return filepath.Join("/tmp", fmt.Sprintf("cfgms-%s.sock", hash))
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
