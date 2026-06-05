// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// makeSocketPath returns the Unix domain socket path for a module instance.
// Format: ${runtimeDir}/cfgms-module-${name}-${id}.sock
func makeSocketPath(runtimeDir, moduleName string, id int64) string {
	return filepath.Join(runtimeDir, fmt.Sprintf("cfgms-module-%s-%d.sock", sanitizeName(moduleName), id))
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
