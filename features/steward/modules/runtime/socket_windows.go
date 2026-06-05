// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package runtime

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// makeSocketPath returns the named pipe path for a module instance.
// Format: \\.\pipe\cfgms-module-${name}-${id}
// runtimeDir is unused on Windows (named pipes don't use directories).
func makeSocketPath(runtimeDir, moduleName string, id int64) string {
	return fmt.Sprintf(`\\.\pipe\cfgms-module-%s-%d`, sanitizeName(moduleName), id)
}

// waitForSocket polls the named pipe at socketPath until it accepts a
// connection or ctx is cancelled.
func waitForSocket(ctx context.Context, socketPath string) error {
	for {
		conn, err := winio.DialPipeContext(ctx, socketPath)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("named pipe %q not ready: %w", socketPath, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dialGRPCSocket creates a gRPC client connection over the Windows named pipe.
func dialGRPCSocket(socketPath string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, addr)
		}),
	)
}
