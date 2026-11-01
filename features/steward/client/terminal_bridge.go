// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"fmt"
	"sync"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/features/terminal/shell"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TerminalBridge dials the controller's Terminal RPC and bridges the bidirectional
// stream to a local PTY for the lifetime of an interactive admin session (Issue #2760).
// Implements commands.TerminalDialer; a single bridge handles one session.
type TerminalBridge struct {
	client  transportpb.StewardTransportClient
	logger  logging.Logger
	factory *shell.Factory

	mu             sync.Mutex
	activeExecutor shell.Executor
}

// Compile-time check: TerminalBridge implements commands.TerminalDialer.
var _ commands.TerminalDialer = (*TerminalBridge)(nil)

// terminalDialer is the commands.TerminalDialer registered in setupCommandHandler.
// It resolves the gRPC transport client lazily at Dial() time and constructs a
// fresh TerminalBridge per session, so the open_terminal handler can be
// registered unconditionally without depending on the transport client being
// available at setup time (Issue #2760).
type terminalDialer struct {
	c *TransportClient
}

// Compile-time check: terminalDialer implements commands.TerminalDialer.
var _ commands.TerminalDialer = (*terminalDialer)(nil)

// Dial resolves the current gRPC transport client and bridges a Terminal session.
// It returns a descriptive error when no gRPC transport client is available so the
// failure is surfaced as a session-level error rather than a missing handler.
func (d *terminalDialer) Dial(ctx context.Context, sessionID, shellStr string, cols, rows int) error {
	d.c.mu.RLock()
	cp := d.c.controlPlane
	d.c.mu.RUnlock()

	grpcProv, ok := cp.(*grpcCP.Provider)
	if !ok {
		return fmt.Errorf("open_terminal: gRPC transport client unavailable (control plane is not a gRPC provider)")
	}
	tc := grpcProv.TransportClient()
	if tc == nil {
		return fmt.Errorf("open_terminal: gRPC transport client not yet established")
	}
	return NewTerminalBridge(tc, d.c.logger).Dial(ctx, sessionID, shellStr, cols, rows)
}

// NewTerminalBridge returns a TerminalBridge that uses client to open the
// Terminal RPC stream.
func NewTerminalBridge(client transportpb.StewardTransportClient, logger logging.Logger) *TerminalBridge {
	return &TerminalBridge{
		client:  client,
		logger:  logger,
		factory: shell.NewFactory(),
	}
}

// ActiveExecutor returns the shell.Executor created during Dial, or nil if Dial
// has not been called yet. Exposed for test assertions on executor lifecycle.
func (b *TerminalBridge) ActiveExecutor() shell.Executor {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.activeExecutor
}

// Dial opens the Terminal RPC stream to the controller, launches a local PTY,
// and bridges both directions until ctx is cancelled, the stream closes, or the
// PTY process exits. Blocking — callers must run it in a goroutine if they need
// to stay responsive. Returns nil for normal close (EOF / context cancel).
func (b *TerminalBridge) Dial(ctx context.Context, sessionID, shellStr string, cols, rows int) error {
	stream, err := b.client.Terminal(ctx)
	if err != nil {
		return fmt.Errorf("terminal bridge: open stream: %w", err)
	}

	exec, err := b.factory.CreateExecutor(&shell.Config{Shell: shellStr})
	if err != nil {
		return fmt.Errorf("terminal bridge: create executor: %w", err)
	}

	b.mu.Lock()
	b.activeExecutor = exec
	b.mu.Unlock()

	// execCtx is shared between the two goroutines. Cancelling it shuts down the
	// PTY and unblocks the inbound loop via stream.Recv returning an error.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := exec.Start(execCtx, &shell.Config{Shell: shellStr, Cols: cols, Rows: rows}); err != nil {
		_ = exec.Close(context.Background())
		return fmt.Errorf("terminal bridge: start executor: %w", err)
	}
	defer func() { _ = exec.Close(context.Background()) }()

	// Outbound goroutine: PTY output → controller stream.
	// Calls cancel() on exit so the inbound loop (and exec context) also terminate.
	go func() {
		defer cancel()
		for {
			select {
			case data, ok := <-exec.OutputChannel():
				if !ok {
					return
				}
				if sendErr := stream.Send(&transportpb.TerminalData{
					SessionId: sessionID,
					Data:      data,
				}); sendErr != nil {
					b.logger.Warn("terminal bridge: stream send failed", "error", sendErr)
					return
				}
			case execErr, ok := <-exec.ErrorChannel():
				if !ok {
					return
				}
				if execErr != nil {
					b.logger.Info("terminal bridge: executor exited", "error", execErr)
				}
				return
			case <-execCtx.Done():
				return
			}
		}
	}()

	// Inbound loop: controller stream → PTY.
	for {
		frame, recvErr := stream.Recv()
		if recvErr != nil {
			// EOF or context cancellation — normal session close.
			return nil
		}

		// Ignore frames belonging to a different session. The controller may
		// multiplex frames for multiple concurrent sessions over one connection.
		if frame.GetSessionId() != sessionID {
			continue
		}

		if frame.GetIsResize() {
			if resizeErr := exec.Resize(execCtx, int(frame.GetCols()), int(frame.GetRows())); resizeErr != nil {
				b.logger.Warn("terminal bridge: resize failed", "error", resizeErr)
			}
			continue
		}

		if len(frame.GetData()) > 0 {
			if writeErr := exec.WriteData(execCtx, frame.GetData()); writeErr != nil {
				b.logger.Warn("terminal bridge: write data failed", "error", writeErr)
				return writeErr
			}
		}
	}
}
