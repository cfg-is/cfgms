// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build windows

package scriptrelay

import (
	"fmt"

	winio "github.com/Microsoft/go-winio"
)

// initSocket creates a Windows named pipe for the execution with a DACL that
// grants access only to the owner (OW). The default named-pipe DACL is too
// broad; the explicit descriptor prevents other local users from connecting.
func initSocket(r *Relay) error {
	pipeName := `\\.\pipe\cfgms-` + r.executionID

	// DACL: protected, allow generic-all to object owner only.
	ln, err := winio.ListenPipe(pipeName, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;OW)",
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	})
	if err != nil {
		return fmt.Errorf("listen named pipe: %w", err)
	}

	r.socketPath = pipeName
	r.ln = ln
	return nil
}

// cleanupSocket closes the named pipe listener (already closed by Stop).
// Windows named pipes are automatically removed when the last handle is closed.
func cleanupSocket(_ *Relay) {}
