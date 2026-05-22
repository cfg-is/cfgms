// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build !windows

package scriptrelay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// initSocket creates the per-execution directory (mode 0700) and opens a
// unix socket inside it (mode 0600). The directory is created first so no
// window exists between bind and chmod where the socket is world-accessible.
func initSocket(r *Relay) error {
	sockDir := filepath.Join(os.TempDir(), "cfgms-"+r.executionID)
	if err := os.Mkdir(sockDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create socket dir: %w", err)
	}

	sockPath := filepath.Join(sockDir, "api.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("listen unix socket: %w", err)
	}

	// Enforce 0600 on the socket file; the 0700 directory prevents access
	// during the brief window before chmod.
	if err := os.Chmod(sockPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(sockDir)
		return fmt.Errorf("chmod socket: %w", err)
	}

	r.socketPath = sockPath
	r.ln = ln
	return nil
}

// cleanupSocket removes the per-execution socket directory and its contents.
func cleanupSocket(r *Relay) {
	if r.socketPath == "" {
		return
	}
	sockDir := filepath.Dir(r.socketPath)
	_ = os.RemoveAll(sockDir)
}
