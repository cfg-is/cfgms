// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package script

import (
	"os/exec"

	"github.com/cfgis/cfgms/pkg/logging"
)

// processTree on non-Windows platforms preserves the pre-#2715 behavior:
// terminate kills the top-level process only. Issue #2715 (a detached grandchild
// inheriting the stdout/stderr pipe and blocking cmd.Wait forever after a
// top-level kill) is Windows-specific — the Unix executor path is not known to
// exhibit it — so this is intentionally a thin wrapper that does not change Unix
// process semantics. If evidence of the same leak surfaces on Unix, the fix is a
// process group (Setpgid + kill(-pgid)) added here, isolated from Windows.
type processTree struct {
	logger logging.Logger
}

// newProcessTree returns a process-tree tracker. It holds no OS resources.
func newProcessTree(logger logging.Logger) *processTree {
	return &processTree{logger: logger}
}

// prepare is a no-op on non-Windows platforms.
func (p *processTree) prepare() {}

// track is a no-op on non-Windows platforms.
func (p *processTree) track(_ *exec.Cmd) {}

// terminate kills the top-level process (unchanged pre-#2715 Unix behavior).
func (p *processTree) terminate(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			p.logger.Warn("process-tree: failed to kill script process", "error", err)
		}
	}
}

// close is a no-op on non-Windows platforms.
func (p *processTree) close() {}
