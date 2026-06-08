// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// StageBinary copies sourceExe into <Root>/versions/<version>/<StewardBinaryName>
// and updates current.txt to point at it. Returns the path the new binary
// landed at.
//
// Atomic-ish: the binary lands at a sibling temp file first, then is
// renamed into place. current.txt update is its own atomic write.
//
// This is the only WRITE the swap surface exposes — the launcher does
// NOT delete the previous-version directory. Retention is a separate
// concern (epic #1917 Story D).
func (l Layout) StageBinary(version, sourceExe string) (string, error) {
	if err := validateVersion(version); err != nil {
		return "", err
	}

	dst, err := l.StewardExeFor(version)
	if err != nil {
		return "", fmt.Errorf("launcher: resolve destination for %q: %w", version, err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("launcher: create version dir: %w", err)
	}

	if err := copyFile(sourceExe, dst); err != nil {
		return "", fmt.Errorf("launcher: copy steward exe into version dir: %w", err)
	}

	if err := l.WriteCurrent(version); err != nil {
		return "", fmt.Errorf("launcher: update current.txt: %w", err)
	}

	return dst, nil
}

// copyFile copies src → dst via a sibling tmp file + rename so the
// destination either exists with the full content or doesn't exist at all.
// Preserves 0o755 mode bits on Unix; Windows ignores mode here.
func copyFile(src, dst string) error {
	in, err := os.Open(src) //#nosec G304 -- src is supplied by the operator on the CLI
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //#nosec G302 -- service binary must be executable
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
