// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	versionpkg "github.com/cfgis/cfgms/pkg/version"
)

// StageOptions controls the privileged launcher swap boundary.
type StageOptions struct {
	// AllowDowngrade permits an explicitly authorized operator rollback.
	// Installers and normal upgrade paths leave this false.
	AllowDowngrade bool
}

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
	return l.StageBinaryWithOptions(version, sourceExe, StageOptions{})
}

// StageBinaryWithOptions stages a binary while enforcing monotonic semantic
// versions by default. The guard lives in the privileged launcher so an older
// installer cannot bypass the steward-side preflight check.
func (l Layout) StageBinaryWithOptions(version, sourceExe string, opts StageOptions) (string, error) {
	if err := validateVersion(version); err != nil {
		return "", err
	}

	if err := l.rejectDowngrade(version, opts.AllowDowngrade); err != nil {
		return "", err
	}

	dst, err := l.StewardExeFor(version)
	if err != nil {
		return "", fmt.Errorf("launcher: resolve destination for %q: %w", version, err)
	}

	// #nosec G301 -- the unprivileged steward service must traverse the
	// root-owned version directory to execute its staged 0755 binary.
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

func (l Layout) rejectDowngrade(candidate string, allowDowngrade bool) error {
	if allowDowngrade {
		return nil
	}
	current, err := l.ReadCurrent()
	if err != nil {
		return fmt.Errorf("launcher: read current version for downgrade check: %w", err)
	}
	if current == "" {
		return nil
	}

	currentSemantic := versionpkg.IsSemantic(current)
	candidateSemantic := versionpkg.IsSemantic(candidate)
	if !currentSemantic {
		// Legacy installations allowed opaque version identifiers. Permit one
		// migration from that state; subsequent semantic installs are guarded.
		if !candidateSemantic {
			return fmt.Errorf("launcher: downgrade rejected: legacy current version %q requires a semantic candidate, got %q", current, candidate)
		}
		return nil
	}
	if !candidateSemantic {
		return fmt.Errorf("launcher: downgrade rejected: current version %q is semantic but candidate %q is not", current, candidate)
	}
	cmp, err := versionpkg.CompareSemantic(candidate, current)
	if err != nil {
		return fmt.Errorf("launcher: compare versions for downgrade check: %w", err)
	}
	if cmp < 0 {
		return fmt.Errorf("launcher: downgrade rejected: candidate version %q is older than current version %q", candidate, current)
	}
	return nil
}

// copyFile copies src → dst via a sibling tmp file + rename so the
// destination either exists with the full content or doesn't exist at all.
// Preserves 0o755 mode bits on Unix; Windows ignores mode here.
func copyFile(src, dst string) error {
	// #nosec G304 -- src is an explicit privileged launcher CLI artifact path;
	// copying it into the managed version store is this command's purpose.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp := dst + ".tmp"
	// #nosec G302,G304 -- tmp is derived from the launcher-validated destination;
	// 0755 is required for the staged service binary to execute.
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
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
