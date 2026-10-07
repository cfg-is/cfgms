// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"fmt"
	"io"
	"os"
)

// copyBinary copies src to dst atomically using a temp file.
// 0750: owner rwx (service binary), group rx (service group), no world access.
// #nosec G302 -- binary requires execute permission; root-owned install, no world access
func copyBinary(src, dst string) error {
	// #nosec G304 -- src is the installer-selected controller artifact; reading
	// and copying that explicit local path is this privileged helper's purpose.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp := dst + ".tmp"
	// #nosec G302,G304 -- tmp is derived from the validated service destination;
	// 0750 is required for the root-owned binary and its service group.
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0750)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy failed: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close failed: %w", err)
	}

	return os.Rename(tmp, dst)
}
