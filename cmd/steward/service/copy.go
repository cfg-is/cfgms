// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
	"io"
	"os"
)

// copyBinary copies src to dst atomically using a temp file.
// The destination is created with 0755 permissions (owner rwx, group/other rx).
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, dst)
}
