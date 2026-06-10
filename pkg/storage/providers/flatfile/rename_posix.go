// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package flatfile

import "os"

// atomicRename renames src → dst with POSIX rename(2) semantics: the
// rename is atomic with respect to concurrent readers, who always
// observe either the old file or the new file in full. No retry is
// needed.
func atomicRename(src, dst string) error {
	return os.Rename(src, dst)
}
