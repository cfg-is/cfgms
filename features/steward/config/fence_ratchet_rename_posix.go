// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package config

import "os"

// renameFenceRatchetFile renames src to dst with POSIX rename(2) semantics:
// the rename is atomic with respect to concurrent readers, who always
// observe either the old file or the new file in full. No retry is needed.
func renameFenceRatchetFile(src, dst string) error {
	return os.Rename(src, dst)
}

// readFenceRatchetFile reads path directly. POSIX rename(2) never blocks or
// fails because of a concurrent reader, so no retry is needed.
//
// Precondition: path is a FenceRatchet.filePath() result — filepath.Join of the
// locally configured cert-store directory and the fenceRatchetFileName constant.
// The steward never accepts a fence-ratchet path from a command, a peer, or any
// other remote input, and this helper has no other caller.
func readFenceRatchetFile(path string) ([]byte, error) {
	// #nosec G304 -- path is filepath.Join(r.dir, fenceRatchetFileName): a fixed
	// filename under an operator-configured local directory, with no
	// caller-supplied or remote component. See the precondition above.
	return os.ReadFile(path)
}
