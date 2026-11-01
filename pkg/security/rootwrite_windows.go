// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import "os"

// openLeafForWrite opens rel for writing inside root without truncating. Every
// component is resolved inside root. Root.OpenFile resolves a reparse point at the
// leaf when its target stays inside root, so the caller must verify the handle
// against a Lstat taken after the open before it truncates or writes; without
// O_TRUNC nothing is changed in a file reached through a swapped leaf.
func openLeafForWrite(root *os.Root, rel string, perm os.FileMode) (*os.File, error) {
	return root.OpenFile(rel, os.O_WRONLY|os.O_CREATE, perm)
}
