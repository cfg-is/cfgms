// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
)

// secureCredentialsDir creates the credentials directory at mode 0700 (private
// to the user) if it does not exist.
func secureCredentialsDir(dir string) error {
	// #nosec G301 G703 - 0700: traversable but private to the user; dir is
	// derived only from the user's own config directory (os.UserConfigDir),
	// never from request or remote input.
	return os.MkdirAll(filepath.Clean(dir), 0700)
}

// secureCredentialFile is a no-op here: Store writes the file at mode 0600.
func secureCredentialFile(string) error {
	return nil
}
