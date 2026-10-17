// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import "errors"

// ReadTokenFile is not available on Windows yet. The Windows service still
// passes --regtoken; a later change replaces this with an ACL-checked read.
func ReadTokenFile(path string) (string, error) {
	return "", errors.New("--regtoken-file is not available on Windows yet: use --regtoken")
}
