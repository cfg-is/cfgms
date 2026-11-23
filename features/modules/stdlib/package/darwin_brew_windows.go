// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package package_module

import (
	"context"
	"errors"
	"os/exec"
)

var errBrewUnsupported = errors.New("homebrew is not supported on windows")

// newBrewCmd is unavailable on Windows: Homebrew is a macOS provider and
// syscall.Credential does not exist here.
func newBrewCmd(_ context.Context, _ ...string) (*exec.Cmd, error) {
	return nil, errBrewUnsupported
}

// brewCheck always reports Homebrew as unavailable on Windows.
func brewCheck(_ context.Context) error {
	return errBrewUnsupported
}
