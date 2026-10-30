//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package activedirectory

import (
	"context"
	"errors"
)

// unsupportedRunner is the script runner on platforms other than Windows: the
// module reads Active Directory through Windows PowerShell only.
type unsupportedRunner struct{}

func newPlatformRunner() scriptRunner { return unsupportedRunner{} }

// Run implements scriptRunner.
func (unsupportedRunner) Run(context.Context, []byte, func([]byte) error) error {
	return errors.New("activedirectory module requires Windows")
}
