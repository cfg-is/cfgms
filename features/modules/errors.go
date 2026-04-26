// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package modules

import "errors"

var (
	// ErrInvalidResourceID is returned when a resource ID is invalid
	ErrInvalidResourceID = errors.New("invalid resource ID")
	// ErrInvalidInput is returned when input parameters are invalid
	ErrInvalidInput = errors.New("invalid input")
	// ErrUnsupportedPlatform is returned when a feature is not supported on the current platform
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	// ErrModuleNotReady is returned by Get() when a module requires configuration via Set()
	// before it can read current state. The execution engine treats this as "current state
	// unknown" and proceeds directly to Set() to apply the desired state.
	ErrModuleNotReady = errors.New("module not ready: call Set() first to configure this module")
)
