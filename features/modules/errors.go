// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package modules

import "errors"

var (
	// ErrInvalidResourceID is returned when a resource ID is invalid
	ErrInvalidResourceID = errors.New("invalid resource ID")
	// ErrInvalidInput is returned when input parameters are invalid
	ErrInvalidInput = errors.New("invalid input")
	// ErrUnsupportedPlatform is returned when a feature is not supported on the current platform
	ErrUnsupportedPlatform = errors.New("unsupported platform")
)
