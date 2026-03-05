// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import "errors"

var (
	// ErrNilConfig is returned when attempting to create a server with a nil config
	ErrNilConfig = errors.New("nil configuration provided")

	// ErrNotInitialized is returned when the controller has not been initialized.
	// Run `controller --init --config <path>` to perform first-run initialization.
	ErrNotInitialized = errors.New("controller not initialized: run 'controller --init --config <path>' to perform first-run initialization before starting the controller")
)
