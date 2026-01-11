// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import "errors"

var (
	// ErrNilConfig is returned when attempting to create a server with a nil config
	ErrNilConfig = errors.New("nil configuration provided")
)
