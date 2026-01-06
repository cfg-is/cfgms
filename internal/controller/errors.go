// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package controller

import "errors"

var (
	// ErrModuleExists is returned when attempting to register a module with a name that's already in use
	ErrModuleExists = errors.New("module already exists")

	// ErrModuleNotFound is returned when attempting to access a non-existent module
	ErrModuleNotFound = errors.New("module not found")
)
