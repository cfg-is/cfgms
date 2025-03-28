package controller

import "errors"

var (
	// ErrModuleExists is returned when attempting to register a module with a name that's already in use
	ErrModuleExists = errors.New("module already exists")

	// ErrModuleNotFound is returned when attempting to access a non-existent module
	ErrModuleNotFound = errors.New("module not found")
) 