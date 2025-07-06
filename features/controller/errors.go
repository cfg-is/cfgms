package controller

import "errors"

var (
	// ErrModuleExists is returned when attempting to register a module with a name that's already in use
	ErrModuleExists = errors.New("module already exists")

	// ErrModuleNotFound is returned when attempting to access a non-existent module
	ErrModuleNotFound = errors.New("module not found")

	// ErrAlreadyRunning is returned when attempting to start an already running controller
	ErrAlreadyRunning = errors.New("controller already running")

	// ErrNotRunning is returned when attempting to stop a controller that's not running
	ErrNotRunning = errors.New("controller not running")
) 