package module

import "errors"

var (
	// ErrModuleUnhealthy indicates the module is in an unhealthy state
	ErrModuleUnhealthy = errors.New("module is unhealthy")

	// ErrModuleNotInitialized indicates an attempt to use an uninitialized module
	ErrModuleNotInitialized = errors.New("module not initialized")

	// ErrModuleAlreadyRunning indicates an attempt to start an already running module
	ErrModuleAlreadyRunning = errors.New("module already running")

	// ErrInvalidConfig indicates the module configuration is invalid
	ErrInvalidConfig = errors.New("invalid module configuration")
)
