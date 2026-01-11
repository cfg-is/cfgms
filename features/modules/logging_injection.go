// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package modules defines interfaces for dependency injection into CFGMS modules.
//
// This package implements a secure interface-based logging injection pattern that
// preserves module binary signatures while enabling centralized logging control.
// The pattern allows the steward to inject logger implementations at runtime
// without modifying module source code or binary hashes.
package modules

import (
	"github.com/cfgis/cfgms/pkg/logging"
)

// LoggingInjectable defines the interface that modules can optionally implement
// to receive logger injection from the steward at runtime.
//
// This interface is designed to preserve code signing and application allowlisting:
// - Modules maintain their original constructors and binary signatures
// - The steward can inject loggers after module creation through this interface
// - If a module doesn't implement this interface, it uses its default logging behavior
// - No changes to existing module APIs or constructors are required
//
// Security characteristics:
// - Interface-based injection (standard Go pattern, not process injection)
// - Voluntary opt-in by modules (modules must implement the interface)
// - No executable code modification (preserves binary signatures)
// - Centralized logging control while maintaining module autonomy
type LoggingInjectable interface {
	// SetLogger injects a logger implementation into the module.
	// This method will be called by the steward after module creation
	// if the module implements this interface.
	//
	// Parameters:
	//   logger: The logger implementation to use for this module
	//
	// Returns:
	//   error: If the logger injection fails for any reason
	//
	// Implementation guidelines:
	// - Store the logger for use in Get/Set operations
	// - Replace any existing logger if already set
	// - Validate that the logger is not nil
	// - Return error if injection is not supported or fails
	SetLogger(logger logging.Logger) error

	// GetLogger returns the currently injected logger, if any.
	// This method allows the steward to verify successful injection
	// and enables debugging of the logging configuration.
	//
	// Returns:
	//   logger: The currently injected logger, or nil if none set
	//   injected: True if a logger was successfully injected, false otherwise
	//
	// Implementation guidelines:
	// - Return nil, false if no logger has been injected
	// - Return the injected logger and true if injection succeeded
	// - This method should be safe to call concurrently
	GetLogger() (logger logging.Logger, injected bool)
}

// LoggerProvider defines the interface for creating context-aware loggers
// that can be injected into modules. This interface abstracts the logger
// creation process and enables different logging strategies.
type LoggerProvider interface {
	// ForModule creates a logger specifically configured for a module.
	// This logger should include module-specific context and configuration.
	//
	// Parameters:
	//   moduleName: The name of the module (e.g., "script", "file", "directory")
	//   stewardID: The ID of the steward that owns this module instance
	//
	// Returns:
	//   logger: A configured logger for the module
	//   error: If logger creation fails
	ForModule(moduleName, stewardID string) (logging.Logger, error)

	// ForComponent creates a logger for a specific component within a module.
	// This allows fine-grained logging control within complex modules.
	//
	// Parameters:
	//   moduleName: The name of the module
	//   componentName: The name of the component within the module
	//   stewardID: The ID of the steward that owns this module instance
	//
	// Returns:
	//   logger: A configured logger for the component
	//   error: If logger creation fails
	ForComponent(moduleName, componentName, stewardID string) (logging.Logger, error)
}

// CentralLoggingManager defines the interface for managing centralized logging
// across all modules in a steward. This interface is implemented by the steward
// to provide centralized logging control and monitoring.
type CentralLoggingManager interface {
	// InjectLogger attempts to inject a logger into a module if it supports injection.
	// This method checks if the module implements LoggingInjectable and injects
	// an appropriate logger if so.
	//
	// Parameters:
	//   module: The module instance to inject a logger into
	//   moduleName: The name of the module for logger configuration
	//
	// Returns:
	//   injected: True if logger injection was successful, false otherwise
	//   error: If injection was attempted but failed
	InjectLogger(module Module, moduleName string) (injected bool, err error)

	// GetModuleLogger retrieves the logger for a specific module, if injected.
	// This method allows the steward to access module loggers for monitoring
	// and debugging purposes.
	//
	// Parameters:
	//   module: The module instance to get the logger from
	//
	// Returns:
	//   logger: The injected logger, or nil if none was injected
	//   hasLogger: True if the module has an injected logger
	GetModuleLogger(module Module) (logger logging.Logger, hasLogger bool)

	// ListModulesWithLoggers returns information about all modules that have
	// received logger injection. This enables monitoring and debugging of
	// the centralized logging system.
	//
	// Returns:
	//   modules: Map of module names to their injection status
	ListModulesWithLoggers() map[string]LoggerInjectionStatus
}

// LoggerInjectionStatus provides information about the logger injection
// status for a specific module instance.
type LoggerInjectionStatus struct {
	ModuleName     string `json:"module_name"`     // Name of the module
	StewardID      string `json:"steward_id"`      // ID of the owning steward
	Injected       bool   `json:"injected"`        // Whether injection succeeded
	SupportsInject bool   `json:"supports_inject"` // Whether module supports injection
	LoggerType     string `json:"logger_type"`     // Type of injected logger
	LastInjected   int64  `json:"last_injected"`   // Unix timestamp of last injection
	ErrorMessage   string `json:"error_message"`   // Last injection error, if any
}

// ModuleWithLogging is a convenience interface that combines the Module interface
// with LoggingInjectable. Modules can implement this interface to clearly indicate
// they support both module functionality and logger injection.
type ModuleWithLogging interface {
	Module
	LoggingInjectable
}

// Default implementation helpers for modules that want to support logging injection
// without implementing the full interface themselves.

// DefaultLoggingSupport provides a default implementation of LoggingInjectable
// that modules can embed to gain logging injection support.
type DefaultLoggingSupport struct {
	injectedLogger logging.Logger
}

// SetLogger implements LoggingInjectable.SetLogger with a default implementation.
func (d *DefaultLoggingSupport) SetLogger(logger logging.Logger) error {
	if logger == nil {
		return ErrInvalidInput
	}
	d.injectedLogger = logger
	return nil
}

// GetLogger implements LoggingInjectable.GetLogger with a default implementation.
func (d *DefaultLoggingSupport) GetLogger() (logging.Logger, bool) {
	if d.injectedLogger == nil {
		return nil, false
	}
	return d.injectedLogger, true
}

// GetEffectiveLogger returns either the injected logger or a fallback logger.
// This helper method enables modules to always have a logger available.
func (d *DefaultLoggingSupport) GetEffectiveLogger(fallback logging.Logger) logging.Logger {
	if d.injectedLogger != nil {
		return d.injectedLogger
	}
	return fallback
}

// HasInjectedLogger returns true if a logger has been successfully injected.
func (d *DefaultLoggingSupport) HasInjectedLogger() bool {
	return d.injectedLogger != nil
}
