// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package service provides idempotent Get/Set management of OS services for
// the CFGMS steward. It supports Linux (systemd), Windows (SCM), and macOS
// (launchd) through platform-specific executor implementations selected at
// compile time via build tags.
//
// The module follows the Get→Compare→Set→Verify convergence model used by all
// steward modules. Get reports the current service state (running/stopped,
// enabled/disabled). The steward framework compares that to the desired state
// declared in the resource configuration. If drift is detected, Set is called
// to converge to the desired state.
package service

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// serviceNamePattern restricts service names to characters that are safe to
// pass as arguments to systemctl, sc.exe, and launchctl without shell quoting.
// Allows alphanumeric characters, dots, hyphens, underscores, and @ (needed
// for systemd template units like getty@tty1.service).
// The name must start with an alphanumeric character to prevent flag injection.
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,254}$`)

// validateServiceName rejects names that could cause argument injection when
// passed to OS service management commands.
func validateServiceName(name string) error {
	if !serviceNamePattern.MatchString(name) {
		return fmt.Errorf("%w: service name %q contains invalid characters (allowed: alphanumeric, '.', '_', '-', '@')", modules.ErrInvalidInput, name)
	}
	return nil
}

// serviceModule implements modules.Module for OS service management.
type serviceModule struct {
	modules.DefaultLoggingSupport
	executor serviceExecutor
}

// New creates a new instance of the service module with the platform-appropriate
// OS service executor.
func New() modules.Module {
	return &serviceModule{
		executor: newExecutor(),
	}
}

// Get returns the current state of the named OS service.
//
// The resourceID is the OS-level service name (e.g., "cfgms-controller" on
// Linux, "CFGMSController" on Windows, "com.cfgms.controller" on macOS).
//
// If the service does not exist on the system, Get returns a ServiceConfig
// with State: "stopped" and Enabled: false — analogous to how the file module
// returns State: "absent" for non-existent files.
func (m *serviceModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}
	if err := validateServiceName(resourceID); err != nil {
		return nil, err
	}

	logger := m.GetEffectiveLogger(logging.ForModule("service"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Getting service state",
		"operation", "service_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "service")

	state, err := m.executor.getState(resourceID)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to get service state",
			"operation", "service_get",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "SERVICE_GET_FAILED",
			"error_details", err.Error())
		return nil, err
	}

	serviceState := "stopped"
	if state.Running {
		serviceState = "running"
	}

	config := &ServiceConfig{
		State:   serviceState,
		Enabled: state.Enabled,
	}

	logger.InfoCtx(ctx, "Service state retrieved",
		"operation", "service_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"state", serviceState,
		"enabled", state.Enabled,
		"status", "completed")

	return config, nil
}

// Set applies the desired service configuration.
//
// The resourceID is the OS-level service name. The config must be a ServiceConfig
// (or any ConfigState whose AsMap contains "state" and "enabled" keys).
//
// Set is idempotent: calling it when the service is already in the desired state
// performs no observable change. The convergence loop relies on this property.
func (m *serviceModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if err := validateServiceName(resourceID); err != nil {
		return err
	}
	if config == nil {
		return modules.ErrInvalidInput
	}

	logger := m.GetEffectiveLogger(logging.ForModule("service"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Setting service state",
		"operation", "service_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "service")

	configMap := config.AsMap()
	svcConfig := &ServiceConfig{}

	if state, ok := configMap["state"].(string); ok {
		svcConfig.State = state
	}
	if enabled, ok := configMap["enabled"].(bool); ok {
		svcConfig.Enabled = enabled
	}

	if err := svcConfig.Validate(); err != nil {
		logger.ErrorCtx(ctx, "Service configuration validation failed",
			"operation", "service_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	desiredRunning := svcConfig.State == "running"

	if err := m.executor.setState(resourceID, desiredRunning, svcConfig.Enabled); err != nil {
		logger.ErrorCtx(ctx, "Failed to set service state",
			"operation", "service_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "SERVICE_SET_FAILED",
			"error_details", err.Error())
		return fmt.Errorf("service %s: %w", logging.SanitizeLogValue(resourceID), err)
	}

	logger.InfoCtx(ctx, "Service configuration completed successfully",
		"operation", "service_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"state", svcConfig.State,
		"enabled", svcConfig.Enabled,
		"status", "completed")

	return nil
}
