// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package user provides idempotent Get/Set management of local OS user accounts
// for the CFGMS steward. It supports Linux (useradd/usermod), Windows (net.exe),
// and macOS (dscl) through platform-specific executor implementations selected at
// compile time via build tags.
//
// The module manages account existence, full name, group membership, and lock/disable
// state. Password setting is intentionally out of scope: the module observes whether
// an account has a password (password_set, returned by Get) but never accepts,
// stores, or transmits password material.
//
// The module follows the Get→Compare→Set→Verify convergence model used by all
// steward modules. Get reports observed account state. The steward framework
// compares that to the desired state declared in the resource configuration.
// If drift is detected, Set is called to converge to the desired state.
package user

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// usernamePattern restricts usernames to characters that are safe to pass as
// arguments to useradd, usermod, net.exe, and dscl without shell quoting or
// injection risk. Allows alphanumeric, underscore, hyphen, and dot.
// Must start with a letter or underscore to prevent flag injection.
var usernamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)

// groupNamePattern restricts group names using the same safe character set.
var groupNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)

// validateUsername rejects names that could cause argument injection when
// passed to OS user-management commands.
func validateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("%w: username %q is invalid (allowed: alphanumeric, '_', '-', '.')", modules.ErrInvalidInput, username)
	}
	return nil
}

// validateGroupName rejects group names that could cause argument injection.
func validateGroupName(group string) error {
	if !groupNamePattern.MatchString(group) {
		return fmt.Errorf("%w: group name %q is invalid (allowed: alphanumeric, '_', '-', '.')", modules.ErrInvalidInput, group)
	}
	return nil
}

// validateFullName rejects full-name strings that contain control characters
// (newlines, carriage returns, NUL) or colons. These characters are harmless
// under exec.Command (no shell is involved) but could corrupt GECOS-format
// fields in /etc/passwd and are defense-in-depth consistent with the
// username/group validation posture. An empty full name is always valid.
func validateFullName(fullName string) error {
	for _, r := range fullName {
		if r == '\n' || r == '\r' || r == 0 || r == ':' {
			return fmt.Errorf("%w: full_name contains disallowed character %q (control chars and ':' are not permitted)", modules.ErrInvalidInput, r)
		}
	}
	return nil
}

// userModule implements modules.Module for local user account management.
type userModule struct {
	modules.DefaultLoggingSupport
	executor userExecutor
}

// New creates a new instance of the user module with the platform-appropriate
// OS user-management executor.
func New() modules.Module {
	return &userModule{
		executor: newExecutor(),
	}
}

// Get returns the current state of the named local user account.
//
// The resourceID is the OS-level username (e.g., "alice", "SYSTEM").
//
// If the user does not exist on the system, Get returns a UserConfig with
// State: "absent" — analogous to how the file module returns State: "absent"
// for non-existent files.
//
// The returned UserConfig.PasswordSet is an observed value only; Set() never
// accepts or modifies it.
func (m *userModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}
	if err := validateUsername(resourceID); err != nil {
		return nil, err
	}

	logger := m.GetEffectiveLogger(logging.ForModule("user"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Getting user state",
		"operation", "user_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "user")

	state, err := m.executor.getState(resourceID)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to get user state",
			"operation", "user_get",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "USER_GET_FAILED",
			"error_details", err.Error())
		return nil, err
	}

	accountState := "absent"
	if state.Exists {
		accountState = "present"
	}

	groups := make([]string, len(state.Groups))
	copy(groups, state.Groups)
	sort.Strings(groups)

	config := &UserConfig{
		State:       accountState,
		FullName:    state.FullName,
		Groups:      groups,
		Locked:      state.Locked,
		PasswordSet: state.PasswordSet,
	}

	logger.InfoCtx(ctx, "User state retrieved",
		"operation", "user_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"state", accountState,
		"locked", state.Locked,
		"status", "completed")

	return config, nil
}

// Set applies the desired user account configuration.
//
// The resourceID is the OS-level username. The config must be a UserConfig (or
// any ConfigState whose AsMap contains "state", "full_name", "groups", and
// "locked" keys).
//
// Set is idempotent: calling it when the account is already in the desired state
// performs no observable change. The convergence loop relies on this property.
//
// password_set in the config is silently ignored — this module never accepts,
// stores, or transmits password material.
func (m *userModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if err := validateUsername(resourceID); err != nil {
		return err
	}
	if config == nil {
		return modules.ErrInvalidInput
	}

	logger := m.GetEffectiveLogger(logging.ForModule("user"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Setting user state",
		"operation", "user_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "user")

	userCfg, ok := config.(*UserConfig)
	if !ok {
		return fmt.Errorf("%w: unsupported config type %T (expected *UserConfig)", modules.ErrInvalidInput, config)
	}
	// PasswordSet is not written to desired state — it is an observed-only field.

	if err := userCfg.Validate(); err != nil {
		logger.ErrorCtx(ctx, "User configuration validation failed",
			"operation", "user_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "CONFIG_VALIDATION_FAILED",
			"error_details", err.Error())
		return err
	}

	if err := validateFullName(userCfg.FullName); err != nil {
		return err
	}

	for _, g := range userCfg.Groups {
		if err := validateGroupName(g); err != nil {
			return err
		}
	}

	desired := userState{
		Exists:   userCfg.State == "present",
		FullName: userCfg.FullName,
		Groups:   userCfg.Groups,
		Locked:   userCfg.Locked,
		// PasswordSet is never set in desired state
	}

	if err := m.executor.setState(resourceID, desired); err != nil {
		logger.ErrorCtx(ctx, "Failed to set user state",
			"operation", "user_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "USER_SET_FAILED",
			"error_details", err.Error())
		return fmt.Errorf("user %s: %w", logging.SanitizeLogValue(resourceID), err)
	}

	logger.InfoCtx(ctx, "User configuration completed successfully",
		"operation", "user_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"state", userCfg.State,
		"locked", userCfg.Locked,
		"status", "completed")

	return nil
}
