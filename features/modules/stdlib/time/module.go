// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package timemodule implements the CFGMS stdlib time module.
//
// The package name is timemodule (not time) to avoid shadowing Go's standard
// library time package, which this module also imports for duration handling.
//
// The module manages host timezone and NTP/time-sync configuration via the
// platform executor. The resource ID is system-scoped (one time configuration
// per host); any non-empty resource ID is accepted and refers to the single
// system-wide configuration.
package timemodule

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ianaTimezonePattern matches valid IANA timezone identifiers.
// Accepted: "UTC", "America/Chicago", "Etc/GMT+5", "Pacific/Auckland".
// Rejected: empty strings, strings with newlines or control characters,
// strings starting with '-' (which could be mistaken for command flags).
var ianaTimezonePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-/]*$`)

// ntpServerPattern matches valid NTP server hostnames or IPv4/IPv6 addresses.
// Accepts dotted names, hostnames, and numeric addresses. Rejects leading '-',
// newlines, spaces, and other shell-special characters.
var ntpServerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-\[\]]*$`)

// TimeConfig represents the desired or observed time configuration of the host.
type TimeConfig struct {
	// Timezone is the IANA timezone identifier (e.g. "UTC", "America/Chicago").
	Timezone string `yaml:"timezone"`
	// NTPServers is the list of NTP server hostnames or IP addresses.
	// Returned sorted alphabetically by Get for determinism (ADR-016 clause 4).
	NTPServers []string `yaml:"ntp_servers"`
	// NTPSyncEnabled indicates whether automatic NTP synchronisation is enabled.
	NTPSyncEnabled bool `yaml:"ntp_sync_enabled"`
}

// AsMap returns the configuration as a map for field-by-field comparison.
// NTPServers is sorted to ensure deterministic output (ADR-016 clause 4).
func (c *TimeConfig) AsMap() map[string]interface{} {
	servers := make([]string, len(c.NTPServers))
	copy(servers, c.NTPServers)
	sort.Strings(servers)
	return map[string]interface{}{
		"timezone":         c.Timezone,
		"ntp_servers":      servers,
		"ntp_sync_enabled": c.NTPSyncEnabled,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *TimeConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *TimeConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate checks that the configuration is valid before applying it.
func (c *TimeConfig) Validate() error {
	if c.Timezone == "" {
		return fmt.Errorf("%w: timezone is required (IANA identifier, e.g. \"UTC\" or \"America/Chicago\")", modules.ErrInvalidInput)
	}
	if !ianaTimezonePattern.MatchString(c.Timezone) {
		return fmt.Errorf("%w: timezone %q is not a valid IANA identifier", modules.ErrInvalidInput, c.Timezone)
	}
	for _, srv := range c.NTPServers {
		if strings.ContainsAny(srv, "\n\r\t") || !ntpServerPattern.MatchString(srv) {
			return fmt.Errorf("%w: NTP server %q contains invalid characters", modules.ErrInvalidInput, srv)
		}
	}
	return nil
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *TimeConfig) GetManagedFields() []string {
	return []string{"timezone", "ntp_servers", "ntp_sync_enabled"}
}

// timeModule implements modules.Module for host time configuration.
type timeModule struct {
	modules.DefaultLoggingSupport
	executor timeExecutor
}

// New returns a new time module instance.
func New() modules.Module {
	return &timeModule{
		executor: newExecutor(),
	}
}

// Get returns the current time configuration of the host.
// The resource ID is system-scoped; any non-empty value refers to the single
// host-wide time configuration.
func (m *timeModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	logger := m.GetEffectiveLogger(logging.ForModule("time"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Getting time configuration",
		"operation", "time_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "time")

	state, err := m.executor.getState()
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to get time configuration",
			"operation", "time_get",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "TIME_GET_FAILED",
			"error_details", logging.SanitizeLogValue(err.Error()))
		return nil, err
	}

	servers := make([]string, len(state.NTPServers))
	copy(servers, state.NTPServers)
	sort.Strings(servers)

	config := &TimeConfig{
		Timezone:       state.Timezone,
		NTPServers:     servers,
		NTPSyncEnabled: state.NTPSyncEnabled,
	}

	logger.InfoCtx(ctx, "Time configuration retrieved",
		"operation", "time_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"timezone", logging.SanitizeLogValue(state.Timezone),
		"ntp_server_count", len(servers),
		"ntp_sync_enabled", state.NTPSyncEnabled,
		"status", "completed")

	return config, nil
}

// Set applies the desired time configuration to the host.
// The resource ID is system-scoped; any non-empty value refers to the single
// host-wide time configuration.
func (m *timeModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if config == nil {
		return fmt.Errorf("%w: config must not be nil", modules.ErrInvalidInput)
	}

	tc, ok := config.(*TimeConfig)
	if !ok {
		return fmt.Errorf("%w: expected *TimeConfig, got %T", modules.ErrInvalidInput, config)
	}

	if err := tc.Validate(); err != nil {
		return err
	}

	logger := m.GetEffectiveLogger(logging.ForModule("time"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Setting time configuration",
		"operation", "time_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"timezone", logging.SanitizeLogValue(tc.Timezone),
		"ntp_server_count", len(tc.NTPServers),
		"ntp_sync_enabled", tc.NTPSyncEnabled,
		"resource_type", "time")

	servers := make([]string, len(tc.NTPServers))
	copy(servers, tc.NTPServers)
	sort.Strings(servers)

	desired := timeState{
		Timezone:       tc.Timezone,
		NTPServers:     servers,
		NTPSyncEnabled: tc.NTPSyncEnabled,
	}

	if err := m.executor.setState(desired); err != nil {
		logger.ErrorCtx(ctx, "Failed to set time configuration",
			"operation", "time_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "TIME_SET_FAILED",
			"error_details", logging.SanitizeLogValue(err.Error()))
		return err
	}

	logger.InfoCtx(ctx, "Time configuration applied",
		"operation", "time_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"timezone", logging.SanitizeLogValue(tc.Timezone),
		"status", "completed")

	return nil
}
