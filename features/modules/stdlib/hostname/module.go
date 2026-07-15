// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package hostname implements the CFGMS stdlib hostname module.
//
// The module manages the host system name (computer name) and Windows workgroup
// via the platform executor. The resource ID is system-scoped (one hostname
// configuration per host); any non-empty resource ID is accepted and refers to
// the single host-wide identity.
//
// This is a declare-once identity module per ADR-016 clause 1: the desired
// hostname is set once and held, not continuously re-derived. Repeated Set
// calls with the same desired hostname are idempotent no-ops.
package hostname

import (
	"context"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// hostnamePattern matches valid hostname labels per RFC 952 / RFC 1123.
// Accepts alphanumeric labels and hyphens; rejects leading/trailing hyphens,
// empty strings, and control characters.
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$`)

// workgroupPattern matches valid Windows workgroup names (NetBIOS name rules).
// Accepts alphanumeric characters, hyphens, and underscores; max 15 characters.
var workgroupPattern = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,15}$`)

// HostnameConfig represents the desired or observed hostname configuration.
type HostnameConfig struct {
	// Hostname is the system/computer name of the host.
	Hostname string `yaml:"hostname"`
	// Workgroup is the Windows workgroup name. Omitted on Linux and macOS.
	Workgroup string `yaml:"workgroup,omitempty"`
}

// AsMap returns the configuration as a map for field-by-field comparison.
// Workgroup is omitted when empty so that Linux and macOS fragments do not
// carry a spurious absent-vs-empty distinction (ADR-016 clause 4).
func (c *HostnameConfig) AsMap() map[string]interface{} {
	m := map[string]interface{}{
		"hostname": c.Hostname,
	}
	if c.Workgroup != "" {
		m["workgroup"] = c.Workgroup
	}
	return m
}

// ToYAML serializes the configuration to YAML.
func (c *HostnameConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *HostnameConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate checks that the configuration is valid before applying it.
func (c *HostnameConfig) Validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("%w: hostname is required", modules.ErrInvalidInput)
	}
	if len(c.Hostname) > 253 {
		return fmt.Errorf("%w: hostname exceeds 253-character limit", modules.ErrInvalidInput)
	}
	if !hostnamePattern.MatchString(c.Hostname) {
		return fmt.Errorf("%w: hostname %q is not a valid host label (RFC 1123: alphanumeric and hyphens, no leading/trailing hyphen)", modules.ErrInvalidInput, c.Hostname)
	}
	if c.Workgroup != "" && !workgroupPattern.MatchString(c.Workgroup) {
		return fmt.Errorf("%w: workgroup %q is not a valid NetBIOS name (alphanumeric, hyphen, underscore; max 15 chars)", modules.ErrInvalidInput, c.Workgroup)
	}
	return nil
}

// GetManagedFields returns the list of fields this configuration manages.
func (c *HostnameConfig) GetManagedFields() []string {
	return []string{"hostname", "workgroup"}
}

// hostnameModule implements modules.Module for host identity configuration.
type hostnameModule struct {
	modules.DefaultLoggingSupport
	executor hostnameExecutor
}

// New returns a new hostname module instance.
func New() modules.Module {
	return &hostnameModule{
		executor: newExecutor(),
	}
}

// Get returns the current hostname configuration of the host.
// The resource ID is system-scoped; any non-empty value refers to the single
// host-wide identity configuration.
func (m *hostnameModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, modules.ErrInvalidResourceID
	}

	logger := m.GetEffectiveLogger(logging.ForModule("hostname"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Getting hostname configuration",
		"operation", "hostname_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "hostname")

	state, err := m.executor.getState()
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to get hostname configuration",
			"operation", "hostname_get",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "HOSTNAME_GET_FAILED",
			"error_details", logging.SanitizeLogValue(err.Error()))
		return nil, err
	}

	config := &HostnameConfig{
		Hostname:  state.Hostname,
		Workgroup: state.Workgroup,
	}

	logger.InfoCtx(ctx, "Hostname configuration retrieved",
		"operation", "hostname_get",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"status", "completed")

	return config, nil
}

// Set applies the desired hostname configuration to the host.
// Repeated calls with the same desired configuration are idempotent no-ops —
// important for declare-once identity semantics (ADR-016 clause 1).
func (m *hostnameModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return modules.ErrInvalidResourceID
	}
	if config == nil {
		return fmt.Errorf("%w: config must not be nil", modules.ErrInvalidInput)
	}

	hc, ok := config.(*HostnameConfig)
	if !ok {
		return fmt.Errorf("%w: expected *HostnameConfig, got %T", modules.ErrInvalidInput, config)
	}

	if err := hc.Validate(); err != nil {
		return err
	}

	logger := m.GetEffectiveLogger(logging.ForModule("hostname"))
	tenantID := logging.ExtractTenantFromContext(ctx)

	logger.InfoCtx(ctx, "Setting hostname configuration",
		"operation", "hostname_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"tenant_id", tenantID,
		"resource_type", "hostname")

	// Idempotency: skip the write if the host is already in the desired state.
	// This is especially important for declare-once identity modules — repeated
	// applies must not trigger reboots or rename churn (ADR-016 clause 1).
	current, err := m.executor.getState()
	if err == nil && current.Hostname == hc.Hostname && current.Workgroup == hc.Workgroup {
		logger.InfoCtx(ctx, "Hostname already matches desired state; no-op",
			"operation", "hostname_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"status", "no-op")
		return nil
	}

	desired := hostnameState{
		Hostname:  hc.Hostname,
		Workgroup: hc.Workgroup,
	}

	if err := m.executor.setState(desired); err != nil {
		logger.ErrorCtx(ctx, "Failed to set hostname configuration",
			"operation", "hostname_set",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error_code", "HOSTNAME_SET_FAILED",
			"error_details", logging.SanitizeLogValue(err.Error()))
		return err
	}

	logger.InfoCtx(ctx, "Hostname configuration applied",
		"operation", "hostname_set",
		"resource_id", logging.SanitizeLogValue(resourceID),
		"status", "completed")

	return nil
}
