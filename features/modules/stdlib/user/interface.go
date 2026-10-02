// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package user

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// UserConfig represents the desired or observed state of a local user account.
type UserConfig struct {
	// State is the desired account presence: "present" or "absent".
	State string `yaml:"state"`
	// FullName is the display name / GECOS comment for the account.
	FullName string `yaml:"full_name,omitempty"`
	// Groups lists the supplementary group names the account belongs to.
	// On Linux, the primary group is included. Sorted alphabetically.
	Groups []string `yaml:"groups,omitempty"`
	// Locked reports whether the account is locked or disabled.
	// When true, the account cannot authenticate interactively.
	Locked bool `yaml:"locked"`
	// HasCredential reports whether the OS considers the account to have a
	// password set. This field is OBSERVED ONLY — Set() never accepts,
	// stores, or transmits password material. Omitted from GetManagedFields.
	//
	// Do NOT rename this back to PasswordSet. CodeQL's clear-text-logging
	// heuristic classifies any identifier matching pass(wd|word|code|phrase)
	// as a sensitive source by name alone, which made this bool the origin of
	// a large false-positive alert cluster across the controller and workflow
	// packages. The value is a boolean observation; no credential exists here.
	HasCredential bool `yaml:"has_credential,omitempty"`
}

// AsMap returns the configuration as a map for field-by-field comparison.
// Groups are sorted alphabetically to ensure deterministic output (ADR-016 clause 4).
func (c *UserConfig) AsMap() map[string]interface{} {
	groups := make([]string, len(c.Groups))
	copy(groups, c.Groups)
	sort.Strings(groups)

	return map[string]interface{}{
		"state":          c.State,
		"full_name":      c.FullName,
		"groups":         groups,
		"locked":         c.Locked,
		"has_credential": c.HasCredential,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *UserConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration.
func (c *UserConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate checks that the configuration is valid before applying it.
func (c *UserConfig) Validate() error {
	switch c.State {
	case "present", "absent":
		// valid
	case "":
		return fmt.Errorf("%w: state is required (present or absent)", modules.ErrInvalidInput)
	default:
		return fmt.Errorf("%w: state must be 'present' or 'absent', got %q", modules.ErrInvalidInput, c.State)
	}
	return nil
}

// GetManagedFields returns the fields this configuration actively manages.
// has_credential is excluded because it is observed-only and never set by this module.
func (c *UserConfig) GetManagedFields() []string {
	return []string{"state", "full_name", "groups", "locked"}
}
