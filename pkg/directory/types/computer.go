// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import "time"

// DirectoryComputer represents a unified computer object across directory providers.
// This is the canonical representation used internally by CFGMS for all computer operations.
type DirectoryComputer struct {
	// Core Identity
	ID             string `json:"id" yaml:"id"`                                       // Unique identifier (objectGUID)
	Name           string `json:"name" yaml:"name"`                                   // Computer display name
	SAMAccountName string `json:"sam_account_name,omitempty" yaml:"sam_account_name"` // SAM account name (e.g. "HOSTNAME$")
	DNSHostName    string `json:"dns_host_name,omitempty" yaml:"dns_host_name"`       // Fully qualified DNS name

	// Directory Structure
	DN string `json:"dn,omitempty" yaml:"dn"` // Distinguished name
	OU string `json:"ou,omitempty" yaml:"ou"` // Parent OU

	// Platform Information
	OperatingSystem        string `json:"operating_system,omitempty" yaml:"operating_system"`                 // OS name
	OperatingSystemVersion string `json:"operating_system_version,omitempty" yaml:"operating_system_version"` // OS version string

	// Authentication / Status
	Enabled   bool       `json:"enabled" yaml:"enabled"`                 // Whether account is enabled
	LastLogon *time.Time `json:"last_logon,omitempty" yaml:"last_logon"` // Last successful logon

	// Provider-Specific Attributes (extensibility)
	ProviderAttributes map[string]interface{} `json:"provider_attributes,omitempty" yaml:"provider_attributes"`

	// Metadata
	Created  *time.Time `json:"created,omitempty" yaml:"created"`   // When created
	Modified *time.Time `json:"modified,omitempty" yaml:"modified"` // When last modified
	Source   string     `json:"source" yaml:"source"`               // Source provider name
}
