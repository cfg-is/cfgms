// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"time"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
)

// ValidateConfiguration delegates to the shared stewardtypes validator.
func ValidateConfiguration(c StewardConfig) error {
	return stewardtypes.ValidateConfiguration(c)
}

// MergeScriptSigningConfig delegates to the shared stewardtypes implementation.
func MergeScriptSigningConfig(parent, child ScriptSigningConfig) (ScriptSigningConfig, error) {
	return stewardtypes.MergeScriptSigningConfig(parent, child)
}

// GetConvergeInterval delegates to the shared stewardtypes implementation.
func GetConvergeInterval(cfg StewardConfig) time.Duration {
	return stewardtypes.GetConvergeInterval(cfg)
}

// GetConfiguredModules delegates to the shared stewardtypes implementation.
func GetConfiguredModules(config StewardConfig) []string {
	return stewardtypes.GetConfiguredModules(config)
}
