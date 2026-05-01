// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package logging

import "sync"

// SensitiveLogConfig controls whether sensitive values are redacted in logs.
// Defaults to zero value (UnredactedSensitiveValues = false → redact by default).
type SensitiveLogConfig struct {
	// UnredactedSensitiveValues, when true, causes RedactedID to return the
	// full value rather than the 8-char prefix. Should only be set to true
	// in development environments via explicit configuration.
	// Default: false.
	UnredactedSensitiveValues bool
}

var (
	sensitiveLogConfig SensitiveLogConfig
	sensitiveLogMu     sync.RWMutex
)

// SetSensitiveLogConfig replaces the package-level sensitive log configuration.
// Safe for concurrent use.
func SetSensitiveLogConfig(cfg SensitiveLogConfig) {
	sensitiveLogMu.Lock()
	defer sensitiveLogMu.Unlock()
	sensitiveLogConfig = cfg
}

// GetSensitiveLogConfig returns the current package-level sensitive log configuration.
// Safe for concurrent use.
func GetSensitiveLogConfig() SensitiveLogConfig {
	sensitiveLogMu.RLock()
	defer sensitiveLogMu.RUnlock()
	return sensitiveLogConfig
}
