//go:build !commercial
// +build !commercial

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package ha

// LoadFromEnvironment provides a stub implementation for OSS builds
// The full implementation is in config.go (commercial only)
// OSS doesn't need complex configuration loading from environment variables
func (c *Config) LoadFromEnvironment() error {
	// OSS stub - no environment variable loading needed
	// Configuration is handled through the manager initialization
	return nil
}
