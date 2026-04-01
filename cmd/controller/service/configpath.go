// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
	"fmt"
	"strings"
)

// validateConfigPath rejects config paths that are empty or contain characters
// that could corrupt service definition files:
//   - systemd unit files: double-quote breaks out of ExecStart quoted argument
//   - launchd plists (XML): <, >, & enable XML injection into ProgramArguments
//   - all platforms: null byte is not a valid path character
func validateConfigPath(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config path cannot be empty")
	}
	if strings.Contains(configPath, `"`) {
		return fmt.Errorf("config path must not contain double-quote characters")
	}
	if strings.ContainsAny(configPath, "<>&\x00") {
		return fmt.Errorf("config path must not contain XML-special or null characters (< > & \\0)")
	}
	return nil
}
