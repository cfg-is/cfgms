// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package service

import (
	"fmt"
	"strings"
)

// validateToken rejects registration tokens that contain whitespace or control
// characters. Such characters could corrupt service definition files (systemd
// units, launchd plists) where the token is embedded as a literal argument.
// Valid registration tokens are API-key-style strings (e.g. tok_abc123...) and
// should never contain whitespace.
func validateToken(token string) error {
	if token == "" {
		return fmt.Errorf("registration token cannot be empty")
	}
	if strings.ContainsAny(token, " \t\n\r") {
		return fmt.Errorf("registration token contains whitespace: tokens must not contain spaces, tabs, or newlines")
	}
	return nil
}
