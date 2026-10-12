// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"errors"
	"fmt"
	"os"
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

// regTokenFlag is the launcher child argument carrying the registration token.
const regTokenFlag = "--regtoken"

// commandLineHasRegToken reports whether a service command line or definition
// carries a non-empty --regtoken argument. It never returns the value.
func commandLineHasRegToken(definition string) bool {
	_, rest, found := strings.Cut(definition, regTokenFlag+" ")
	if !found {
		return false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return false
	}
	// The value must not be the next flag or a closing quote.
	return !strings.HasPrefix(fields[0], "-") && !strings.HasPrefix(fields[0], `"`)
}

// definitionHasRegToken reports whether the service definition file at path
// carries a --regtoken argument. A missing file reports false, not an error.
func definitionHasRegToken(path string) (bool, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- fixed platform service-definition path
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read service definition %s: %w", path, err)
	}
	return commandLineHasRegToken(string(data)), nil
}
