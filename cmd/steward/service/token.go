// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"fmt"
	"path/filepath"
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

// regTokenFileFlag is the launcher child argument carrying the path of the
// registration token file.
const regTokenFileFlag = "--regtoken-file"

// commandLineHasRegToken reports whether a service command line or definition
// carries a non-empty --regtoken or --regtoken-file argument. It never returns
// the value.
func commandLineHasRegToken(definition string) bool {
	return commandLineHasFlagValue(definition, regTokenFlag) ||
		commandLineHasFlagValue(definition, regTokenFileFlag)
}

func commandLineHasFlagValue(definition, flag string) bool {
	_, rest, found := strings.Cut(definition, flag+" ")
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

// tokenFileName is the name of the root-only registration token file. It lives
// beside the installed CA certificate.
const tokenFileName = "registration-token"

// platformTokenFilePath returns the registration token file path, a sibling of
// platformCACertPath so CFGMS_INSTALL_PREFIX isolates tests.
func platformTokenFilePath() string {
	return filepath.Join(filepath.Dir(platformCACertPath()), tokenFileName)
}

// TokenFilePath returns the path of the registration token file.
func TokenFilePath() string {
	return platformTokenFilePath()
}
