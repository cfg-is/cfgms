// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"errors"
	"fmt"
	"io"
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

// TokenFileErrorKind classifies why a registration token file was refused, so a
// caller can tell the class without matching the message.
type TokenFileErrorKind string

const (
	// TokenFileMissing: the file does not exist.
	TokenFileMissing TokenFileErrorKind = "missing"
	// TokenFileEmpty: the file holds no token.
	TokenFileEmpty TokenFileErrorKind = "empty"
	// TokenFilePermissions: the file is not exclusively controlled by the
	// service account (owner, mode or ACL), is not a regular file, or cannot be
	// opened for reading.
	TokenFilePermissions TokenFileErrorKind = "permissions"
	// TokenFileInvalid: the file was read but its content is unusable (too
	// large, or not a single-token string), or reading it failed.
	TokenFileInvalid TokenFileErrorKind = "invalid"
)

// TokenFileError is returned by ReadTokenFile when the file is refused. Its
// message never contains the token.
type TokenFileError struct {
	Kind TokenFileErrorKind
	Err  error
}

func (e *TokenFileError) Error() string { return e.Err.Error() }
func (e *TokenFileError) Unwrap() error { return e.Err }

// tokenFileErr wraps err as a *TokenFileError of the given kind.
func tokenFileErr(kind TokenFileErrorKind, format string, args ...any) error {
	return &TokenFileError{Kind: kind, Err: fmt.Errorf(format, args...)}
}

// AsTokenFileError reports whether err is (or wraps) a *TokenFileError.
func AsTokenFileError(err error) (*TokenFileError, bool) {
	var tfe *TokenFileError
	if errors.As(err, &tfe) {
		return tfe, true
	}
	return nil, false
}

// readTokenContent reads the token from r, an already-opened and checked token
// file at path, and refuses content that is too large, empty or not a valid
// token. Errors never contain the token.
func readTokenContent(r io.Reader, path string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxTokenFileSize+1))
	if err != nil {
		return "", tokenFileErr(TokenFileInvalid, "read registration token file %s: %w", path, err)
	}
	if len(data) > maxTokenFileSize {
		return "", tokenFileErr(TokenFileInvalid, "registration token file %s is too large", path)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", tokenFileErr(TokenFileEmpty, "registration token file %s is empty", path)
	}
	if err := validateToken(token); err != nil {
		return "", tokenFileErr(TokenFileInvalid, "registration token file %s: %w", path, err)
	}
	return token, nil
}
