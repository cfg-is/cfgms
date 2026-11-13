// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package identity

import (
	"crypto"
	"errors"
	"io"
)

// ErrUserKeyUnavailable means no platform key provider can hold a user key on
// this host.
var ErrUserKeyUnavailable = errors.New("no platform key provider is available")

// ErrUserKeyUnsupported means this OS has no platform user-key support. Every
// user-key function returns it here; the Linux TPM and macOS Secure Enclave are
// not used for user keys.
var ErrUserKeyUnsupported = errors.New("platform user keys are not supported on this OS")

// UserKeysSupported reports whether CreateUserKey can be used on this OS.
func UserKeysSupported() bool { return false }

// UserKeySigner is a platform user key. It cannot be created on this OS.
type UserKeySigner struct{}

var _ crypto.Signer = (*UserKeySigner)(nil)

// CreateUserKey returns ErrUserKeyUnsupported.
func CreateUserKey() (*UserKeySigner, error) { return nil, ErrUserKeyUnsupported }

// OpenUserKey returns ErrUserKeyUnsupported.
func OpenUserKey(_, _ string) (*UserKeySigner, error) { return nil, ErrUserKeyUnsupported }

// DeleteUserKey returns ErrUserKeyUnsupported.
func DeleteUserKey(_, _ string) error { return ErrUserKeyUnsupported }

// KeyName returns "".
func (s *UserKeySigner) KeyName() string { return "" }

// Provider returns "".
func (s *UserKeySigner) Provider() string { return "" }

// Public returns nil.
func (s *UserKeySigner) Public() crypto.PublicKey { return nil }

// Sign returns ErrUserKeyUnsupported.
func (s *UserKeySigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, ErrUserKeyUnsupported
}
