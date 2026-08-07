// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package user

// userState holds the observed current state of a local OS user account.
type userState struct {
	Exists        bool
	FullName      string
	Groups        []string // sorted supplementary+primary group names, no duplicates
	Locked        bool
	HasCredential bool // observed only; setState must never modify this
}

// userExecutor is the platform-specific backend for local user account operations.
// Each platform (Linux, Windows, macOS) provides its own implementation via build
// tags. Unsupported platforms use the stub implementation that returns
// ErrUnsupportedPlatform.
type userExecutor interface {
	// getState returns the current state of the named local user account.
	// If the user does not exist, it returns a zero userState with Exists=false
	// and no error — callers check Exists to distinguish absence from error.
	getState(username string) (userState, error)

	// setState applies the desired account state. It is idempotent: calling
	// setState when the account is already in the desired state is a no-op.
	// setState never reads or writes password material; HasCredential in desired
	// is always ignored.
	setState(username string, desired userState) error
}
