// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import "errors"

// Sentinel errors returned by HandleCommand for each authentication rejection path.
var (
	// ErrUnauthenticatedCommand is returned when a command has no signature or the
	// signature verification fails.
	ErrUnauthenticatedCommand = errors.New("unauthenticated command")

	// ErrCommandReplay is returned when a command timestamp exceeds the replay window
	// or when the command ID has already been processed within the current window.
	ErrCommandReplay = errors.New("command replay detected")

	// ErrWrongSteward is returned when the command's StewardID does not match this
	// handler's steward identity.
	ErrWrongSteward = errors.New("command addressed to wrong steward")

	// ErrParamsTooLarge is returned when the JSON-serialized Params exceed the
	// configured maxParamsBytes limit.
	ErrParamsTooLarge = errors.New("command params too large")
)
