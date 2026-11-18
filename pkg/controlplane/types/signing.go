// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/features/config/signature"
)

// SigningVersionSource chooses the signing payload version for a steward's
// current connection. The answer comes from controller-held state only: never
// from the command being signed, and never from anything a steward sent in a
// command or its params.
type SigningVersionSource interface {
	// SigningVersionFor returns SigningPayloadV1 or SigningPayloadV2 for the
	// steward's connection. It may wait, bounded, for a connection that has not
	// declared its capabilities yet; ctx ends that wait.
	SigningVersionFor(ctx context.Context, stewardID string) uint32
}

// SignCommand wraps cmd in a SignedCommand and, when signer is non-nil, signs it
// over the term-covering v2 payload (#5285). It is SignCommandVersion at v2, for
// callers that have no steward connection to choose a version for. The input
// command is not modified; the returned command carries
// SigningPayloadVersion = SigningPayloadV2.
func SignCommand(cmd *Command, signer signature.Signer) (*SignedCommand, error) {
	return SignCommandVersion(cmd, signer, SigningPayloadV2)
}

// SignCommandForSteward signs cmd in the payload version source names for
// cmd.StewardID's connection. A nil source signs v2. Whatever
// cmd.SigningPayloadVersion held on entry is ignored.
func SignCommandForSteward(ctx context.Context, source SigningVersionSource, cmd *Command, signer signature.Signer) (*SignedCommand, error) {
	version := SigningPayloadV2
	if source != nil {
		version = source.SigningVersionFor(ctx, cmd.StewardID)
	}
	return SignCommandVersion(cmd, signer, version)
}

// SignCommandVersion wraps cmd in a SignedCommand and, when signer is non-nil,
// signs it over the named payload version. Only SigningPayloadV1 and
// SigningPayloadV2 are accepted; any other version is
// ErrUnknownSigningPayloadVersion. The input command is not modified.
//
// A v2 command carries SigningPayloadVersion = SigningPayloadV2. A v1 command
// leaves it unset (0), the pre-#5285 wire form a v0.10.5 steward verifies; its
// stamped term stays on the command but is not covered by the signature. Any
// SigningPayloadVersion cmd held on entry is overwritten.
func SignCommandVersion(cmd *Command, signer signature.Signer, version uint32) (*SignedCommand, error) {
	if version != SigningPayloadV1 && version != SigningPayloadV2 {
		return nil, fmt.Errorf("%w: %d", ErrUnknownSigningPayloadVersion, version)
	}
	sc := &SignedCommand{Command: *cmd}
	if version == SigningPayloadV2 {
		sc.Command.SigningPayloadVersion = SigningPayloadV2
	} else {
		sc.Command.SigningPayloadVersion = 0
	}
	if signer == nil {
		return sc, nil
	}
	// Sign the canonical form (string params + UTC timestamp) that survives the
	// proto round-trip without type mutations. See CommandSigningBytes for details.
	rawParams := InterfaceParamsToStringMap(sc.Command.Params)
	signBytes, err := CommandSigningBytesVersion(&sc.Command, rawParams, version)
	if err != nil {
		return nil, fmt.Errorf("marshal command for signing: %w", err)
	}
	sig, err := signer.Sign(signBytes)
	if err != nil {
		return nil, fmt.Errorf("sign command: %w", err)
	}
	sc.Signature = sig
	return sc, nil
}

// CommandSupportSource reports whether a steward's current connection handles a
// command type. Like SigningVersionSource, the answer comes from controller-held
// state only, never from the command or anything a steward sent in it.
type CommandSupportSource interface {
	// SupportsCommandType returns false only when the controller knows the
	// steward's profile and the profile does not list cmdType. A type the
	// controller does not know, and a steward with no state, are supported: the
	// command is not gated. It may wait, bounded, for a connection that has not
	// declared its capabilities yet; ctx ends that wait.
	SupportsCommandType(ctx context.Context, stewardID string, cmdType CommandType) bool
}

// PeerSupportsCommandType asks source, when it also answers command support,
// whether the steward handles cmdType. A source that does not (including nil)
// gates nothing.
func PeerSupportsCommandType(ctx context.Context, source SigningVersionSource, stewardID string, cmdType CommandType) bool {
	support, ok := source.(CommandSupportSource)
	if !ok {
		return true
	}
	return support.SupportsCommandType(ctx, stewardID, cmdType)
}
