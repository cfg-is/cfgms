// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"fmt"
	"sync"

	"github.com/cfgis/cfgms/features/config/signature"
)

// SigningCapabilities records, per steward, the highest command signing-payload
// version the steward advertised on its heartbeat (#5174). It is the single source
// of the version choice for every controller-side signer (command publisher, script
// dispatcher, relay handler) through SignCommand.
//
// State is in memory and rebuilt from heartbeats: until a steward's first heartbeat
// reaches this controller node it is treated as v1-only, the safe default.
//
// A nil *SigningCapabilities is valid and reports v1 for every steward.
type SigningCapabilities struct {
	mu       sync.RWMutex
	stewards map[string]uint32
}

// NewSigningCapabilities returns an empty registry.
func NewSigningCapabilities() *SigningCapabilities {
	return &SigningCapabilities{stewards: make(map[string]uint32)}
}

// Record replaces what is known about a steward from the versions on its latest
// heartbeat. Versions this build does not know are ignored, and an empty list
// resets the steward to v1.
func (c *SigningCapabilities) Record(stewardID string, versions []uint32) {
	if c == nil || stewardID == "" {
		return
	}
	best := SigningPayloadV1
	for _, v := range versions {
		if v == SigningPayloadV2 && v > best {
			best = v
		}
	}
	c.mu.Lock()
	if best == SigningPayloadV1 {
		delete(c.stewards, stewardID)
	} else {
		c.stewards[stewardID] = best
	}
	c.mu.Unlock()
}

// VersionFor returns the payload version to sign with for stewardID.
func (c *SigningCapabilities) VersionFor(stewardID string) uint32 {
	if c == nil {
		return SigningPayloadV1
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.stewards[stewardID]; ok {
		return v
	}
	return SigningPayloadV1
}

// SignCommand wraps cmd in a SignedCommand and, when signer is non-nil, signs it
// over the payload version caps selects for cmd.StewardID. This is the one signing
// path for outbound controller commands. The input command is not modified; the
// returned command carries SigningPayloadVersion when v2 was used (v1 leaves it
// unset so v1 commands stay byte-compatible on the wire).
func SignCommand(cmd *Command, signer signature.Signer, caps *SigningCapabilities) (*SignedCommand, error) {
	sc := &SignedCommand{Command: *cmd}
	if signer == nil {
		return sc, nil
	}
	version := caps.VersionFor(cmd.StewardID)
	if version != SigningPayloadV1 {
		sc.Command.SigningPayloadVersion = version
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
