// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
)

// SigningCapabilityStore is the durable, cluster-shared home of each steward's
// advertised signing-payload version. business.StewardStore satisfies it, so every
// controller node sharing the steward store sees the same capability and signs the
// version the steward expects (#5174). GetSigningPayloadVersion returns 0 with a nil
// error for a steward the store has no record of.
type SigningCapabilityStore interface {
	SetSigningPayloadVersion(ctx context.Context, stewardID string, version uint32) error
	GetSigningPayloadVersion(ctx context.Context, stewardID string) (uint32, error)
}

const (
	// capabilityStoreTimeout bounds one store round trip made while signing.
	capabilityStoreTimeout = 5 * time.Second
	// capabilityRewriteInterval is how long an unchanged advertisement is trusted to
	// still be in the shared store before a heartbeat writes it again. It bounds the
	// store write rate (one per steward per interval, not one per heartbeat) while
	// repairing a value another node overwrote.
	capabilityRewriteInterval = 5 * time.Minute
)

// SigningCapabilities records, per steward, the highest command signing-payload
// version the steward advertised on its heartbeat (#5174). It is the single source
// of the version choice for every controller-side signer (command publisher, script
// dispatcher, relay handler) through SignCommand.
//
// Built with NewSharedSigningCapabilities, the capability lives in the shared store,
// so a node that never received the steward's heartbeat still signs the version the
// steward expects, and a store failure surfaces as an error instead of a silent v1
// command a switched steward would refuse. Built with NewSigningCapabilities the
// state is in memory (single node, tests): an unknown steward is v1.
//
// A nil *SigningCapabilities is valid and reports v1 for every steward.
type SigningCapabilities struct {
	store SigningCapabilityStore

	mu       sync.RWMutex
	stewards map[string]uint32    // memory-only registry (store == nil)
	written  map[string]writtenAt // last value this node wrote to the store
}

type writtenAt struct {
	version uint32
	at      time.Time
}

// NewSigningCapabilities returns an in-memory registry.
func NewSigningCapabilities() *SigningCapabilities {
	return &SigningCapabilities{stewards: make(map[string]uint32)}
}

// NewSharedSigningCapabilities returns a registry backed by the cluster-shared store.
func NewSharedSigningCapabilities(store SigningCapabilityStore) *SigningCapabilities {
	return &SigningCapabilities{store: store, written: make(map[string]writtenAt)}
}

// Record replaces what is known about a steward from the versions on its latest
// heartbeat. Versions this build does not know are ignored, and an empty list
// resets the steward to v1. A shared-store failure is returned.
func (c *SigningCapabilities) Record(stewardID string, versions []uint32) error {
	if c == nil || stewardID == "" {
		return nil
	}
	best := SigningPayloadV1
	for _, v := range versions {
		if v == SigningPayloadV2 && v > best {
			best = v
		}
	}
	stored := best
	if stored == SigningPayloadV1 {
		stored = 0
	}

	if c.store == nil {
		c.mu.Lock()
		if best == SigningPayloadV1 {
			delete(c.stewards, stewardID)
		} else {
			c.stewards[stewardID] = best
		}
		c.mu.Unlock()
		return nil
	}

	now := time.Now()
	c.mu.RLock()
	last, ok := c.written[stewardID]
	c.mu.RUnlock()
	if ok && last.version == stored && now.Sub(last.at) < capabilityRewriteInterval {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityStoreTimeout)
	defer cancel()
	if err := c.store.SetSigningPayloadVersion(ctx, stewardID, stored); err != nil {
		return fmt.Errorf("record signing capability: %w", err)
	}
	c.mu.Lock()
	c.written[stewardID] = writtenAt{version: stored, at: now}
	c.mu.Unlock()
	return nil
}

// VersionFor returns the payload version to sign with for stewardID. With a shared
// store, an error means the capability could not be determined; callers must not
// sign in that case, because a guessed version may be one the steward refuses.
func (c *SigningCapabilities) VersionFor(stewardID string) (uint32, error) {
	if c == nil {
		return SigningPayloadV1, nil
	}
	if c.store == nil {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if v, ok := c.stewards[stewardID]; ok {
			return v, nil
		}
		return SigningPayloadV1, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityStoreTimeout)
	defer cancel()
	v, err := c.store.GetSigningPayloadVersion(ctx, stewardID)
	if err != nil {
		return 0, fmt.Errorf("look up signing capability for steward %q: %w", stewardID, err)
	}
	if v == SigningPayloadV2 {
		return v, nil
	}
	return SigningPayloadV1, nil
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
	version, err := caps.VersionFor(cmd.StewardID)
	if err != nil {
		return nil, fmt.Errorf("select signing payload version: %w", err)
	}
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
