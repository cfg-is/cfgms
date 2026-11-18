// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package types

import (
	"errors"
	"sort"
)

// Capability states of one steward connection. They are the same values the
// durable record stores (business.StewardCapability*).
const (
	// CapabilityPending means the connection has not declared its capabilities
	// and the grace period has not ended. Nothing is known about the steward.
	CapabilityPending = "pending"
	// CapabilityDeclared means the steward declared its capability sets on this
	// connection.
	CapabilityDeclared = "declared"
	// CapabilityFloor means no declaration arrived within the grace period, so
	// the profile is the baseline every steward build handles.
	CapabilityFloor = "floor"
)

// Declaration bounds. A declaration is steward input and untrusted: the lists
// are capped before they are stored, so a hostile steward cannot grow a record.
const (
	// MaxDeclaredCommandTypes caps the command type numbers kept per declaration.
	MaxDeclaredCommandTypes = 64
	// MaxDeclaredSigningPayloadVersions caps the payload versions kept per
	// declaration.
	MaxDeclaredSigningPayloadVersions = 16
)

// maxRawDeclaredEntries bounds how many entries of a declared list are examined
// at all, so a hostile list is not walked in full before it is capped.
const maxRawDeclaredEntries = 1024

// floorCommandTypeMax is the highest CommandType number every steward build
// handles. Command types 1..13 are the set the wire carried before capability
// declarations existed.
const floorCommandTypeMax = 13

// probeSigningPayloadVersionMax bounds the probe SupportedSigningPayloadVersions
// runs to find the versions CommandSigningBytesVersion accepts.
const probeSigningPayloadVersionMax = 32

// StewardCapabilities is what a steward declares on the control channel: the
// command type numbers (the wire CommandType enum values) and the signing
// payload versions its build handles.
type StewardCapabilities struct {
	// StewardID is the steward making the declaration. The controller checks it
	// against the authenticated identity of the stream.
	StewardID string

	// CommandTypes are CommandType enum numbers.
	CommandTypes []int32

	// SigningPayloadVersions are the signing payload versions the steward can
	// verify.
	SigningPayloadVersions []uint32
}

// CapabilityProfile is the capability set the controller works with for one
// steward connection, with the state it is in. CommandTypes and
// SigningPayloadVersions are meaningful only when State is CapabilityDeclared or
// CapabilityFloor.
type CapabilityProfile struct {
	// State is CapabilityPending, CapabilityDeclared or CapabilityFloor.
	State string

	// CommandTypes are CommandType enum numbers the steward handles.
	CommandTypes []int32

	// SigningPayloadVersions are the payload versions the steward verifies.
	SigningPayloadVersions []uint32
}

// FloorProfile is the baseline profile: command types 1..13 and signing payload
// version 1. It is what the controller assumes for a steward that did not
// declare, and what every steward build handles.
func FloorProfile() CapabilityProfile {
	cmds := make([]int32, 0, floorCommandTypeMax)
	for i := int32(1); i <= floorCommandTypeMax; i++ {
		cmds = append(cmds, i)
	}
	return CapabilityProfile{
		State:                  CapabilityFloor,
		CommandTypes:           cmds,
		SigningPayloadVersions: []uint32{SigningPayloadV1},
	}
}

// SupportsCommandType reports whether the profile lists the command type number.
func (p CapabilityProfile) SupportsCommandType(n int32) bool {
	for _, c := range p.CommandTypes {
		if c == n {
			return true
		}
	}
	return false
}

// SupportsSigningPayloadVersion reports whether the profile lists the version.
func (p CapabilityProfile) SupportsSigningPayloadVersion(v uint32) bool {
	for _, c := range p.SigningPayloadVersions {
		if c == v {
			return true
		}
	}
	return false
}

// SupportedSigningPayloadVersions returns, ascending, the signing payload
// versions this build's CommandSigningBytesVersion accepts. It asks the signing
// code instead of listing versions, so a declaration cannot drift from the build.
func SupportedSigningPayloadVersions() []uint32 {
	var out []uint32
	for v := uint32(1); v <= probeSigningPayloadVersionMax; v++ {
		if _, err := CommandSigningBytesVersion(&Command{}, nil, v); !errors.Is(err, ErrUnknownSigningPayloadVersion) {
			out = append(out, v)
		}
	}
	return out
}

// NormalizeCapabilityLists returns the declared lists in the form the
// controller stores: command types and versions sorted, deduplicated and capped,
// with every value for which known reports false dropped. A nil known keeps all
// positive command types. Declarations are untrusted, so an oversized list is
// truncated after sorting rather than rejected.
func NormalizeCapabilityLists(commandTypes []int32, versions []uint32, knownCommand func(int32) bool) ([]int32, []uint32) {
	cmds := normalizeList(commandTypes, MaxDeclaredCommandTypes, func(c int32) bool {
		return c > 0 && (knownCommand == nil || knownCommand(c))
	})
	vers := normalizeList(versions, MaxDeclaredSigningPayloadVersions, func(v uint32) bool { return v > 0 })
	return cmds, vers
}

// normalizeList examines at most maxRawDeclaredEntries of in, keeps the distinct
// values keep accepts, and returns them ascending and capped at limit.
func normalizeList[T int32 | uint32](in []T, limit int, keep func(T) bool) []T {
	if len(in) > maxRawDeclaredEntries {
		in = in[:maxRawDeclaredEntries]
	}
	out := make([]T, 0, len(in))
	seen := make(map[T]struct{}, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		if keep(v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
