// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package types defines the foundational types for the CFGMS entity graph.
package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// registeredAuthorityTypes is the closed set of authority types for this version
// of the taxonomy. Authority types are the named things that mint stable local IDs
// for entities (ADR-022 §1).
var registeredAuthorityTypes = map[string]struct{}{
	"host":      {},
	"cluster":   {},
	"directory": {},
	"m365":      {},
	"cfgms":     {},
}

// EID is a fleet-global entity identifier with the form:
//
//	authority_type:authority_name[/local_id]
//
// authority_type must be a registered authority type.
// authority_name must not contain '/'.
// local_id, when present, is the ADR-017 fragment_id and may contain '/'.
//
// Parsing is unambiguous at the first '/': everything left is the authority
// segment; everything right is the local_id.
type EID struct {
	authorityType string
	authorityName string
	localID       string
}

// NewEID constructs a validated EID from its constituent parts.
// localID may be empty (produces a bare-authority EID) or may contain '/'.
func NewEID(authorityType, authorityName, localID string) (EID, error) {
	if authorityType == "" {
		return EID{}, fmt.Errorf("entitygraph/eid: authority type must not be empty")
	}
	if _, ok := registeredAuthorityTypes[authorityType]; !ok {
		return EID{}, fmt.Errorf("entitygraph/eid: unregistered authority type %q", authorityType)
	}
	if authorityName == "" {
		return EID{}, fmt.Errorf("entitygraph/eid: authority name must not be empty")
	}
	if strings.Contains(authorityName, "/") {
		return EID{}, fmt.Errorf("entitygraph/eid: authority name must not contain '/': %q", authorityName)
	}
	return EID{authorityType: authorityType, authorityName: authorityName, localID: localID}, nil
}

// ParseEID parses a string EID.
//
// The string is split at the first '/' to obtain the authority segment and
// optional local_id. The authority segment must be 'type:name' where type is
// a registered authority type and name contains no '/'.
func ParseEID(s string) (EID, error) {
	if s == "" {
		return EID{}, fmt.Errorf("entitygraph/eid: empty string is not a valid eid")
	}

	var authSeg, localID string
	if idx := strings.Index(s, "/"); idx >= 0 {
		authSeg = s[:idx]
		localID = s[idx+1:]
	} else {
		authSeg = s
	}

	colonIdx := strings.Index(authSeg, ":")
	if colonIdx < 0 {
		return EID{}, fmt.Errorf("entitygraph/eid: malformed authority segment %q: expected 'type:name'", authSeg)
	}

	authType := authSeg[:colonIdx]
	authName := authSeg[colonIdx+1:]

	if authType == "" {
		return EID{}, fmt.Errorf("entitygraph/eid: authority type must not be empty")
	}
	if authName == "" {
		return EID{}, fmt.Errorf("entitygraph/eid: authority name must not be empty in segment %q", authSeg)
	}
	if strings.Contains(authName, "/") {
		return EID{}, fmt.Errorf("entitygraph/eid: authority name must not contain '/': %q", authName)
	}
	if _, ok := registeredAuthorityTypes[authType]; !ok {
		return EID{}, fmt.Errorf("entitygraph/eid: unregistered authority type %q", authType)
	}

	return EID{authorityType: authType, authorityName: authName, localID: localID}, nil
}

// AuthorityType returns the authority type portion (e.g. "host", "cluster").
func (e EID) AuthorityType() string { return e.authorityType }

// AuthorityName returns the authority name portion (e.g. "a1b2c3").
func (e EID) AuthorityName() string { return e.authorityName }

// LocalID returns the local_id portion. Empty string means this is a bare
// authority-level EID naming the asset as a whole.
func (e EID) LocalID() string { return e.localID }

// AuthoritySegment returns "authority_type:authority_name".
func (e EID) AuthoritySegment() string { return e.authorityType + ":" + e.authorityName }

// HasLocalID reports whether the EID names a fragment within an authority.
func (e EID) HasLocalID() bool { return e.localID != "" }

// String returns the canonical string form of the EID.
func (e EID) String() string {
	if e.localID == "" {
		return e.authorityType + ":" + e.authorityName
	}
	return e.authorityType + ":" + e.authorityName + "/" + e.localID
}

// IsZero reports whether the EID is the zero value (not yet set).
func (e EID) IsZero() bool { return e.authorityType == "" }

// MarshalJSON encodes the EID as its canonical string form. Without this,
// encoding/json would serialize EID's unexported fields as "{}", silently
// discarding the entity identifier from every REST response.
func (e EID) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// UnmarshalJSON parses the EID from its canonical string form (see ParseEID).
func (e *EID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseEID(s)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}
