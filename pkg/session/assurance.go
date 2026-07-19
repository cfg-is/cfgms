// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

// AssuranceLevel is the identity assurance level of an authenticated principal
// (ADR-021 Decision 1). Higher values mean stronger proof of identity.
// The numeric values are load-bearing — they are compared with < and >= operators
// in requirePermission to enforce minimum assurance levels.
type AssuranceLevel int

const (
	// AssuranceMachine is assigned to API-key principals. These callers authenticate
	// with a long-lived credential that requires no human interaction at the time of
	// use, so they are unsuitable for credential-minting or catastrophic operations.
	AssuranceMachine AssuranceLevel = 0

	// AssuranceBasic is assigned to cfg-CLI Bearer session principals and web-session
	// cookie principals. The session was originally established with a stronger
	// credential (mTLS admin cert or WebAuthn), but the ongoing session token does not
	// require human presence to present.
	AssuranceBasic AssuranceLevel = 1

	// AssuranceStrong is assigned to mTLS admin-certificate principals. The admin cert
	// is a hardware-bound or tightly-controlled credential that requires deliberate
	// operator action to present, making it suitable for credential-minting operations.
	// Future: WebAuthn assertions will also reach AssuranceStrong.
	AssuranceStrong AssuranceLevel = 2
)

// String returns the lowercase name of the assurance level for use in API responses
// and the WWW-Authenticate header (ADR-021 Decision 6).
func (a AssuranceLevel) String() string {
	switch a {
	case AssuranceMachine:
		return "machine"
	case AssuranceBasic:
		return "basic"
	case AssuranceStrong:
		return "strong"
	default:
		return "unknown"
	}
}
