// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3578: mTLS admin certificate bindings for web-admin accounts.
// CertBinding ties a certificate serial number to the account that owns it.
// Serial is the binding key because IsRevoked(serial) is already the per-request
// check in extractAdminPrincipal — keying on serial means revoke-binding and
// "serial no longer resolves to an account" collapse into the existing check.
package api

import "time"

// CertBinding is the durable record of an mTLS admin certificate bound to an account.
// Serial is the binding and lookup key; Fingerprint is stored alongside for defense-in-depth
// audit correlation (both are computed at no extra cost during extractAdminPrincipal).
//
// LastUsedAt is the compensating control for Issue #3715: it records when the binding was
// last used to authenticate, so an operator listing bindings can spot a credential that no
// longer needs to renew itself. It is optional (nil) — bindings created before this story,
// and any binding that has never successfully authenticated, have no recorded use. It is
// observational only: recording it never affects the authentication decision.
//
// This field is never populated by loadAccountFromStore/persistAccount — it is always nil
// on a CertBinding read from the account record. The durable value lives in its own record
// (see certBindingLastUsedKeyPrefix in middleware.go) precisely so that recording use never
// shares a read-modify-write with the account's security-relevant fields (Disabled,
// Permissions, ...). handleListCertBindings merges it into CertBindingInfo at response time.
type CertBinding struct {
	Serial      string     `json:"serial"`
	Fingerprint string     `json:"fingerprint"`
	Label       string     `json:"label,omitempty"`
	BoundAt     time.Time  `json:"bound_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	// HumanApprovedAt is set once, when the credential this binding traces back to
	// was first approved by a human (the credential-request approve endpoint, Issue
	// #3718), and copied forward unchanged on every later renewal (Issue #3724). A
	// credential that renews itself indefinitely still carries the date a person
	// last vouched for it. Nil for bindings created outside that flow (e.g. the
	// admin-account cert-bind endpoint) — there is no approval event to record.
	HumanApprovedAt *time.Time `json:"human_approved_at,omitempty"`
}

// CertBindingInfo is the public view returned by GET .../certs.
// It mirrors CertBinding but carries no additional fields — the full struct
// is already public-safe (no private key material is ever stored).
type CertBindingInfo struct {
	Serial      string     `json:"serial"`
	Fingerprint string     `json:"fingerprint"`
	Label       string     `json:"label,omitempty"`
	BoundAt     time.Time  `json:"bound_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	// HumanApprovedAt mirrors CertBinding.HumanApprovedAt — see that field's doc comment.
	HumanApprovedAt *time.Time `json:"human_approved_at,omitempty"`
}
