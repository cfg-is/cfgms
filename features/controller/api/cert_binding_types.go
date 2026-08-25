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
type CertBinding struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	Label       string    `json:"label,omitempty"`
	BoundAt     time.Time `json:"bound_at"`
}

// CertBindingInfo is the public view returned by GET .../certs.
// It mirrors CertBinding but carries no additional fields — the full struct
// is already public-safe (no private key material is ever stored).
type CertBindingInfo struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	Label       string    `json:"label,omitempty"`
	BoundAt     time.Time `json:"bound_at"`
}
