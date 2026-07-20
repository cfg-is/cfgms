// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: WebAuthn passkey / FIDO2 registration — type definitions.
package api

import "time"

// WebAuthnCredential is a stored WebAuthn passkey / FIDO2 credential record.
// Only public-key material is persisted — the server never holds the private key.
//
// Storage decision (required explicit call by the issue): credentials are stored
// in the web-account secrets-store metadata entry alongside the argon2id hash,
// keeping one persistence path per account record. Rationale: WebAuthn credentials
// are public keys — they do not need secret storage (ADR-021 Non-Goals). The
// secrets-store seam is chosen for implementation simplicity (one record, one
// persistence path) rather than because the keys require encryption.
type WebAuthnCredential struct {
	ID           []byte    `json:"id"`
	PublicKey    []byte    `json:"public_key"`
	SignCount    uint32    `json:"sign_count"`
	Transport    []string  `json:"transport,omitempty"`
	Label        string    `json:"label,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// webAuthnSessionTTL is the maximum age of a pending WebAuthn registration session.
// Challenges older than this are refused (challenge freshness enforcement).
const webAuthnSessionTTL = 5 * time.Minute

// WebAuthnRegisterFinishResponse is returned on successful credential registration.
// Only the credential ID and metadata are returned — no private-key-adjacent material
// (the server never holds the private key; this response confirms what was stored).
type WebAuthnRegisterFinishResponse struct {
	CredentialID []byte    `json:"credential_id"`
	Label        string    `json:"label,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// WebAuthnCredentialInfo is the public view of a registered credential, returned
// by the list endpoint. The public key bytes are omitted — credential ID, label,
// transport hints, and registration timestamp are sufficient for display and revocation.
type WebAuthnCredentialInfo struct {
	ID           string    `json:"id"` // base64url-encoded credential ID
	Label        string    `json:"label,omitempty"`
	Transport    []string  `json:"transport,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// WebAuthnListResponse is returned by GET /api/v1/web/accounts/{username}/webauthn/credentials.
type WebAuthnListResponse struct {
	Username    string                   `json:"username"`
	Credentials []WebAuthnCredentialInfo `json:"credentials"`
}
