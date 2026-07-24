// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: WebAuthn passkey / FIDO2 registration — type definitions.
// Issue #2784: presence-token types and constants.
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
	ID             []byte    `json:"id"`
	PublicKey      []byte    `json:"public_key"`
	SignCount      uint32    `json:"sign_count"`
	Transport      []string  `json:"transport,omitempty"`
	Label          string    `json:"label,omitempty"`
	RegisteredAt   time.Time `json:"registered_at"`
	BackupEligible bool      `json:"backup_eligible,omitempty"` // W3C WebAuthn BE flag (stored at registration)
	BackupState    bool      `json:"backup_state,omitempty"`    // W3C WebAuthn BS flag (stored at registration)
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

// presenceTokenTTL is the maximum age of a minted presence token. Tokens older than
// this are rejected even if they haven't been consumed yet. The short window enforces
// ADR-021 Decision 4: "fresh per action, not per session."
const presenceTokenTTL = 30 * time.Second

// presenceTokenRecord is a single entry in the server's presenceTokens sync.Map.
// It is keyed by the SHA-256 hex hash of the raw token value. The token itself is
// never stored — only the hash — to limit exposure if the map were somehow dumped.
//
// Single-use contract: the entry is deleted via LoadAndDelete at first use. Expiry is
// enforced independently so that unconsumed tokens are refused after presenceTokenTTL
// even if they were not loaded (client may never send the request).
type presenceTokenRecord struct {
	principalID string
	expires     time.Time
}

// WebAuthnPresenceFinishResponse is returned by POST /api/v1/webauthn/presence/finish
// when the assertion is successfully verified. The token must be attached as the
// X-Presence-Token header on the guarded request within presenceTokenTTL seconds.
type WebAuthnPresenceFinishResponse struct {
	PresenceToken string `json:"presence_token"`
	ExpiresIn     int    `json:"expires_in_seconds"` // informational; server enforces TTL
}

// StepUpElevateFinishResponse is returned by POST /api/v1/webauthn/elevate/finish
// on successful step-up elevation. The assurance field echoes the new session assurance.
type StepUpElevateFinishResponse struct {
	Assurance  string    `json:"assurance"`
	ElevatedAt time.Time `json:"elevated_at"`
}
