// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3717 (Epic #3711 — browser-authenticated CLI enrolment): enrolment tokens
// and the pending credential-request queue. An admin mints a short-lived single-use
// enrolment token and hands it to a machine out of band. That machine, holding no
// certificate, spends the token to lodge a certificate signing request carrying only
// a public key. The request lands in a durable pending queue that admins can list and
// deny. Nothing in this story issues a certificate, binds an account, or collects the
// credential — those are later stories in the epic.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	// enrolmentTokenSecretType and credentialRequestSecretType are the distinct
	// MetadataKeySecretType values for these two record kinds in the central secret
	// store (M-AUTH-1). Records live in the store the same way web-account records do
	// (handlers_accounts.go persistAccount) — no sibling storage-provider interface.
	enrolmentTokenSecretType    = "enrolment_token"
	credentialRequestSecretType = "credential_request"

	// enrolmentTokenKeyPrefix and credentialRequestKeyPrefix namespace these two
	// record kinds in the secret store, mirroring accountKeyPrefix.
	enrolmentTokenKeyPrefix    = "enrolment-token-"
	credentialRequestKeyPrefix = "credential-request-"

	// enrolmentTokenTTL and credentialRequestTTL bound the lifetime of a minted
	// token and a lodged request. Both are short-lived by design (Issue #3717): an
	// enrolment token is a bearer credential handed out of band, and a pending
	// request is an unauthenticated actor's unverified claim.
	enrolmentTokenTTL    = time.Hour
	credentialRequestTTL = time.Hour

	// enrolmentTokenBytes and collectSecretBytes are the random source lengths for
	// the enrolment token and the collect secret. 32 bytes = 256 bits, well above
	// the >=128-bit bar used elsewhere in this package (accounts.go enrollmentTokenBytes).
	enrolmentTokenBytes = 32
	collectSecretBytes  = 32

	// enrolmentTokenDisplayPrefixLen is how many hex characters of the raw token are
	// retained in cleartext for operator identification in listings and logs — the
	// rest is discarded once the hash is computed. Mirrors business.RegistrationTokenDisplayPrefix.
	enrolmentTokenDisplayPrefixLen = 6

	// maxPendingCredentialRequestsPerTenant bounds the queue so a flood of lodges
	// against tenant-scoped tokens cannot grow the pending queue without limit. The
	// cap refuses new lodges outright rather than evicting existing entries — eviction
	// would turn the cap into a queue-flush primitive (Issue #3717 implementation note).
	maxPendingCredentialRequestsPerTenant = 100

	// credentialRequestStatusPending and credentialRequestStatusDenied are the status
	// vocabulary for this story. There is no "approved" or "collected" status here —
	// those belong to the next two stories in the epic, which this story's queue does
	// not implement. A denied request can never move to any other status.
	credentialRequestStatusPending = "pending"
	credentialRequestStatusDenied  = "denied"
)

// enrolmentToken is the durable record for a single-use, short-lived pre-shared
// credential that gates the lodge endpoint. Persisted through the central secret
// store (M-AUTH-1); the raw token value is never stored — only its SHA-256 hash and
// a short display prefix (mirrors business.RegistrationTokenLookupKey /
// RegistrationTokenDisplayPrefix — the same hashed-at-rest shape, implemented locally
// here because this is a distinct record kind from registration.Token).
type enrolmentToken struct {
	ID          string
	TenantID    string
	TokenHash   string
	TokenPrefix string
	CreatedAt   time.Time
	CreatedBy   string
	ExpiresAt   time.Time
	Revoked     bool
	RevokedAt   *time.Time
	// SpentAt is set the moment a lodge consumes this token, whether or not the
	// resulting request is ever approved (Issue #3717 implementation note: the token
	// is single-use, unlike the perennial steward registration token).
	SpentAt          *time.Time
	SpentByRequestID string
}

// valid reports whether t may still be spent by a lodge at time now: not revoked,
// not already spent, and not expired. Unknown (nil) tokens are invalid.
func (t *enrolmentToken) valid(now time.Time) bool {
	if t == nil {
		return false
	}
	if t.Revoked {
		return false
	}
	if t.SpentAt != nil {
		return false
	}
	if !now.Before(t.ExpiresAt) {
		return false
	}
	return true
}

// pendingCredentialRequest is the durable record for a lodged signing request
// awaiting an administrator's decision. Persisted through the central secret store,
// exactly like enrolmentToken. Hostname, Label, Platform and Purpose are caller-supplied
// at lodge time and are display-only untrusted text — never used as a store key and
// never trusted for any authorization decision.
type pendingCredentialRequest struct {
	ID       string
	TenantID string
	Status   string

	// PublicKeyFingerprint is the SHA-256 fingerprint over the CSR's public key
	// (RawSubjectPublicKeyInfo) — the request's identity (Issue #3717). CSRPEM is
	// retained so a later story can issue a certificate from it without asking the
	// machine to re-present its signing request.
	PublicKeyFingerprint string
	CSRPEM               string

	SourceIP string
	Hostname string
	Label    string
	Platform string
	Purpose  string

	CreatedAt time.Time
	ExpiresAt time.Time

	// CollectSecretHash is the SHA-256 hash of the collect secret returned exactly
	// once at lodge time. Never the cleartext value.
	CollectSecretHash string

	EnrolmentTokenID string

	DeniedAt *time.Time
	DeniedBy string
}

// hashCredentialSecret returns the SHA-256 hex digest of a raw secret (an enrolment
// token or a collect secret). Only the hash is ever persisted.
func hashCredentialSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// enrolmentTokenDisplayPrefix extracts the short, non-secret operator-identification
// prefix from a raw token. This is the only part of the token safe to surface in a
// listing or a log line (Issue #3717 implementation note).
func enrolmentTokenDisplayPrefix(raw string) string {
	if len(raw) <= enrolmentTokenDisplayPrefixLen {
		return raw
	}
	return raw[:enrolmentTokenDisplayPrefixLen]
}

// publicKeyFingerprint returns the full SHA-256 fingerprint (hex) of spkiDER — the
// persisted request identity — and a short, human-comparable form. Both forms are
// deterministic functions of the public key alone, so an administrator can compute
// the same short form independently and match it against what the lodging machine
// printed before approving (Issue #3717 AC).
func publicKeyFingerprint(spkiDER []byte) (full, short string) {
	sum := sha256.Sum256(spkiDER)
	full = hex.EncodeToString(sum[:])
	short = shortFingerprintFromFull(full)
	return full, short
}

// shortFingerprintFromFull derives the human-comparable short form from a full hex
// fingerprint: its first 16 hex characters (the first 8 bytes of the digest),
// uppercased and grouped in 4-character blocks (e.g. "AB12-CD34-EF56-7890"). Kept
// separate from publicKeyFingerprint so a stored full fingerprint (which is all that
// persists — the raw public key is not re-read) can be redisplayed identically in a
// listing without needing the original DER bytes.
func shortFingerprintFromFull(fullHex string) string {
	hexStr := fullHex
	if len(hexStr) > 16 {
		hexStr = hexStr[:16]
	}
	hexStr = strings.ToUpper(hexStr)
	var groups []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		groups = append(groups, hexStr[i:end])
	}
	return strings.Join(groups, "-")
}

// MintEnrolmentTokenRequest is the POST /api/v1/enrolment-tokens body.
type MintEnrolmentTokenRequest struct {
	TenantID string `json:"tenant_id"`
}

// EnrolmentTokenResponse is the API representation of an enrolment token. Token (the
// full secret) is populated only by the mint response — every other path must use
// EnrolmentTokenResponseRedacted.
type EnrolmentTokenResponse struct {
	ID          string  `json:"id"`
	Token       string  `json:"token,omitempty"`
	TokenPrefix string  `json:"token_prefix"`
	TenantID    string  `json:"tenant_id"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   string  `json:"expires_at"`
	Revoked     bool    `json:"revoked"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
}

// LodgeCredentialRequestBody is the POST .../credential-requests/lodge body. Every
// field besides CSRPEM is display-only untrusted text (Issue #3717 implementation
// note) — deliberately absent are any tenant, account, permission or marker fields:
// json.Decode ignores any such keys a caller sends, so there is nothing here for a
// caller-supplied claim to attach to.
type LodgeCredentialRequestBody struct {
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname,omitempty"`
	Label    string `json:"label,omitempty"`
	Platform string `json:"platform,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
}

// LodgeCredentialRequestResponse is returned once, at lodge time. CollectSecret is
// never returned by any other endpoint.
type LodgeCredentialRequestResponse struct {
	RequestID                 string `json:"request_id"`
	PublicKeyFingerprint      string `json:"public_key_fingerprint"`
	PublicKeyFingerprintShort string `json:"public_key_fingerprint_short"`
	CollectSecret             string `json:"collect_secret"`
	ExpiresAt                 string `json:"expires_at"`
}

// PendingCredentialRequestInfo is the list-response shape for a pending credential
// request. It never carries the collect secret (hash or cleartext), the CSR, or the
// enrolment token that lodged it.
type PendingCredentialRequestInfo struct {
	ID                        string `json:"id"`
	TenantID                  string `json:"tenant_id"`
	Status                    string `json:"status"`
	PublicKeyFingerprint      string `json:"public_key_fingerprint"`
	PublicKeyFingerprintShort string `json:"public_key_fingerprint_short"`
	SourceIP                  string `json:"source_ip"`
	Hostname                  string `json:"hostname,omitempty"`
	Label                     string `json:"label,omitempty"`
	Platform                  string `json:"platform,omitempty"`
	Purpose                   string `json:"purpose,omitempty"`
	CreatedAt                 string `json:"created_at"`
	ExpiresAt                 string `json:"expires_at"`
}

// denyCredentialRequestRequest is the optional request body for the deny endpoint,
// mirroring denyRegistrationRequest in handlers_registration.go.
type denyCredentialRequestRequest struct {
	Reason string `json:"reason,omitempty"`
}
