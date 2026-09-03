// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package operatorpayload defines the canonical signed-envelope format an operator
// signs to authorize command execution against a specific, already-resolved set of
// stewards.
//
// The existing operator-signature mechanisms (features/controller/api/handlers_runs.go,
// features/steward/commands/execute_script.go) sign command content only. Nothing binds
// the fleet selector, so a legitimately-signed payload re-addressed to a different target
// set in transit is not caught, and nothing binds a nonce or expiry, so a captured
// signature can be replayed.
//
// A live selector expression (e.g. "tenant-a/*") cannot be the bound target: resolving it
// requires features/controller/fleet, a controller-only package a steward cannot import,
// and even a portable matcher would let a group selector match more hosts at delivery time
// than at signing time through ordinary fleet growth — a timing variant of the same
// re-addressing threat. Envelope.Targets is instead an explicit, resolved list of
// cfg-declared steward IDs, frozen into the signed bytes at signing time. Verification
// becomes simple set-membership — is the delivered steward's ID in the list — requiring no
// selector-parsing capability on the steward at all.
//
// This package only encodes the envelope. Selector resolution, nonce generation, expiry
// policy, and replay-cache tracking are all owned by consuming stories.
package operatorpayload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidEnvelope is returned when an Envelope cannot form a canonical message — an
// empty required field, or a field/element containing a reserved separator. It is
// deliberately a hard error rather than a sanitization: stripping or escaping a separator
// would let two distinct envelopes collide on one signed message, which is exactly the
// ambiguity this canonicalization exists to remove.
var ErrInvalidEnvelope = errors.New("invalid operator payload envelope")

// envelopeFieldSep separates the top-level fields in the canonical message. It is absent
// from every legitimate field: the content hash is hex, shell names come from a fixed
// allow-list, the target list is inner-joined and re-checked below, nonces are
// caller-generated opaque tokens, and RFC3339 timestamps never contain "|". Fields
// carrying it are rejected rather than escaped.
const envelopeFieldSep = "|"

// envelopeTargetSep separates individual targets within the joined target list. It is
// distinct from envelopeFieldSep so the two cannot be confused with each other, and — like
// the outer separator — any target containing it is rejected rather than escaped.
const envelopeTargetSep = ","

// Envelope is the canonical set of coordinates an operator signs to authorize command
// execution: the command content, its shell, the frozen list of resolved target steward
// IDs, a replay-prevention nonce, and an expiry.
type Envelope struct {
	// Content is the raw command/script content. It is hashed (SHA-256) rather than
	// embedded verbatim into the canonical message: unlike the other fields, script
	// content routinely contains the reserved separator characters (a shell pipeline
	// like "cmd1 | cmd2" is ordinary), so rejecting on their presence would make most
	// real scripts unsignable.
	Content []byte

	// Shell identifies the interpreter the content is executed under (e.g. "bash",
	// "powershell").
	Shell string

	// Targets is the explicit, resolved list of cfg-declared steward IDs this envelope
	// authorizes. It must already be resolved and in a deterministic order before
	// signing — CanonicalBytes preserves order as given and does not sort or dedupe.
	Targets []string

	// Nonce is a caller-generated opaque token that makes the signed message unique
	// even when Content, Shell, Targets, and ExpiresAt repeat, preventing replay of a
	// captured signature. Generation and replay tracking belong to the caller.
	Nonce string

	// ExpiresAt is the instant after which the envelope is no longer valid.
	ExpiresAt time.Time
}

// CanonicalBytes returns the deterministic, injective byte sequence an operator signs for
// e: sha256(content)|shell|target1,target2,...|nonce|expiresAt.
//
// Every field is required and validated for the reserved separators before joining, so no
// two distinct Envelope values can ever produce identical output. Targets are joined with
// envelopeTargetSep before being placed into the envelopeFieldSep-joined message; since
// each target is individually checked against both separators, splitting the message
// exactly recovers the original target list.
//
// ExpiresAt is serialized via RFC3339, which is unambiguous and never contains either
// reserved separator.
func CanonicalBytes(e Envelope) ([]byte, error) {
	if len(e.Content) == 0 {
		return nil, fmt.Errorf("%w: content is empty", ErrInvalidEnvelope)
	}
	if err := requireCleanField("shell", e.Shell); err != nil {
		return nil, err
	}
	if len(e.Targets) == 0 {
		return nil, fmt.Errorf("%w: targets is empty", ErrInvalidEnvelope)
	}
	for _, target := range e.Targets {
		if err := requireCleanField("target", target); err != nil {
			return nil, err
		}
		if strings.Contains(target, envelopeTargetSep) {
			return nil, fmt.Errorf("%w: target %q contains the reserved %q separator",
				ErrInvalidEnvelope, target, envelopeTargetSep)
		}
	}
	if err := requireCleanField("nonce", e.Nonce); err != nil {
		return nil, err
	}
	if e.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: expiresAt is empty", ErrInvalidEnvelope)
	}

	contentHash := sha256.Sum256(e.Content)

	parts := []string{
		hex.EncodeToString(contentHash[:]),
		e.Shell,
		strings.Join(e.Targets, envelopeTargetSep),
		e.Nonce,
		e.ExpiresAt.UTC().Format(time.RFC3339),
	}
	return []byte(strings.Join(parts, envelopeFieldSep)), nil
}

// challengeDomainTag prefixes the WebAuthn challenge preimage so that
// sha256(challengeDomainTag || CanonicalBytes(e)) can never collide with a hash taken
// over any other assertion challenge at the same relying party.
//
// Without it, the challenge for an operator payload is sha256 of a bare canonical
// message, which is indistinguishable from an arbitrary opaque challenge: a controller
// that has been taken over could serve sha256(CanonicalBytes(envelope)) as the challenge
// in a routine passkey login, and an operator who touched their authenticator for what
// looked like a login would have produced a valid authorization for that envelope. The
// tag makes the preimage self-describing, so an assertion produced for any other
// ceremony cannot be replayed as an operator-payload authorization.
//
// It ends with the same reserved field separator CanonicalBytes joins on, and no
// legitimate field may contain that separator, so tag and canonical message can never
// run together ambiguously.
const challengeDomainTag = "cfgms-operator-payload-challenge-v1" + envelopeFieldSep

// ChallengeBytes returns the domain-separated preimage an operator's WebAuthn assertion
// challenge is taken over: challengeDomainTag || CanonicalBytes(e).
//
// The X.509 operator-signature path signs CanonicalBytes directly and is unaffected:
// that signature is produced by a certificate whose EKU and payload-signing marker
// already establish what it is for, whereas a WebAuthn assertion carries no such
// statement of purpose and needs the purpose encoded into the signed bytes themselves.
func ChallengeBytes(e Envelope) ([]byte, error) {
	canonical, err := CanonicalBytes(e)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(challengeDomainTag)+len(canonical))
	out = append(out, challengeDomainTag...)
	out = append(out, canonical...)
	return out, nil
}

// ChallengeHash returns sha256(ChallengeBytes(e)) — the exact bytes the controller
// issues as the WebAuthn assertion challenge and the steward independently recomputes
// when verifying the resulting assertion.
func ChallengeHash(e Envelope) ([sha256.Size]byte, error) {
	preimage, err := ChallengeBytes(e)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// requireCleanField rejects an empty value or one containing the reserved top-level
// separator, naming the offending field/element in the error.
func requireCleanField(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidEnvelope, name)
	}
	if strings.Contains(value, envelopeFieldSep) {
		return fmt.Errorf("%w: %s %q contains the reserved %q separator",
			ErrInvalidEnvelope, name, value, envelopeFieldSep)
	}
	return nil
}
