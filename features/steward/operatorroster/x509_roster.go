// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// The X.509 operator-signer roster: the part of the controller's signed manifest that says which
// payload-signing certificates may currently sign an operator payload on this steward. It is the
// X.509 counterpart of the WebAuthn roster the commands package verifies per command, and it
// rides the same manifest (features/controller/api.RevocationManifest). The structs here mirror
// the controller's field for field so the manifest round-trips losslessly through
// encoding/json — see the note on revocationManifest.
package operatorroster

import (
	"time"
)

// AuthorizedX509SignerKind mirrors AuthorizedX509SignerKind in
// features/controller/api/handlers_revocation_manifest.go.
const AuthorizedX509SignerKind = "x509-signing-certificate"

// rosterClockSkew is how far a manifest's issuance instant may sit in this steward's future
// before its roster is ignored. Without a bound, a far-future IssuedAt would become the newest
// roster this steward holds and lock out every legitimate manifest that follows.
const rosterClockSkew = 2 * time.Minute

// AuthorizedX509Signer mirrors features/controller/api.AuthorizedX509Signer field-for-field.
type AuthorizedX509Signer struct {
	Kind             string   `json:"kind"`
	Serial           string   `json:"serial"`
	AccountID        string   `json:"account_id"`
	TenantID         string   `json:"tenant_id"`
	RootScope        bool     `json:"root_scope"`
	Grants           []string `json:"grants"`
	CoveredTenantIDs []string `json:"covered_tenant_ids,omitempty"`
}

// x509RosterState is the newest verified X.509 signer roster. Unlike RevokedSerials, which only
// ever grows, the roster is replaced wholesale by a newer one: a signer the controller has
// dropped (account disabled, grant removed) must stop being accepted, not be remembered.
type x509RosterState struct {
	held     bool
	issuedAt time.Time
	bySerial map[string][]AuthorizedX509Signer
}

// apply adopts the roster of a manifest issued at issuedAt, only when that manifest is at least
// as new as the roster already held, so a captured older manifest cannot roll the roster back to
// one that still lists a since-removed signer. A manifest issued implausibly far in the future
// is ignored for the same reason a stale one is. Called under the verifier's lock, and only for
// a manifest whose signature chain-verified.
func (r *x509RosterState) apply(issuedAt time.Time, signers []AuthorizedX509Signer) {
	if issuedAt.IsZero() || issuedAt.After(time.Now().Add(rosterClockSkew)) {
		return
	}
	if r.held && issuedAt.Before(r.issuedAt) {
		return
	}
	bySerial := make(map[string][]AuthorizedX509Signer, len(signers))
	for _, signer := range signers {
		if signer.Kind != AuthorizedX509SignerKind || signer.Serial == "" {
			continue
		}
		bySerial[signer.Serial] = append(bySerial[signer.Serial], signer)
	}
	r.held = true
	r.issuedAt = issuedAt
	r.bySerial = bySerial
}

// X509SignerRoster is a point-in-time view of the verified X.509 signer roster.
type X509SignerRoster struct {
	issuedAt time.Time
	bySerial map[string][]AuthorizedX509Signer
}

// IssuedAt is the controller-signed issuance instant of the manifest the roster came from; the
// caller bounds its age.
func (r *X509SignerRoster) IssuedAt() time.Time { return r.issuedAt }

// SignersForSerial returns the roster entries naming serial (a decimal certificate serial). The
// controller lists one entry per certificate, so more than one is only possible from a
// misbehaving controller; the caller examines every entry and accepts on any that authorizes.
func (r *X509SignerRoster) SignersForSerial(serial string) []AuthorizedX509Signer {
	return r.bySerial[serial]
}

// X509SignerRoster returns the newest X.509 signer roster this verifier took from a manifest it
// chain-verified itself, and false when it holds none — no manifest has verified yet, or none
// that did carried a verified signer. Absence is not an empty roster: callers must refuse
// X.509 operator signatures without one, because it is the only source of the signer's
// authority.
func (v *RevocationVerifier) X509SignerRoster() (*X509SignerRoster, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.x509Roster.held {
		return nil, false
	}
	return &X509SignerRoster{issuedAt: v.x509Roster.issuedAt, bySerial: v.x509Roster.bySerial}, true
}
