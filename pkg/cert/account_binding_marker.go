// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// AccountBindingOID is the CFGMS-private OID of the extension that binds a payload-signing
// certificate to the account that owns it. Arc: 1.3.6.1.4.1.99999.1.4 — sibling to
// AdminMarkerOID (.1.1), RootScopeMarkerOID (.1.2) and PayloadSigningMarkerOID (.1.3); see
// AdminMarkerOID's NOTE on the placeholder PEN.
//
// The value is the owning account's ID as a DER UTF8String. The certificate's CommonName is
// display-only and is never used for authorization: it is the channel-prefixed principal name,
// which says nothing durable about which account may sign. A verifier reads the owner from this
// extension, compares it with the authenticated principal's account ID, and then re-checks that
// account's current authority — the certificate proves who owns the key, not that the owner is
// still allowed to sign.
var AccountBindingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}

// MaxAccountBindingLen bounds the account ID carried in the extension, in bytes. It keeps a
// hostile or malformed certificate from driving an unbounded allocation or comparison in a
// verifier, and is far above any ID the controller generates.
const MaxAccountBindingLen = 256

// validAccountBindingID reports whether id is usable as a bound account ID: non-empty, within
// MaxAccountBindingLen, valid UTF-8 and free of control characters.
func validAccountBindingID(id string) bool {
	if id == "" || len(id) > MaxAccountBindingLen || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidateAccountBindingID reports whether accountID could be bound into a certificate by
// SetAccountBinding, without needing a certificate template. Issuers call it to refuse an
// unbindable ID before any certificate is signed.
func ValidateAccountBindingID(accountID string) error {
	if !validAccountBindingID(accountID) {
		return fmt.Errorf("account binding requires a non-empty account ID of at most %d printable UTF-8 bytes", MaxAccountBindingLen)
	}
	return nil
}

// SetAccountBinding stamps template with the account-binding extension for accountID. It
// refuses an ID that could not be read back by AccountBindingFromCertificate, so a certificate
// is never issued with a binding no verifier would accept.
//
// Use it alongside SetPayloadSigningMarker when issuing a payload-signing credential; the
// restricted-caller rule of SetPayloadSigningMarker applies equally, because a binding naming
// an account other than the requester's would let one operator sign as another.
func SetAccountBinding(template *x509.Certificate, accountID string) error {
	if err := ValidateAccountBindingID(accountID); err != nil {
		return err
	}
	value, err := asn1.MarshalWithParams(accountID, "utf8")
	if err != nil {
		return fmt.Errorf("encode account binding: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       AccountBindingOID,
		Critical: false,
		Value:    value,
	})
	return nil
}

// AccountBindingFromCertificate returns the account ID bound into cert and true, or "" and
// false when cert carries no usable binding. It fails closed: a repeated extension, a value that
// is not exactly one non-empty UTF8String, trailing bytes, an oversized ID or one with control
// characters all report no binding, so a caller that requires a binding rejects them. Chain
// verification is the caller's responsibility.
func AccountBindingFromCertificate(cert *x509.Certificate) (string, bool) {
	var raw []byte
	found := false
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(AccountBindingOID) {
			continue
		}
		if found {
			return "", false
		}
		found = true
		raw = ext.Value
	}
	if !found {
		return "", false
	}
	var id string
	rest, err := asn1.UnmarshalWithParams(raw, &id, "utf8")
	if err != nil || len(rest) != 0 || !validAccountBindingID(id) {
		return "", false
	}
	return id, true
}
