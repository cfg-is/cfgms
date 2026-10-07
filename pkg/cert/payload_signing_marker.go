// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// PayloadSigningMarkerOID is the CFGMS-private OID used to mark a CSR-issued
// payload-signing client certificate. Arc: 1.3.6.1.4.1.99999.1.3 — sibling to
// AdminMarkerOID (.1.1) and RootScopeMarkerOID (.1.2); see AdminMarkerOID's NOTE
// on the placeholder PEN.
//
// A cert bearing this extension was issued via CA.SignClientCertificateRequest:
// the CA signed a caller-supplied public key and never generated or held the
// corresponding private key. This marker exists so a payload-signing credential
// is never indistinguishable from an ordinary admin transport bundle at
// verification time — HasAdminMarker alone is not sufficient to authorize
// payload-signing use.
var PayloadSigningMarkerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}

// SetPayloadSigningMarker stamps template with the CFGMS payload-signing extension
// (OID 1.3.6.1.4.1.99999.1.3). A cert bearing this extension, signed by the
// controller CA, authenticates its holder as a CFGMS payload-signing credential.
//
// IMPORTANT — restricted callers (enforced by TestSetPayloadSigningMarker_Architecture
// in architecture_test.go). Do not call from any production path outside the
// allow-list without PO approval:
//   - features/controller/api/handlers_signing_credential.go (Issue #3693)
func SetPayloadSigningMarker(template *x509.Certificate) {
	// ASN.1 DER encoding of boolean TRUE: 0x01 (BOOLEAN) 0x01 (length) 0xFF (TRUE)
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       PayloadSigningMarkerOID,
		Critical: false,
		Value:    []byte{0x01, 0x01, 0xff},
	})
}

// HasPayloadSigningMarker reports whether cert carries the CFGMS payload-signing
// extension. Chain verification is the caller's responsibility — in production
// this is handled at the TLS handshake layer via tls.VerifyClientCertIfGiven +
// ClientCAs.
func HasPayloadSigningMarker(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(PayloadSigningMarkerOID) {
			return true
		}
	}
	return false
}
