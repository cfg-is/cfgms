// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// AdminMarkerOID is the CFGMS-private OID used to mark admin client certificates.
// Arc: 1.3.6.1.4.1.99999.1.1
// NOTE: 99999 is a placeholder PEN. Once CFGMS registers a Private Enterprise Number
// with IANA, replace 99999 with the assigned PEN in all issued certificate templates.
// The OID byte sequence is the security boundary — certs already issued with this OID
// require a coordinated rotation when the PEN changes.
// Follow-up P3 issue: register CFGMS PEN with IANA.
var AdminMarkerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// SetAdminMarker stamps template with the CFGMS admin extension (OID 1.3.6.1.4.1.99999.1.1).
// A cert bearing this extension, signed by the controller CA, authenticates its holder
// as a CFGMS admin principal with full API authorization.
//
// IMPORTANT — restricted callers (enforced by TestSetAdminMarker_Architecture in architecture_test.go).
// Do not call from any production path outside the allow-list without PO approval:
//   - features/controller/initialization/initialization.go (Story B)
//   - features/controller/initialization/admin_bundle.go  (Story D)
func SetAdminMarker(template *x509.Certificate) {
	// ASN.1 DER encoding of boolean TRUE: 0x01 (BOOLEAN) 0x01 (length) 0xFF (TRUE)
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       AdminMarkerOID,
		Critical: false,
		Value:    []byte{0x01, 0x01, 0xff},
	})
}

// HasAdminMarker reports whether cert carries the CFGMS admin extension.
// Chain verification is the caller's responsibility — in production this is handled
// at the TLS handshake layer via tls.VerifyClientCertIfGiven + ClientCAs.
func HasAdminMarker(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AdminMarkerOID) {
			return true
		}
	}
	return false
}
