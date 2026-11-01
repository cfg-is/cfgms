// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// RootScopeMarkerOID is the CFGMS-private OID used to mark an mTLS admin certificate
// as belonging to a root-scoped SaaS-operator principal (ADR-025 Amendment 1 A1.3),
// as opposed to an unscoped superadmin cert. Arc: 1.3.6.1.4.1.99999.1.2 — sibling to
// AdminMarkerOID (.1.1); see that constant's NOTE on the placeholder PEN.
//
// A root-scoped principal is a distinct, narrower category than an unscoped
// superadmin: both present TenantID == "" (extractAdminPrincipal never assigns a
// tenant to an admin cert — see its doc comment), but only a superadmin cert
// (RootScopeMarkerOID absent) bypasses ADR-025 Decision 1's root<->MSP boundary
// unconditionally. This marker must never be inferred from an empty TenantID —
// that was ADR-025 Amendment 1 A1.3's open question, resolved by requiring an
// explicit signal instead.
var RootScopeMarkerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}

// SetRootScopeMarker stamps template with the CFGMS root-scope extension. A cert
// bearing both the admin marker and this extension, signed by the controller CA,
// authenticates its holder as a root-scoped SaaS-operator principal: subject to the
// ADR-025 Decision 1 root<->MSP boundary (descendants of "root" require an active
// grant or break-glass crossing) rather than the unrestricted access an ordinary
// admin cert receives. Follows the same restricted-caller convention as
// SetAdminMarker — issuance tooling should call this only from the same allow-listed
// admin cert issuance paths, gated behind whatever selects "root-scoped" vs.
// "superadmin" at generation time.
func SetRootScopeMarker(template *x509.Certificate) {
	// ASN.1 DER encoding of boolean TRUE: 0x01 (BOOLEAN) 0x01 (length) 0xFF (TRUE)
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       RootScopeMarkerOID,
		Critical: false,
		Value:    []byte{0x01, 0x01, 0xff},
	})
}

// HasRootScopeMarker reports whether cert carries the CFGMS root-scope extension.
func HasRootScopeMarker(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(RootScopeMarkerOID) {
			return true
		}
	}
	return false
}
