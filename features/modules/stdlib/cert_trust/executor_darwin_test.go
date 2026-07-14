// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package cert_trust

import (
	"strings"
	"testing"
)

// buildSecurityOutput assembles a synthetic `security find-certificate -a -Z -p`
// output block for a certificate: a "SHA-256 hash:" line (using the supplied
// fingerprint text verbatim so tests can exercise formatting variants) followed
// by the certificate's PEM. This mirrors the interleaved format the security(1)
// binary produces without invoking it.
func buildSecurityOutput(fpLine, certPEM string) string {
	return "SHA-256 hash: " + fpLine + "\n" + strings.TrimSpace(certPEM) + "\n"
}

// TestParseSecurityFindCertificateOutput_SingleCert verifies a single cert block
// is parsed into one certEntry with the security-reported fingerprint preserved
// and metadata (subject, issuer, expiry) derived from the DER.
func TestParseSecurityFindCertificateOutput_SingleCert(t *testing.T) {
	certPEM, certDER := generateTestCAPEM(t)
	fp := certFingerprint(certDER)

	// security reports uppercase hex; the parser must normalize to lowercase.
	out := buildSecurityOutput(strings.ToUpper(fp), certPEM)

	entries := parseSecurityFindCertificateOutput(out)
	if len(entries) != 1 {
		t.Fatalf("parseSecurityFindCertificateOutput returned %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Fingerprint != fp {
		t.Errorf("Fingerprint = %q, want %q (lowercase, no colons)", e.Fingerprint, fp)
	}
	if e.Subject == "" {
		t.Error("Subject must not be empty")
	}
	if e.Issuer == "" {
		t.Error("Issuer must not be empty")
	}
	if e.NotAfter == "" {
		t.Error("NotAfter must not be empty")
	}
}

// TestParseSecurityFindCertificateOutput_ColonAndSpaceSeparators verifies the
// parser strips colon and space separators from the SHA-256 hash line, which
// some security(1) versions/locales emit.
func TestParseSecurityFindCertificateOutput_ColonAndSpaceSeparators(t *testing.T) {
	certPEM, certDER := generateTestCAPEM(t)
	fp := certFingerprint(certDER)

	// Insert a colon after every two hex chars, uppercase, to mimic a
	// colon-separated, spaced hash line.
	var b strings.Builder
	up := strings.ToUpper(fp)
	for i := 0; i < len(up); i += 2 {
		if i > 0 {
			b.WriteString(" : ")
		}
		b.WriteString(up[i : i+2])
	}
	out := buildSecurityOutput(b.String(), certPEM)

	entries := parseSecurityFindCertificateOutput(out)
	if len(entries) != 1 {
		t.Fatalf("returned %d entries, want 1", len(entries))
	}
	if entries[0].Fingerprint != fp {
		t.Errorf("Fingerprint = %q, want %q", entries[0].Fingerprint, fp)
	}
}

// TestParseSecurityFindCertificateOutput_MultipleCerts verifies that multiple
// interleaved hash+PEM blocks each produce a distinct certEntry with the
// correct fingerprint paired to the correct certificate.
func TestParseSecurityFindCertificateOutput_MultipleCerts(t *testing.T) {
	pem1, der1 := generateTestCAPEM(t)
	pem2, der2 := generateTestCAPEM(t)
	fp1 := certFingerprint(der1)
	fp2 := certFingerprint(der2)

	out := buildSecurityOutput(strings.ToUpper(fp1), pem1) +
		buildSecurityOutput(strings.ToUpper(fp2), pem2)

	entries := parseSecurityFindCertificateOutput(out)
	if len(entries) != 2 {
		t.Fatalf("returned %d entries, want 2", len(entries))
	}

	byFP := map[string]certEntry{}
	for _, e := range entries {
		byFP[e.Fingerprint] = e
	}
	if _, ok := byFP[fp1]; !ok {
		t.Errorf("entry for fingerprint %s missing", fp1)
	}
	if _, ok := byFP[fp2]; !ok {
		t.Errorf("entry for fingerprint %s missing", fp2)
	}
}

// TestParseSecurityFindCertificateOutput_Empty verifies empty and whitespace-only
// output yields no entries and does not panic.
func TestParseSecurityFindCertificateOutput_Empty(t *testing.T) {
	for _, in := range []string{"", "\n", "   \n\n"} {
		if entries := parseSecurityFindCertificateOutput(in); len(entries) != 0 {
			t.Errorf("parseSecurityFindCertificateOutput(%q) = %d entries, want 0", in, len(entries))
		}
	}
}

// TestParseSecurityFindCertificateOutput_PEMWithoutHash verifies a PEM block that
// has no preceding SHA-256 hash line is skipped rather than emitting an entry
// with an empty fingerprint.
func TestParseSecurityFindCertificateOutput_PEMWithoutHash(t *testing.T) {
	certPEM, _ := generateTestCAPEM(t)

	entries := parseSecurityFindCertificateOutput(strings.TrimSpace(certPEM) + "\n")
	if len(entries) != 0 {
		t.Errorf("PEM without SHA-256 hash line produced %d entries, want 0", len(entries))
	}
}

// TestParseSecurityFindCertificateOutput_MalformedPEM verifies a corrupted PEM
// block is skipped without producing an entry or panicking.
func TestParseSecurityFindCertificateOutput_MalformedPEM(t *testing.T) {
	out := "SHA-256 hash: AABBCC\n" +
		"-----BEGIN CERTIFICATE-----\n" +
		"not-valid-base64-@@@@\n" +
		"-----END CERTIFICATE-----\n"

	if entries := parseSecurityFindCertificateOutput(out); len(entries) != 0 {
		t.Errorf("malformed PEM produced %d entries, want 0", len(entries))
	}
}

// TestParseSecurityFindCertificateOutput_HashResetBetweenBlocks verifies the
// current fingerprint is cleared after each PEM block so a trailing PEM without
// its own hash line does not inherit the previous block's fingerprint.
func TestParseSecurityFindCertificateOutput_HashResetBetweenBlocks(t *testing.T) {
	pem1, der1 := generateTestCAPEM(t)
	pem2, _ := generateTestCAPEM(t)
	fp1 := certFingerprint(der1)

	// First block is complete (hash + PEM); second block is a PEM with no hash.
	out := buildSecurityOutput(strings.ToUpper(fp1), pem1) + strings.TrimSpace(pem2) + "\n"

	entries := parseSecurityFindCertificateOutput(out)
	if len(entries) != 1 {
		t.Fatalf("returned %d entries, want 1 (second PEM must not inherit fp1)", len(entries))
	}
	if entries[0].Fingerprint != fp1 {
		t.Errorf("Fingerprint = %q, want %q", entries[0].Fingerprint, fp1)
	}
}
