// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert_trust

// certEntry holds the observed state of a single certificate in the OS trust store.
type certEntry struct {
	// Fingerprint is the SHA-256 fingerprint of the certificate (lowercase hex, no colons).
	Fingerprint string
	// Subject is the certificate subject distinguished name.
	Subject string
	// Issuer is the certificate issuer distinguished name.
	Issuer string
	// NotAfter is the certificate expiry in RFC3339 format.
	NotAfter string
	// TrustedFor describes the trust purpose (e.g. "any", "tls", "code_signing").
	// On Linux and Windows this defaults to "any"; macOS trust settings may be more specific.
	TrustedFor string
}

// trustStoreExecutor is the platform-specific backend for OS trust store operations.
// Each platform (Linux, Windows, macOS) provides its own implementation via build
// tags. Unsupported platforms use the stub implementation that returns ErrUnsupportedPlatform.
type trustStoreExecutor interface {
	// list returns all certificates currently in the system trust store.
	list() ([]certEntry, error)

	// install adds the DER-encoded certificate to the system trust store.
	// The certificate must be a CA certificate (IsCA=true). No private key
	// material is accepted — if certDER contains a private key, install returns
	// an error.
	install(certDER []byte) error

	// remove deletes the certificate with the given SHA-256 fingerprint (lowercase
	// hex, no colons) from the system trust store. If no certificate with that
	// fingerprint is present, remove is a no-op (not an error).
	remove(fingerprint string) error
}
