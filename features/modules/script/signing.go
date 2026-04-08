// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

// TrustMode defines which signing keys or certificates are considered trustworthy.
type TrustMode string

const (
	// TrustModeAnyValid accepts any cryptographically valid signature.
	TrustModeAnyValid TrustMode = "any_valid"

	// TrustModeTrustedKeys accepts signatures only from keys listed in TrustedKeys.
	TrustModeTrustedKeys TrustMode = "trusted_keys"

	// TrustModeTrustedKeysAndPublic accepts listed keys or publicly-trusted CA chains when
	// AllowPublicCA is also true.
	TrustModeTrustedKeysAndPublic TrustMode = "trusted_keys_and_public"
)

// TrustedKeyEntry identifies a trusted signing key or certificate by thumbprint.
type TrustedKeyEntry struct {
	// Name is a human-readable label for this entry.
	Name string

	// Thumbprint is the hex-encoded certificate thumbprint (SHA-1 or SHA-256).
	// Compared case-insensitively against the thumbprint embedded in the script signature.
	Thumbprint string

	// PublicKeyRef is reserved for future secrets-provider integration.
	// When set, this is an opaque reference to a public key stored in the secrets store.
	// Matching by PublicKeyRef requires a secrets provider and is not yet implemented.
	PublicKeyRef string
}

// ModuleSigningConfig holds the steward-level signing policy for the script module.
// It is injected via Module.SetSigningConfig and consulted during signature verification.
// The zero value corresponds to TrustModeAnyValid (no key restriction).
type ModuleSigningConfig struct {
	// TrustMode controls which signatures are accepted after cryptographic verification.
	TrustMode TrustMode

	// TrustedKeys is the allowlist consulted when TrustMode is trusted_keys or
	// trusted_keys_and_public. Matching is performed by Thumbprint.
	TrustedKeys []TrustedKeyEntry

	// AllowPublicCA, when true alongside TrustModeTrustedKeysAndPublic, also accepts
	// signatures from publicly-trusted certificate authorities.
	AllowPublicCA bool
}

// windowsAuthenticodeVerifier is set by signing_windows.go on Windows builds via init().
// On non-Windows platforms it remains nil and PowerShell scripts fall back to detached
// signature verification. This avoids a build-tag split on the shared dispatch function.
var windowsAuthenticodeVerifier func(content []byte, sig *ScriptSignature, cfg ModuleSigningConfig) error

// isPowerShellScript reports whether the shell type is a PowerShell variant.
func isPowerShellScript(shell ShellType) bool {
	return shell == ShellPowerShell
}

// verifyScriptSignature selects the appropriate verification method based on platform and shell.
//
// On Windows, PowerShell (.ps1/.psm1/.psd1) scripts are verified via Authenticode
// (Get-AuthenticodeSignature). All other scripts — including PowerShell on non-Windows
// platforms — use detached RSA/ECDSA signature verification.
func verifyScriptSignature(content []byte, sig *ScriptSignature, shell ShellType, cfg ModuleSigningConfig) error {
	if isPowerShellScript(shell) && windowsAuthenticodeVerifier != nil {
		return windowsAuthenticodeVerifier(content, sig, cfg)
	}
	return verifyDetachedSignature(content, sig, cfg)
}

// verifyDetachedSignature performs real cryptographic signature verification of script content.
//
// sig.PublicKey must be a PEM-encoded public key (PKIX or X.509 certificate).
// sig.Signature must be the raw signature bytes encoded as standard or URL-safe base64.
// sig.Algorithm must be one of: rsa-sha256, rsa-sha512, ecdsa-sha256, ecdsa-sha384.
//
// After cryptographic verification, the trust mode policy is enforced using sig.Thumbprint.
func verifyDetachedSignature(content []byte, sig *ScriptSignature, cfg ModuleSigningConfig) error {
	if sig == nil {
		return fmt.Errorf("%w: signature is nil", modules.ErrInvalidInput)
	}
	if sig.PublicKey == "" {
		return fmt.Errorf("%w: public key is required for cryptographic verification", modules.ErrInvalidInput)
	}

	// Decode base64-encoded signature bytes; try standard then URL-safe encoding.
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		sigBytes, err = base64.URLEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("%w: signature must be base64 encoded: %v", modules.ErrInvalidInput, err)
		}
	}

	// Parse the PEM-encoded public key.
	pub, err := parsePublicKey(sig.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: failed to parse public key: %v", modules.ErrInvalidInput, err)
	}

	// Perform cryptographic verification against the script content.
	if err := verifyCryptoSignature(content, sigBytes, sig.Algorithm, pub); err != nil {
		return fmt.Errorf("cryptographic signature verification failed: %w", err)
	}

	// Enforce trust mode policy using the signature's certificate thumbprint.
	return applyTrustMode(sig.Thumbprint, cfg)
}

// parsePublicKey decodes a PEM-encoded PKIX public key or X.509 certificate.
func parsePublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key string")
	}

	// Try PKIX SubjectPublicKeyInfo format (standard for raw public keys).
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}

	// Fall back to X.509 certificate (extract the embedded public key).
	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr != nil {
		return nil, fmt.Errorf("unsupported key format (not PKIX SubjectPublicKeyInfo or X.509 DER): %v", err)
	}
	return cert.PublicKey, nil
}

// verifyCryptoSignature verifies sigBytes against the hash of content using the named algorithm.
//
// Supported algorithms:
//   - rsa-sha256:   RSA PKCS#1 v1.5 with SHA-256
//   - rsa-sha512:   RSA PKCS#1 v1.5 with SHA-512
//   - ecdsa-sha256: ECDSA with SHA-256 (DER-encoded ASN.1 signature)
//   - ecdsa-sha384: ECDSA with SHA-384 (DER-encoded ASN.1 signature)
func verifyCryptoSignature(content, sigBytes []byte, algorithm string, pub crypto.PublicKey) error {
	algo := strings.ToLower(algorithm)

	switch algo {
	case "rsa-sha256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm rsa-sha256 requires an RSA public key, got %T", pub)
		}
		h := sha256.Sum256(content)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sigBytes)

	case "rsa-sha512":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm rsa-sha512 requires an RSA public key, got %T", pub)
		}
		h := sha512.Sum512(content)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, h[:], sigBytes)

	case "ecdsa-sha256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm ecdsa-sha256 requires an ECDSA public key, got %T", pub)
		}
		h := sha256.Sum256(content)
		if !ecdsa.VerifyASN1(ecPub, h[:], sigBytes) {
			return fmt.Errorf("ECDSA-SHA256 signature is not valid")
		}
		return nil

	case "ecdsa-sha384":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm ecdsa-sha384 requires an ECDSA public key, got %T", pub)
		}
		h := sha512.Sum384(content)
		if !ecdsa.VerifyASN1(ecPub, h[:], sigBytes) {
			return fmt.Errorf("ECDSA-SHA384 signature is not valid")
		}
		return nil

	default:
		return fmt.Errorf("unsupported signature algorithm: %q (supported: rsa-sha256, rsa-sha512, ecdsa-sha256, ecdsa-sha384)", algorithm)
	}
}

// applyTrustMode enforces the trust mode policy after a signature has been cryptographically
// verified. thumbprint is the certificate thumbprint embedded in the script signature (may
// be empty for signatures that carry only a raw public key).
func applyTrustMode(thumbprint string, cfg ModuleSigningConfig) error {
	switch cfg.TrustMode {
	case TrustModeAnyValid, "":
		// Any cryptographically valid signature is accepted; no key allowlist checked.
		return nil

	case TrustModeTrustedKeys:
		if isTrustedThumbprint(thumbprint, cfg.TrustedKeys) {
			return nil
		}
		return fmt.Errorf("%w: signing key thumbprint %q is not in the trusted keys allowlist", modules.ErrInvalidInput, thumbprint)

	case TrustModeTrustedKeysAndPublic:
		if isTrustedThumbprint(thumbprint, cfg.TrustedKeys) {
			return nil
		}
		if cfg.AllowPublicCA {
			// The script was signed by a key not in the allowlist, but AllowPublicCA
			// permits any signature that was already cryptographically valid.
			return nil
		}
		return fmt.Errorf("%w: signing key thumbprint %q is not in the trusted keys allowlist and allow_public_ca is false", modules.ErrInvalidInput, thumbprint)

	default:
		return fmt.Errorf("%w: unknown trust mode: %q", modules.ErrInvalidInput, cfg.TrustMode)
	}
}

// isTrustedThumbprint reports whether thumbprint matches any entry in trustedKeys.
// Comparison is case-insensitive to handle both upper- and lower-case hex representations.
func isTrustedThumbprint(thumbprint string, trustedKeys []TrustedKeyEntry) bool {
	if thumbprint == "" {
		return false
	}
	for _, tk := range trustedKeys {
		if tk.Thumbprint != "" && strings.EqualFold(thumbprint, tk.Thumbprint) {
			return true
		}
	}
	return false
}
