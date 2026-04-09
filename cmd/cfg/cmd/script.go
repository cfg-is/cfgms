// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// errNoSignatureFound is returned when the .sig file does not exist for a script.
var errNoSignatureFound = errors.New("no signature found")

// windowsAuthenticodeSigner is set by script_sign_windows.go on Windows builds.
// When set and the target file is a PowerShell script, signing delegates to
// Set-AuthenticodeSignature instead of creating a detached .sig file.
var windowsAuthenticodeSigner func(filePath string) error

// windowsAuthenticodeScriptVerifier is set by script_sign_windows.go on Windows builds.
// When set and the target file is a PowerShell script, verification delegates to
// Get-AuthenticodeSignature instead of reading a detached .sig file.
var windowsAuthenticodeScriptVerifier func(filePath string) error

// scriptCmd is the parent command for script signing and verification.
var scriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Sign and verify scripts",
	Long: `Sign scripts with a private key or verify detached signatures.

For PowerShell files (.ps1, .psm1, .psd1) on Windows, signing and verification
delegate to Authenticode (Set-AuthenticodeSignature / Get-AuthenticodeSignature).

For all other script types — and for PowerShell on non-Windows platforms —
a detached signature file is created alongside the script:

  script.sh     → source file
  script.sh.sig → raw DER signature bytes (RSA or ECDSA)

The detached .sig file contains raw cryptographic signature bytes (not base64).
Use the same --algorithm flag for both signing and verification.

Supported algorithms: rsa-sha256, rsa-sha384, rsa-sha512,
                      ecdsa-sha256, ecdsa-sha384, ecdsa-sha512

Exit codes:
  0  signature valid (verify) or signed successfully (sign)
  1  signature invalid, not found, or signing failed`,
}

func init() {
	scriptCmd.AddCommand(scriptSignCmd)
	scriptCmd.AddCommand(scriptVerifyCmd)
	rootCmd.AddCommand(scriptCmd)
}

// ---------------------------------------------------------------------------
// isPowerShellExt reports whether path has a PowerShell script extension.
// Comparison is case-insensitive to handle Windows file naming conventions.
// ---------------------------------------------------------------------------

func isPowerShellExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".ps1" || ext == ".psm1" || ext == ".psd1"
}

// ---------------------------------------------------------------------------
// loadPrivateKey reads and parses a PEM-encoded PKCS#8 private key from path.
// ---------------------------------------------------------------------------

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 — user-provided key path is intentional
	if err != nil {
		return nil, fmt.Errorf("read private key file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// loadPublicKey reads and parses a PEM-encoded PKIX public key from path.
// It also accepts PEM blocks containing X.509 certificates and extracts
// the embedded public key.
// ---------------------------------------------------------------------------

func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 — user-provided key path is intentional
	if err != nil {
		return nil, fmt.Errorf("read public key file %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	// Try PKIX SubjectPublicKeyInfo (standard raw public key format).
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pub, nil
	}

	// Fall back to X.509 certificate — extract the embedded public key.
	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr != nil {
		return nil, fmt.Errorf("unsupported key format (not PKIX SubjectPublicKeyInfo or X.509): %v", err)
	}
	return cert.PublicKey, nil
}

// ---------------------------------------------------------------------------
// hashContent hashes content using the digest component of the named algorithm.
// Returns the raw digest bytes.
// ---------------------------------------------------------------------------

func hashContent(content []byte, algorithm string) ([]byte, error) {
	switch strings.ToLower(algorithm) {
	case "rsa-sha256", "ecdsa-sha256":
		h := sha256.Sum256(content)
		return h[:], nil
	case "rsa-sha384", "ecdsa-sha384":
		h := sha512.Sum384(content)
		return h[:], nil
	case "rsa-sha512", "ecdsa-sha512":
		h := sha512.Sum512(content)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q (supported: rsa-sha256, rsa-sha384, rsa-sha512, ecdsa-sha256, ecdsa-sha384, ecdsa-sha512)", algorithm)
	}
}

// ---------------------------------------------------------------------------
// signScript signs filePath using the private key at keyPath and the named
// algorithm, writing raw DER signature bytes to filePath+".sig".
//
// On Windows, PowerShell scripts (.ps1/.psm1/.psd1) delegate to
// windowsAuthenticodeSigner when it is set.
// ---------------------------------------------------------------------------

func signScript(filePath, keyPath, algorithm string) error {
	content, err := os.ReadFile(filePath) // #nosec G304 — user-provided script path is intentional
	if err != nil {
		return fmt.Errorf("read script %q: %w", filePath, err)
	}

	// Delegate PowerShell files to Authenticode on Windows builds.
	if windowsAuthenticodeSigner != nil && isPowerShellExt(filePath) {
		return windowsAuthenticodeSigner(filePath)
	}

	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	digest, err := hashContent(content, algorithm)
	if err != nil {
		return err
	}

	sigBytes, err := signDigest(digest, privKey, algorithm)
	if err != nil {
		return err
	}

	sigPath := filePath + ".sig"
	if err := os.WriteFile(sigPath, sigBytes, 0600); err != nil {
		return fmt.Errorf("write signature file %q: %w", sigPath, err)
	}
	return nil
}

// signDigest signs the pre-computed digest with the private key using the
// named algorithm. Returns raw DER-encoded signature bytes.
func signDigest(digest []byte, privKey crypto.PrivateKey, algorithm string) ([]byte, error) {
	algo := strings.ToLower(algorithm)
	switch {
	case strings.HasPrefix(algo, "rsa-"):
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key mismatch: algorithm %q requires an RSA private key, got %T", algorithm, privKey)
		}
		return signRSADigest(rsaKey, digest, algo)

	case strings.HasPrefix(algo, "ecdsa-"):
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key mismatch: algorithm %q requires an ECDSA private key, got %T", algorithm, privKey)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest)
		if err != nil {
			return nil, fmt.Errorf("ECDSA sign: %w", err)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func signRSADigest(key *rsa.PrivateKey, digest []byte, algo string) ([]byte, error) {
	var hashID crypto.Hash
	switch algo {
	case "rsa-sha256":
		hashID = crypto.SHA256
	case "rsa-sha384":
		hashID = crypto.SHA384
	case "rsa-sha512":
		hashID = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm %q", algo)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hashID, digest)
	if err != nil {
		return nil, fmt.Errorf("RSA sign: %w", err)
	}
	return sig, nil
}

// ---------------------------------------------------------------------------
// verifyScript verifies the detached signature for filePath using the public
// key at pubKeyPath and the named algorithm.
//
// Returns nil on success, errNoSignatureFound when the .sig file is absent,
// or a descriptive error when verification fails.
//
// On Windows, PowerShell scripts (.ps1/.psm1/.psd1) delegate to
// windowsAuthenticodeScriptVerifier when it is set.
// ---------------------------------------------------------------------------

func verifyScript(filePath, pubKeyPath, algorithm string) error {
	content, err := os.ReadFile(filePath) // #nosec G304 — user-provided script path is intentional
	if err != nil {
		return fmt.Errorf("read script %q: %w", filePath, err)
	}

	// Delegate PowerShell files to Authenticode on Windows builds.
	if windowsAuthenticodeScriptVerifier != nil && isPowerShellExt(filePath) {
		return windowsAuthenticodeScriptVerifier(filePath)
	}

	sigPath := filePath + ".sig"
	sigBytes, err := os.ReadFile(sigPath) // #nosec G304 — derived from user-provided path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errNoSignatureFound
		}
		return fmt.Errorf("read signature file %q: %w", sigPath, err)
	}

	pubKey, err := loadPublicKey(pubKeyPath)
	if err != nil {
		return err
	}

	digest, err := hashContent(content, algorithm)
	if err != nil {
		return err
	}

	if err := verifySigBytes(digest, sigBytes, pubKey, algorithm); err != nil {
		return fmt.Errorf("signature invalid — tampered: %w", err)
	}
	return nil
}

// verifySigBytes verifies that sigBytes is a valid signature over digest using
// pubKey and the named algorithm.
func verifySigBytes(digest, sigBytes []byte, pubKey crypto.PublicKey, algorithm string) error {
	algo := strings.ToLower(algorithm)
	switch {
	case strings.HasPrefix(algo, "rsa-"):
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("key mismatch: algorithm %q requires an RSA public key, got %T", algorithm, pubKey)
		}
		return verifyRSASig(rsaPub, digest, sigBytes, algo)

	case strings.HasPrefix(algo, "ecdsa-"):
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("key mismatch: algorithm %q requires an ECDSA public key, got %T", algorithm, pubKey)
		}
		if !ecdsa.VerifyASN1(ecPub, digest, sigBytes) {
			return fmt.Errorf("ECDSA signature is not valid")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func verifyRSASig(pub *rsa.PublicKey, digest, sigBytes []byte, algo string) error {
	var hashID crypto.Hash
	switch algo {
	case "rsa-sha256":
		hashID = crypto.SHA256
	case "rsa-sha384":
		hashID = crypto.SHA384
	case "rsa-sha512":
		hashID = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm %q", algo)
	}
	return rsa.VerifyPKCS1v15(pub, hashID, digest, sigBytes)
}

// ---------------------------------------------------------------------------
// escapePSPath escapes a file path for safe embedding in a PowerShell string
// literal delimited by single quotes. Single quotes within the path are doubled.
// This is defined here (not in script_sign_windows.go) so it can be tested
// on all platforms.
// ---------------------------------------------------------------------------

func escapePSPath(path string) string {
	return strings.ReplaceAll(path, "'", "''")
}
