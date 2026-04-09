// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Test key generation helpers
// ---------------------------------------------------------------------------

func testGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func testGenECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

func writePrivKeyPEM(t *testing.T, dir string, key crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

func writePubKeyPEM(t *testing.T, dir string, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

func writeScriptFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write script file: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Sign + Verify round-trip tests
// ---------------------------------------------------------------------------

func TestSignVerifyRoundTrip_RSA_SHA256(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	sigPath := scriptPath + ".sig"
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("expected .sig file to exist: %v", err)
	}

	if err := verifyScript(scriptPath, pubPath, "rsa-sha256"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

func TestSignVerifyRoundTrip_RSA_SHA512(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "deploy.sh", "#!/bin/sh\n./deploy.sh\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha512"); err != nil {
		t.Fatalf("signScript: %v", err)
	}
	if err := verifyScript(scriptPath, pubPath, "rsa-sha512"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

func TestSignVerifyRoundTrip_RSA_SHA384(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "test.sh", "#!/bin/bash\ndate\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha384"); err != nil {
		t.Fatalf("signScript: %v", err)
	}
	if err := verifyScript(scriptPath, pubPath, "rsa-sha384"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

func TestSignVerifyRoundTrip_ECDSA_SHA256(t *testing.T) {
	dir := t.TempDir()
	key := testGenECDSAKey(t, elliptic.P256())
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho ecdsa\n")

	if err := signScript(scriptPath, keyPath, "ecdsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}
	if err := verifyScript(scriptPath, pubPath, "ecdsa-sha256"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

func TestSignVerifyRoundTrip_ECDSA_SHA384(t *testing.T) {
	dir := t.TempDir()
	key := testGenECDSAKey(t, elliptic.P384())
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho p384\n")

	if err := signScript(scriptPath, keyPath, "ecdsa-sha384"); err != nil {
		t.Fatalf("signScript: %v", err)
	}
	if err := verifyScript(scriptPath, pubPath, "ecdsa-sha384"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

func TestSignVerifyRoundTrip_ECDSA_SHA512(t *testing.T) {
	dir := t.TempDir()
	key := testGenECDSAKey(t, elliptic.P521())
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho p521\n")

	if err := signScript(scriptPath, keyPath, "ecdsa-sha512"); err != nil {
		t.Fatalf("signScript: %v", err)
	}
	if err := verifyScript(scriptPath, pubPath, "ecdsa-sha512"); err != nil {
		t.Errorf("verifyScript: expected valid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

func TestVerify_TamperedContent_Rejected(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	// Tamper with the script after signing
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\nrm -rf /\n"), 0600); err != nil {
		t.Fatalf("tamper script: %v", err)
	}

	err := verifyScript(scriptPath, pubPath, "rsa-sha256")
	if err == nil {
		t.Error("expected tampered content to fail verification, but it passed")
	}
}

// ---------------------------------------------------------------------------
// Missing signature file
// ---------------------------------------------------------------------------

func TestVerify_MissingSignatureFile(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")
	// Do not create .sig file

	err := verifyScript(scriptPath, pubPath, "rsa-sha256")
	if err == nil {
		t.Error("expected error for missing .sig file, but got nil")
	}
	if !errors.Is(err, errNoSignatureFound) {
		t.Errorf("expected errNoSignatureFound, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Wrong key (key mismatch)
// ---------------------------------------------------------------------------

func TestVerify_WrongPublicKey_Rejected(t *testing.T) {
	dir := t.TempDir()
	signingKey := testGenRSAKey(t)
	wrongKey := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, signingKey)
	wrongPubPath := writePubKeyPEM(t, dir, &wrongKey.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	err := verifyScript(scriptPath, wrongPubPath, "rsa-sha256")
	if err == nil {
		t.Error("expected wrong key to fail verification, but it passed")
	}
}

// ---------------------------------------------------------------------------
// Invalid inputs
// ---------------------------------------------------------------------------

func TestSign_MissingScriptFile(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)

	err := signScript(filepath.Join(dir, "nonexistent.sh"), keyPath, "rsa-sha256")
	if err == nil {
		t.Error("expected error for missing script file")
	}
}

func TestSign_InvalidPrivateKey(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")
	badKeyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badKeyPath, []byte("not-a-pem"), 0600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}

	err := signScript(scriptPath, badKeyPath, "rsa-sha256")
	if err == nil {
		t.Error("expected error for invalid private key")
	}
}

func TestSign_UnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	err := signScript(scriptPath, keyPath, "md5-rsa")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	badPubPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPubPath, []byte("not-a-pem"), 0600); err != nil {
		t.Fatalf("write bad pubkey: %v", err)
	}

	err := verifyScript(scriptPath, badPubPath, "rsa-sha256")
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestVerify_KeyTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	rsaKey := testGenRSAKey(t)
	ecKey := testGenECDSAKey(t, elliptic.P256())
	keyPath := writePrivKeyPEM(t, dir, rsaKey)
	ecPubPath := writePubKeyPEM(t, dir, &ecKey.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	// Sign with RSA
	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	// Verify with ECDSA key + RSA algorithm — should fail
	err := verifyScript(scriptPath, ecPubPath, "rsa-sha256")
	if err == nil {
		t.Error("expected key type mismatch to fail, but it passed")
	}
}

// ---------------------------------------------------------------------------
// runScriptVerify handler tests (cobra-layer validation)
// ---------------------------------------------------------------------------

func TestRunScriptSign_MissingKey_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	origKey := scriptSignKey
	origAlgo := scriptSignAlgorithm
	t.Cleanup(func() {
		scriptSignKey = origKey
		scriptSignAlgorithm = origAlgo
	})
	scriptSignKey = ""
	scriptSignAlgorithm = "rsa-sha256"

	err := runScriptSign(scriptSignCmd, []string{scriptPath})
	if err == nil {
		t.Error("expected error when --key is missing for non-Authenticode path")
	}
}

func TestRunScriptVerify_MissingPubkey_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	// Simulate runScriptVerify with empty pubkey
	origPubKey := scriptVerifyPubKey
	origAlgo := scriptVerifyAlgorithm
	t.Cleanup(func() {
		scriptVerifyPubKey = origPubKey
		scriptVerifyAlgorithm = origAlgo
	})
	scriptVerifyPubKey = ""
	scriptVerifyAlgorithm = "rsa-sha256"

	err := runScriptVerify(scriptVerifyCmd, []string{scriptPath})
	if err == nil {
		t.Error("expected error when --pubkey is missing")
	}
}

func TestRunScriptVerify_ValidSignature_ReturnsNil(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	if err := signScript(scriptPath, keyPath, "rsa-sha256"); err != nil {
		t.Fatalf("signScript: %v", err)
	}

	origPubKey := scriptVerifyPubKey
	origAlgo := scriptVerifyAlgorithm
	t.Cleanup(func() {
		scriptVerifyPubKey = origPubKey
		scriptVerifyAlgorithm = origAlgo
	})
	scriptVerifyPubKey = pubPath
	scriptVerifyAlgorithm = "rsa-sha256"

	if err := runScriptVerify(scriptVerifyCmd, []string{scriptPath}); err != nil {
		t.Errorf("runScriptVerify: expected nil, got: %v", err)
	}
}

func TestRunScriptVerify_NoSignatureFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)
	scriptPath := writeScriptFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	origPubKey := scriptVerifyPubKey
	origAlgo := scriptVerifyAlgorithm
	t.Cleanup(func() {
		scriptVerifyPubKey = origPubKey
		scriptVerifyAlgorithm = origAlgo
	})
	scriptVerifyPubKey = pubPath
	scriptVerifyAlgorithm = "rsa-sha256"

	err := runScriptVerify(scriptVerifyCmd, []string{scriptPath})
	if err == nil {
		t.Error("expected error for missing .sig file")
	}
}

// ---------------------------------------------------------------------------
// signDigest unsupported algorithm branch
// ---------------------------------------------------------------------------

func TestSignDigest_UnsupportedAlgorithm_ReturnsError(t *testing.T) {
	key := testGenRSAKey(t)
	digest := []byte("fake digest bytes")
	_, err := signDigest(digest, key, "des-cbc")
	if err == nil {
		t.Error("expected error for unsupported algorithm in signDigest")
	}
}

// ---------------------------------------------------------------------------
// verifySigBytes unsupported algorithm branch
// ---------------------------------------------------------------------------

func TestVerifySigBytes_UnsupportedAlgorithm_ReturnsError(t *testing.T) {
	key := testGenRSAKey(t)
	digest := []byte("fake digest bytes")
	sigBytes := []byte("fake sig bytes")
	err := verifySigBytes(digest, sigBytes, &key.PublicKey, "des-cbc")
	if err == nil {
		t.Error("expected error for unsupported algorithm in verifySigBytes")
	}
}

// ---------------------------------------------------------------------------
// verifyRSASig unsupported RSA algorithm branch
// ---------------------------------------------------------------------------

func TestVerifyRSASig_UnsupportedAlgorithm_ReturnsError(t *testing.T) {
	key := testGenRSAKey(t)
	digest := []byte("fake digest bytes")
	sigBytes := []byte("fake sig bytes")
	err := verifyRSASig(&key.PublicKey, digest, sigBytes, "rsa-md5")
	if err == nil {
		t.Error("expected error for unsupported RSA algorithm in verifyRSASig")
	}
}

// ---------------------------------------------------------------------------
// signRSADigest unsupported RSA algorithm branch
// ---------------------------------------------------------------------------

func TestSignRSADigest_UnsupportedAlgorithm_ReturnsError(t *testing.T) {
	key := testGenRSAKey(t)
	digest := []byte("fake digest bytes")
	_, err := signRSADigest(key, digest, "rsa-md5")
	if err == nil {
		t.Error("expected error for unsupported RSA algorithm in signRSADigest")
	}
}

// ---------------------------------------------------------------------------
// isPowerShellExt helper
// ---------------------------------------------------------------------------

func TestIsPowerShellExt(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"script.ps1", true},
		{"module.psm1", true},
		{"manifest.psd1", true},
		{"script.sh", false},
		{"script.py", false},
		{"script.PS1", true}, // case-insensitive
	}
	for _, tt := range tests {
		got := isPowerShellExt(tt.path)
		if got != tt.want {
			t.Errorf("isPowerShellExt(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// hashContent helper
// ---------------------------------------------------------------------------

func TestHashContent_RSA_SHA256(t *testing.T) {
	content := []byte("hello world")
	h, err := hashContent(content, "rsa-sha256")
	if err != nil {
		t.Fatalf("hashContent: %v", err)
	}
	expected := sha256.Sum256(content)
	if string(h) != string(expected[:]) {
		t.Error("rsa-sha256 hash mismatch")
	}
}

func TestHashContent_ECDSA_SHA384(t *testing.T) {
	content := []byte("hello world")
	h, err := hashContent(content, "ecdsa-sha384")
	if err != nil {
		t.Fatalf("hashContent: %v", err)
	}
	expected := sha512.Sum384(content)
	if string(h) != string(expected[:]) {
		t.Error("ecdsa-sha384 hash mismatch")
	}
}

func TestHashContent_UnsupportedAlgorithm(t *testing.T) {
	_, err := hashContent([]byte("content"), "des-sha1")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// ---------------------------------------------------------------------------
// loadPrivateKey helper
// ---------------------------------------------------------------------------

func TestLoadPrivateKey_RSA(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	keyPath := writePrivKeyPEM(t, dir, key)

	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}
	if _, ok := priv.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", priv)
	}
}

func TestLoadPrivateKey_ECDSA(t *testing.T) {
	dir := t.TempDir()
	key := testGenECDSAKey(t, elliptic.P256())
	keyPath := writePrivKeyPEM(t, dir, key)

	priv, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadPrivateKey: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", priv)
	}
}

func TestLoadPrivateKey_NoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not pem content"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := loadPrivateKey(path)
	if err == nil {
		t.Error("expected error for non-PEM content")
	}
}

// ---------------------------------------------------------------------------
// loadPublicKey helper
// ---------------------------------------------------------------------------

func TestLoadPublicKey_RSA(t *testing.T) {
	dir := t.TempDir()
	key := testGenRSAKey(t)
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)

	pub, err := loadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestLoadPublicKey_ECDSA(t *testing.T) {
	dir := t.TempDir()
	key := testGenECDSAKey(t, elliptic.P256())
	pubPath := writePubKeyPEM(t, dir, &key.PublicKey)

	pub, err := loadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("loadPublicKey: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestLoadPublicKey_NoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not pem content"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := loadPublicKey(path)
	if err == nil {
		t.Error("expected error for non-PEM content in loadPublicKey")
	}
}

// ---------------------------------------------------------------------------
// escapePSPath (security-critical: prevents PowerShell injection)
// ---------------------------------------------------------------------------

func TestEscapePSPath_NoQuotes(t *testing.T) {
	input := `C:\Users\agent\script.ps1`
	got := escapePSPath(input)
	if got != input {
		t.Errorf("escapePSPath(%q) = %q, want unchanged", input, got)
	}
}

func TestEscapePSPath_SingleQuoteDoubled(t *testing.T) {
	input := `C:\Users\o'brien\script.ps1`
	want := `C:\Users\o''brien\script.ps1`
	got := escapePSPath(input)
	if got != want {
		t.Errorf("escapePSPath(%q) = %q, want %q", input, got, want)
	}
}

func TestEscapePSPath_MultipleQuotes(t *testing.T) {
	input := `it's a 'test' path`
	want := `it''s a ''test'' path`
	got := escapePSPath(input)
	if got != want {
		t.Errorf("escapePSPath(%q) = %q, want %q", input, got, want)
	}
}

func TestEscapePSPath_EmptyString(t *testing.T) {
	got := escapePSPath("")
	if got != "" {
		t.Errorf("escapePSPath(%q) = %q, want empty", "", got)
	}
}
