// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// ---------------------------------------------------------------------------
// Test key generation helpers
// ---------------------------------------------------------------------------

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generateRSAKey: %v", err)
	}
	return key
}

func rsaPublicKeyPEM(key *rsa.PrivateKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
}

func signRSASHA256(t *testing.T, key *rsa.PrivateKey, content []byte) string {
	t.Helper()
	h := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("signRSASHA256: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func signRSASHA512(t *testing.T, key *rsa.PrivateKey, content []byte) string {
	t.Helper()
	h := sha512.Sum512(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
	if err != nil {
		t.Fatalf("signRSASHA512: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func generateECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generateECDSAKey: %v", err)
	}
	return key
}

func ecdsaPublicKeyPEM(key *ecdsa.PrivateKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
}

func signECDSASHA256(t *testing.T, key *ecdsa.PrivateKey, content []byte) string {
	t.Helper()
	h := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("signECDSASHA256: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func signECDSASHA384(t *testing.T, key *ecdsa.PrivateKey, content []byte) string {
	t.Helper()
	h := sha512.Sum384(content)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("signECDSASHA384: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// ---------------------------------------------------------------------------
// verifyDetachedSignature — algorithm correctness
// ---------------------------------------------------------------------------

func TestVerifyDetachedSignature_RSA_SHA256_Valid(t *testing.T) {
	key := generateRSAKey(t)
	content := []byte("#!/bin/bash\necho hello")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, content),
		PublicKey: rsaPublicKeyPEM(key),
	}

	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err != nil {
		t.Errorf("expected valid signature to pass: %v", err)
	}
}

func TestVerifyDetachedSignature_RSA_SHA512_Valid(t *testing.T) {
	key := generateRSAKey(t)
	content := []byte("#!/bin/bash\necho hello")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha512",
		Signature: signRSASHA512(t, key, content),
		PublicKey: rsaPublicKeyPEM(key),
	}

	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err != nil {
		t.Errorf("expected valid signature to pass: %v", err)
	}
}

func TestVerifyDetachedSignature_ECDSA_SHA256_Valid(t *testing.T) {
	key := generateECDSAKey(t, elliptic.P256())
	content := []byte("#!/bin/bash\necho hello")
	sig := &ScriptSignature{
		Algorithm: "ecdsa-sha256",
		Signature: signECDSASHA256(t, key, content),
		PublicKey: ecdsaPublicKeyPEM(key),
	}

	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err != nil {
		t.Errorf("expected valid signature to pass: %v", err)
	}
}

func TestVerifyDetachedSignature_ECDSA_SHA384_Valid(t *testing.T) {
	key := generateECDSAKey(t, elliptic.P384())
	content := []byte("#!/bin/bash\necho hello")
	sig := &ScriptSignature{
		Algorithm: "ecdsa-sha384",
		Signature: signECDSASHA384(t, key, content),
		PublicKey: ecdsaPublicKeyPEM(key),
	}

	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err != nil {
		t.Errorf("expected valid signature to pass: %v", err)
	}
}

// ---------------------------------------------------------------------------
// verifyDetachedSignature — tamper detection
// ---------------------------------------------------------------------------

func TestVerifyDetachedSignature_TamperedContent_Rejected(t *testing.T) {
	key := generateRSAKey(t)
	original := []byte("#!/bin/bash\necho hello")
	tampered := []byte("#!/bin/bash\nrm -rf /")

	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, original),
		PublicKey: rsaPublicKeyPEM(key),
	}

	if err := verifyDetachedSignature(tampered, sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected tampered content to fail verification, but it passed")
	}
}

func TestVerifyDetachedSignature_WrongKey_Rejected(t *testing.T) {
	signingKey := generateRSAKey(t)
	otherKey := generateRSAKey(t)
	content := []byte("#!/bin/bash\necho hello")

	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, signingKey, content),
		PublicKey: rsaPublicKeyPEM(otherKey), // wrong key
	}

	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected wrong key to fail verification, but it passed")
	}
}

// ---------------------------------------------------------------------------
// verifyDetachedSignature — input validation
// ---------------------------------------------------------------------------

func TestVerifyDetachedSignature_NilSignature(t *testing.T) {
	if err := verifyDetachedSignature([]byte("content"), nil, ModuleSigningConfig{}); err == nil {
		t.Error("expected nil signature to fail, but it passed")
	}
}

func TestVerifyDetachedSignature_MissingPublicKey(t *testing.T) {
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: "AAAA",
		PublicKey: "",
	}
	if err := verifyDetachedSignature([]byte("content"), sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected missing public key to fail, but it passed")
	}
}

func TestVerifyDetachedSignature_InvalidBase64(t *testing.T) {
	key := generateRSAKey(t)
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: "not-valid-base64!!!",
		PublicKey: rsaPublicKeyPEM(key),
	}
	if err := verifyDetachedSignature([]byte("content"), sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected invalid base64 to fail, but it passed")
	}
}

func TestVerifyDetachedSignature_UnsupportedAlgorithm(t *testing.T) {
	key := generateRSAKey(t)
	content := []byte("content")
	sig := &ScriptSignature{
		Algorithm: "md5-rsa", // unsupported
		Signature: signRSASHA256(t, key, content),
		PublicKey: rsaPublicKeyPEM(key),
	}
	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected unsupported algorithm to fail, but it passed")
	}
}

func TestVerifyDetachedSignature_InvalidPEMKey(t *testing.T) {
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: base64.StdEncoding.EncodeToString([]byte("fakesig")),
		PublicKey: "not-a-pem-key",
	}
	if err := verifyDetachedSignature([]byte("content"), sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected invalid PEM to fail, but it passed")
	}
}

func TestVerifyDetachedSignature_KeyTypeMismatch_ECDSA_RSAAlgo(t *testing.T) {
	// Provide an ECDSA key but request RSA algorithm — should fail.
	key := generateECDSAKey(t, elliptic.P256())
	content := []byte("content")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signECDSASHA256(t, key, content),
		PublicKey: ecdsaPublicKeyPEM(key),
	}
	if err := verifyDetachedSignature(content, sig, ModuleSigningConfig{}); err == nil {
		t.Error("expected key type mismatch to fail, but it passed")
	}
}

// ---------------------------------------------------------------------------
// applyTrustMode
// ---------------------------------------------------------------------------

func TestApplyTrustMode_AnyValid_NoThumbprint(t *testing.T) {
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}
	if err := applyTrustMode("", cfg); err != nil {
		t.Errorf("any_valid should accept empty thumbprint: %v", err)
	}
}

func TestApplyTrustMode_AnyValid_WithThumbprint(t *testing.T) {
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}
	if err := applyTrustMode("AABBCCDD", cfg); err != nil {
		t.Errorf("any_valid should accept any thumbprint: %v", err)
	}
}

func TestApplyTrustMode_ZeroValue_ActsAsAnyValid(t *testing.T) {
	// Zero value of ModuleSigningConfig should behave as any_valid.
	if err := applyTrustMode("anything", ModuleSigningConfig{}); err != nil {
		t.Errorf("zero-value config should act as any_valid: %v", err)
	}
}

func TestApplyTrustMode_TrustedKeys_MatchingThumbprint(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
	}
	if err := applyTrustMode("AABBCCDD", cfg); err != nil {
		t.Errorf("matching thumbprint should pass trusted_keys: %v", err)
	}
}

func TestApplyTrustMode_TrustedKeys_CaseInsensitiveMatch(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "aabbccdd"},
		},
	}
	// Signature uses uppercase thumbprint; allowlist uses lowercase.
	if err := applyTrustMode("AABBCCDD", cfg); err != nil {
		t.Errorf("thumbprint match should be case-insensitive: %v", err)
	}
}

func TestApplyTrustMode_TrustedKeys_NonMatchingThumbprint(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
	}
	if err := applyTrustMode("11223344", cfg); err == nil {
		t.Error("non-matching thumbprint should fail trusted_keys")
	}
}

func TestApplyTrustMode_TrustedKeys_EmptyThumbprint_Rejected(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
	}
	// Signature has no thumbprint; cannot match allowlist.
	if err := applyTrustMode("", cfg); err == nil {
		t.Error("empty thumbprint should fail trusted_keys when allowlist is non-empty")
	}
}

func TestApplyTrustMode_TrustedKeys_EmptyAllowlist_Rejected(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode:   TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{}, // no entries
	}
	if err := applyTrustMode("AABBCCDD", cfg); err == nil {
		t.Error("non-empty thumbprint against empty allowlist should fail trusted_keys")
	}
}

func TestApplyTrustMode_TrustedKeysAndPublic_MatchingThumbprint(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeysAndPublic,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
		AllowPublicCA: false,
	}
	if err := applyTrustMode("AABBCCDD", cfg); err != nil {
		t.Errorf("matching trusted key should pass trusted_keys_and_public: %v", err)
	}
}

func TestApplyTrustMode_TrustedKeysAndPublic_NoMatchAllowPublicCA(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode:   TrustModeTrustedKeysAndPublic,
		TrustedKeys: []TrustedKeyEntry{{Name: "corp-cert", Thumbprint: "AABBCCDD"}},
		AllowPublicCA: true,
	}
	// Thumbprint doesn't match the allowlist but AllowPublicCA permits it.
	if err := applyTrustMode("99887766", cfg); err != nil {
		t.Errorf("AllowPublicCA=true should accept non-allowlisted key: %v", err)
	}
}

func TestApplyTrustMode_TrustedKeysAndPublic_NoMatchPublicCAFalse(t *testing.T) {
	cfg := ModuleSigningConfig{
		TrustMode:   TrustModeTrustedKeysAndPublic,
		TrustedKeys: []TrustedKeyEntry{{Name: "corp-cert", Thumbprint: "AABBCCDD"}},
		AllowPublicCA: false,
	}
	if err := applyTrustMode("99887766", cfg); err == nil {
		t.Error("AllowPublicCA=false with non-allowlisted key should fail")
	}
}

func TestApplyTrustMode_UnknownMode_Rejected(t *testing.T) {
	cfg := ModuleSigningConfig{TrustMode: TrustMode("bad_mode")}
	if err := applyTrustMode("AABBCCDD", cfg); err == nil {
		t.Error("unknown trust mode should fail")
	}
}

// ---------------------------------------------------------------------------
// Module.verifySignature — integration with ModuleSigningConfig
// ---------------------------------------------------------------------------

func TestModuleVerifySignature_AnyValid_Passes(t *testing.T) {
	mod := NewModule()
	mod.SetSigningConfig(ModuleSigningConfig{TrustMode: TrustModeAnyValid})

	key := generateRSAKey(t)
	content := "#!/bin/bash\necho hello"
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, []byte(content)),
		PublicKey: rsaPublicKeyPEM(key),
	}

	cfg := &ScriptConfig{
		Content:       content,
		Shell:         ShellBash,
		SigningPolicy: SigningPolicyRequired,
		Signature:     sig,
	}

	if err := mod.verifySignature(cfg); err != nil {
		t.Errorf("valid signature with any_valid mode should pass: %v", err)
	}
}

func TestModuleVerifySignature_TrustedKeys_MatchingThumbprint_Passes(t *testing.T) {
	mod := NewModule()
	mod.SetSigningConfig(ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
	})

	key := generateRSAKey(t)
	content := "#!/bin/bash\necho hello"
	sig := &ScriptSignature{
		Algorithm:  "rsa-sha256",
		Signature:  signRSASHA256(t, key, []byte(content)),
		PublicKey:  rsaPublicKeyPEM(key),
		Thumbprint: "AABBCCDD",
	}

	cfg := &ScriptConfig{
		Content:       content,
		Shell:         ShellBash,
		SigningPolicy: SigningPolicyRequired,
		Signature:     sig,
	}

	if err := mod.verifySignature(cfg); err != nil {
		t.Errorf("matching thumbprint with trusted_keys mode should pass: %v", err)
	}
}

func TestModuleVerifySignature_TrustedKeys_NonMatchingThumbprint_Fails(t *testing.T) {
	mod := NewModule()
	mod.SetSigningConfig(ModuleSigningConfig{
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyEntry{
			{Name: "corp-cert", Thumbprint: "AABBCCDD"},
		},
	})

	key := generateRSAKey(t)
	content := "#!/bin/bash\necho hello"
	sig := &ScriptSignature{
		Algorithm:  "rsa-sha256",
		Signature:  signRSASHA256(t, key, []byte(content)),
		PublicKey:  rsaPublicKeyPEM(key),
		Thumbprint: "not-trusted",
	}

	cfg := &ScriptConfig{
		Content:       content,
		Shell:         ShellBash,
		SigningPolicy: SigningPolicyRequired,
		Signature:     sig,
	}

	if err := mod.verifySignature(cfg); err == nil {
		t.Error("non-matching thumbprint with trusted_keys mode should fail")
	}
}

func TestModuleVerifySignature_TamperedContent_Fails(t *testing.T) {
	mod := NewModule()
	mod.SetSigningConfig(ModuleSigningConfig{TrustMode: TrustModeAnyValid})

	key := generateRSAKey(t)
	original := "#!/bin/bash\necho hello"
	tampered := "#!/bin/bash\nrm -rf /"

	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, []byte(original)),
		PublicKey: rsaPublicKeyPEM(key),
	}

	cfg := &ScriptConfig{
		Content:       tampered, // content was tampered after signing
		Shell:         ShellBash,
		SigningPolicy: SigningPolicyRequired,
		Signature:     sig,
	}

	if err := mod.verifySignature(cfg); err == nil {
		t.Error("tampered content should fail signature verification")
	}
}

func TestModuleVerifySignature_NilSignature_Fails(t *testing.T) {
	mod := NewModule()
	cfg := &ScriptConfig{
		Content:       "#!/bin/bash\necho hello",
		Shell:         ShellBash,
		SigningPolicy: SigningPolicyRequired,
		Signature:     nil,
	}

	if err := mod.verifySignature(cfg); err == nil {
		t.Error("nil signature should fail verifySignature")
	}
}

// ---------------------------------------------------------------------------
// verifyScriptSignature dispatch
// ---------------------------------------------------------------------------

func TestVerifyScriptSignature_NonPowerShell_UsesDetached(t *testing.T) {
	key := generateRSAKey(t)
	content := []byte("#!/bin/bash\necho hello")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, content),
		PublicKey: rsaPublicKeyPEM(key),
	}
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}

	// ShellBash is not PowerShell; always uses detached verification.
	if err := verifyScriptSignature(content, sig, ShellBash, cfg); err != nil {
		t.Errorf("bash script with valid signature should pass: %v", err)
	}
}

func TestVerifyScriptSignature_TamperedBashScript_Fails(t *testing.T) {
	key := generateRSAKey(t)
	original := []byte("#!/bin/bash\necho hello")
	tampered := []byte("#!/bin/bash\nrm -rf /")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, original),
		PublicKey: rsaPublicKeyPEM(key),
	}
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}

	if err := verifyScriptSignature(tampered, sig, ShellBash, cfg); err == nil {
		t.Error("tampered bash script should fail verification")
	}
}

// TestVerifyScriptSignature_PowerShell_FallsBackToDetached verifies that on non-Windows
// (where windowsAuthenticodeVerifier is nil), PowerShell scripts fall back to detached
// cryptographic signature verification rather than Authenticode.
func TestVerifyScriptSignature_PowerShell_FallsBackToDetached(t *testing.T) {
	if windowsAuthenticodeVerifier != nil {
		t.Skip("Authenticode verifier is registered — skipping detached-fallback test (Windows build)")
	}

	key := generateRSAKey(t)
	content := []byte("Write-Output 'hello'")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, content),
		PublicKey: rsaPublicKeyPEM(key),
	}
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}

	// On non-Windows, PowerShell scripts must pass detached signature verification.
	if err := verifyScriptSignature(content, sig, ShellPowerShell, cfg); err != nil {
		t.Errorf("PowerShell script with valid detached signature should pass on non-Windows: %v", err)
	}
}

func TestVerifyScriptSignature_PowerShell_TamperedContent_Fails(t *testing.T) {
	if windowsAuthenticodeVerifier != nil {
		t.Skip("Authenticode verifier is registered — skipping detached-fallback test (Windows build)")
	}

	key := generateRSAKey(t)
	original := []byte("Write-Output 'hello'")
	tampered := []byte("Remove-Item -Recurse -Force C:\\")
	sig := &ScriptSignature{
		Algorithm: "rsa-sha256",
		Signature: signRSASHA256(t, key, original),
		PublicKey: rsaPublicKeyPEM(key),
	}
	cfg := ModuleSigningConfig{TrustMode: TrustModeAnyValid}

	if err := verifyScriptSignature(tampered, sig, ShellPowerShell, cfg); err == nil {
		t.Error("tampered PowerShell script should fail detached verification on non-Windows")
	}
}

// ---------------------------------------------------------------------------
// isPowerShellScript
// ---------------------------------------------------------------------------

func TestIsPowerShellScript(t *testing.T) {
	tests := []struct {
		shell ShellType
		want  bool
	}{
		{ShellPowerShell, true},
		{ShellBash, false},
		{ShellSh, false},
		{ShellZsh, false},
		{ShellCmd, false},
		{ShellPython, false},
		{ShellPython3, false},
	}

	for _, tt := range tests {
		got := isPowerShellScript(tt.shell)
		if got != tt.want {
			t.Errorf("isPowerShellScript(%q) = %v, want %v", tt.shell, got, tt.want)
		}
	}
}
