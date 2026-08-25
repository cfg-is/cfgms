// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// platformKey is the os-arch bundle key for the machine running the tests.
func platformKey() string {
	return goruntime.GOOS + "-" + goruntime.GOARCH
}

// installOsqueryBundle writes a signed osquery bundle to a temp directory and
// returns the installation root, the bundle, and an enforcer whose CFGMS
// identity trusts the signing key.
func installOsqueryBundle(t *testing.T, binaryContent []byte) (string, *bundle.Bundle, *stewardtrust.StewardTrustEnforcer) {
	t.Helper()

	root := t.TempDir()

	manifestBytes, err := os.ReadFile("module.yaml")
	if err != nil {
		t.Fatalf("read module.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, bundle.ManifestFileName), manifestBytes, 0o600); err != nil {
		t.Fatalf("install manifest: %v", err)
	}

	key := platformKey()
	if err := os.MkdirAll(filepath.Join(root, "binaries"), 0o700); err != nil {
		t.Fatalf("mkdir binaries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "binaries", key), binaryContent, 0o600); err != nil {
		t.Fatalf("install binary: %v", err)
	}

	contentHash, err := bundle.ComputeContentHash(map[string][]byte{key: binaryContent}, manifestBytes)
	if err != nil {
		t.Fatalf("ComputeContentHash: %v", err)
	}

	b := &bundle.Bundle{
		Manifest: &modules.ModuleMetadata{
			Name:      "osquery",
			Version:   pinnedVersion,
			Publisher: "cfgms",
			Kind:      "steward",
			Executors: []string{"steward"},
		},
		Binaries:    map[string]string{key: "binaries/" + key},
		ContentHash: contentHash,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate publisher key: %v", err)
	}
	b.Signatures = append(b.Signatures, bundle.BundleSignature{
		Publisher: "cfgms",
		Algorithm: "ed25519",
		Signature: ed25519.Sign(priv, []byte(b.ContentHash)),
	})

	enforcer := stewardtrust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
		return pkgtrust.PublisherIdentity{Name: "cfgms", PublicKey: []byte(pub), Algorithm: "ed25519"}
	})

	return root, b, enforcer
}

func TestVerifyBeforeExec_SignedUntamperedBundlePasses(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("osquery-binary-content"))

	binPath, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeStrict, nil)
	if err != nil {
		t.Fatalf("VerifyBeforeExec rejected a signed, untampered bundle: %v", err)
	}

	want := filepath.Join(root, "binaries", platformKey())
	if binPath != want {
		t.Errorf("binary path = %q, want %q", binPath, want)
	}
}

// TestVerifyBeforeExec_TamperedBinaryIsRefused is the required test from issue
// #3561 AC: a binary whose on-disk hash doesn't match the signed manifest is
// refused execution, not run best-effort.
func TestVerifyBeforeExec_TamperedBinaryIsRefused(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("original-osquery-binary-content"))

	tampered := filepath.Join(root, "binaries", platformKey())
	if err := os.WriteFile(tampered, []byte("TAMPERED-binary-injected-by-attacker"), 0o600); err != nil {
		t.Fatalf("write tampered binary: %v", err)
	}

	binPath, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeStrict, nil)
	if err == nil {
		t.Fatal("VerifyBeforeExec accepted a tampered binary — it must be refused, not run best-effort")
	}
	if binPath != "" {
		t.Errorf("VerifyBeforeExec returned a binary path %q on failure — no path may be handed to a caller", binPath)
	}

	// The ADR-006 tuple must appear in the error so audit logs identify the bundle.
	errMsg := err.Error()
	for _, want := range []string{"cfgms", "osquery", pinnedVersion} {
		if !strings.Contains(errMsg, want) {
			t.Errorf("error message missing %q: %q", want, errMsg)
		}
	}
}

// TestVerifyBeforeExec_TamperedBinaryRefusedInControllerMode proves the on-disk
// re-check is not conditional on strict mode: controller mode skips the
// signature check (the controller already approved the bundle) but must still
// refuse a binary modified after installation.
func TestVerifyBeforeExec_TamperedBinaryRefusedInControllerMode(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("original-osquery-binary-content"))

	tampered := filepath.Join(root, "binaries", platformKey())
	if err := os.WriteFile(tampered, []byte("TAMPERED"), 0o600); err != nil {
		t.Fatalf("write tampered binary: %v", err)
	}

	for _, mode := range []stewardtrust.TrustMode{
		stewardtypes.ModuleTrustModeController,
		stewardtypes.ModuleTrustModeBypass,
	} {
		_, err := NewPreExecVerifierWithEnforcer(enforcer).VerifyBeforeExec(b, root, mode, nil)
		if err == nil {
			t.Errorf("mode %q accepted a tampered binary — the on-disk re-check must run in every trust mode", mode)
		}
	}
}

// TestVerifyBeforeExec_UnsignedBundleRefusedInStrictMode proves the expected
// hash is anchored in a publisher signature rather than a local unsigned
// manifest: with no signature there is nothing to trust and strict mode refuses.
func TestVerifyBeforeExec_UnsignedBundleRefusedInStrictMode(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("osquery-binary-content"))
	b.Signatures = nil

	_, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeStrict, nil)
	if err == nil {
		t.Fatal("VerifyBeforeExec accepted an unsigned bundle in strict mode")
	}
	if !strings.Contains(err.Error(), "trust verification failed") {
		t.Errorf("error should identify the trust gate as the failure point: %q", err)
	}
}

// TestVerifyBeforeExec_UntrustedPublisherRefused verifies that a valid signature
// from a publisher outside the trust store does not satisfy strict mode.
func TestVerifyBeforeExec_UntrustedPublisherRefused(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("osquery-binary-content"))

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	b.Signatures = []bundle.BundleSignature{{
		Publisher: "attacker",
		Algorithm: "ed25519",
		Signature: ed25519.Sign(attackerPriv, []byte(b.ContentHash)),
	}}

	if _, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeStrict, nil); err == nil {
		t.Fatal("VerifyBeforeExec accepted a bundle signed by an untrusted publisher")
	}
}

func TestVerifyBeforeExec_MissingBinaryIsRefused(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("osquery-binary-content"))

	if err := os.Remove(filepath.Join(root, "binaries", platformKey())); err != nil {
		t.Fatalf("remove binary: %v", err)
	}

	if _, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeStrict, nil); err == nil {
		t.Fatal("VerifyBeforeExec accepted a bundle whose binary is missing from disk")
	}
}

func TestVerifyBeforeExec_NoBinaryForPlatform(t *testing.T) {
	root, b, enforcer := installOsqueryBundle(t, []byte("osquery-binary-content"))

	// Re-key the bundle to a platform that is never the test host, keeping the
	// content hash consistent with what is on disk.
	manifestBytes, err := os.ReadFile(filepath.Join(root, bundle.ManifestFileName))
	if err != nil {
		t.Fatalf("read installed manifest: %v", err)
	}
	otherKey := "plan9-mips"
	if err := os.Rename(
		filepath.Join(root, "binaries", platformKey()),
		filepath.Join(root, "binaries", otherKey),
	); err != nil {
		t.Fatalf("rename binary: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "binaries", otherKey))
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	b.Binaries = map[string]string{otherKey: "binaries/" + otherKey}
	b.ContentHash, err = bundle.ComputeContentHash(map[string][]byte{otherKey: content}, manifestBytes)
	if err != nil {
		t.Fatalf("ComputeContentHash: %v", err)
	}

	if _, err := NewPreExecVerifierWithEnforcer(enforcer).
		VerifyBeforeExec(b, root, stewardtypes.ModuleTrustModeBypass, nil); err == nil {
		t.Fatal("VerifyBeforeExec accepted a bundle with no binary for the current platform")
	}
}

func TestVerifyBeforeExec_NilBundle(t *testing.T) {
	if _, err := NewPreExecVerifier().
		VerifyBeforeExec(nil, t.TempDir(), stewardtypes.ModuleTrustModeBypass, nil); err == nil {
		t.Fatal("VerifyBeforeExec accepted a nil bundle")
	}
}

// TestNewPreExecVerifier_UsesProductionEnforcer verifies the production
// constructor wires a usable enforcer rather than a nil one.
func TestNewPreExecVerifier_UsesProductionEnforcer(t *testing.T) {
	v := NewPreExecVerifier()
	if v == nil || v.enforcer == nil {
		t.Fatal("NewPreExecVerifier returned a verifier with no trust enforcer")
	}
}
