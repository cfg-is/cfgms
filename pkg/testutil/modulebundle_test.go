// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package testutil

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func verifyAgainst(t *testing.T, b *bundle.Bundle, pub ed25519.PublicKey) error {
	t.Helper()
	store := trust.NewInMemoryTrustStore()
	if err := store.AddPublisher(trust.PublisherIdentity{Name: b.Manifest.Publisher, PublicKey: pub, Algorithm: "ed25519"}); err != nil {
		t.Fatalf("add publisher: %v", err)
	}
	return trust.VerifyBundleSignature(b, b.Signatures[0], store)
}

func TestNewSignedBundle_VerifiesForAnyPublisherAndPlatformSet(t *testing.T) {
	sb := NewSignedBundle(t, BundleOptions{
		Publisher: "acme-corp",
		Name:      "widget",
		Version:   "2.3.4-rc.1",
		Platforms: []string{"linux-amd64", "windows-arm64"},
	})
	if sb.Manifest.Publisher != "acme-corp" || len(sb.Binaries) != 2 || len(sb.BinaryDigests) != 2 {
		t.Fatalf("unexpected bundle: %+v", sb.Bundle)
	}
	if sb.Binaries["windows-arm64"] != "cfgms-module-widget-windows-arm64.exe" {
		t.Fatalf("windows binary name = %q", sb.Binaries["windows-arm64"])
	}
	if err := verifyAgainst(t, sb.Bundle, sb.PublicKey); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestSignedBundle_WriteRootRoundTrips(t *testing.T) {
	sb := NewSignedBundle(t, BundleOptions{Publisher: "acme-corp", Platforms: []string{"linux-amd64", "darwin-arm64"}})
	root := filepath.Join(t.TempDir(), "root")
	sb.WriteRoot(t, root, bundle.WriteOptions{})

	got, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.ContentHash != sb.ContentHash {
		t.Fatalf("content hash %q != %q", got.ContentHash, sb.ContentHash)
	}
	if err := verifyAgainst(t, got, sb.PublicKey); err != nil {
		t.Fatalf("read-back bundle does not verify: %v", err)
	}
}

func TestSignedBundle_CommitToRepoProducesStrictReadableCheckout(t *testing.T) {
	sb := NewSignedBundle(t, BundleOptions{Publisher: "acme-corp"})
	repo := filepath.Join(t.TempDir(), "repo")
	commit := sb.CommitToRepo(t, repo)
	if len(commit) < 40 {
		t.Fatalf("commit id %q", commit)
	}
	got, err := bundle.ReadInstalledPayload(repo, bundle.ReadOptions{IgnoreNames: []string{".git"}})
	if err != nil {
		t.Fatalf("read repo checkout: %v", err)
	}
	if got.ContentHash != sb.ContentHash {
		t.Fatalf("content hash mismatch")
	}
	if _, err := bundle.ReadInstalledPayload(repo, bundle.ReadOptions{}); err == nil {
		t.Fatalf("strict read without IgnoreNames must refuse .git")
	}
}
