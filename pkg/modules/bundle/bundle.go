// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package bundle defines the CFGMS module bundle format, content addressing,
// and serialization.
//
// # Signing scheme: Ed25519 detached signatures
//
// Each bundle carries one or more BundleSignature values. Signatures use
// Ed25519 (RFC 8032) with a detached 64-byte signature over the bundle's
// ContentHash bytes encoded as UTF-8.
//
// Rationale for Ed25519:
//   - No external CA dependency — publisher identity is a raw 32-byte public key
//   - Deterministic — same message + key → same signature (unlike ECDSA without RFC 6979)
//   - Compact — 64-byte signature and 32-byte public key
//   - Fast verify — ~70k verifications/second on modest hardware
//   - stdlib — crypto/ed25519 ships with every Go release; zero external deps
//
// One scheme for v1. cosign/minisign can be added as additional verifiers in a
// future story without changing the bundle format — the Signatures slice accepts
// multiple entries, each tagged with an Algorithm field.
package bundle

import (
	modules "github.com/cfgis/cfgms/features/modules"
)

// BundleSignature is a detached Ed25519 signature over the bundle's ContentHash.
//
// Signature is a 64-byte Ed25519 signature over the UTF-8 encoding of
// Bundle.ContentHash. Publisher must match a PublisherIdentity registered in
// the TrustStore at verification time.
type BundleSignature struct {
	Publisher string `yaml:"publisher" json:"publisher"`
	// Algorithm is always "ed25519" for v1 bundles.
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	// Signature is the raw 64-byte Ed25519 signature bytes.
	Signature []byte `yaml:"signature" json:"signature"`
}

// Bundle is the top-level artifact exchanged between the controller cache and
// the steward. It carries a module manifest, OS/arch-keyed binary paths, one or
// more publisher signatures, and a deterministic content hash.
//
// Binaries maps os-arch keys (e.g. "linux-amd64", "windows-amd64") to the file
// path of the corresponding contract binary. Paths are relative to the bundle
// root directory.
type Bundle struct {
	Manifest    *modules.ModuleMetadata `yaml:"manifest" json:"manifest"`
	Binaries    map[string]string       `yaml:"binaries" json:"binaries"`
	Signatures  []BundleSignature       `yaml:"signatures,omitempty" json:"signatures,omitempty"`
	ContentHash string                  `yaml:"content_hash" json:"content_hash"`
}

// ContentAddress returns the (publisher, name, version, content_hash) tuple
// that uniquely identifies this bundle.
func (b *Bundle) ContentAddress() ContentAddress {
	publisher := ""
	name := ""
	version := ""
	if b.Manifest != nil {
		publisher = b.Manifest.Publisher
		name = b.Manifest.Name
		version = b.Manifest.Version
	}
	return ContentAddress{
		Publisher:   publisher,
		Name:        name,
		Version:     version,
		ContentHash: b.ContentHash,
	}
}
