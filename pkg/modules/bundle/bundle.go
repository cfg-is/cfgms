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
// # Payload, digests and the one layout
//
// A bundle's content hash is ComputeContentHashFromDigests over the manifest
// bytes and the SHA-256 digest of every platform's binary. Bundle.BinaryDigests
// carries that FULL digest list (hex, per os-arch key) and is persisted in the
// bundle.yaml sidecar, so a holder of the digests can recompute the hash and a
// reader can verify a root holding only one platform's binary.
//
// A bundle exists in two forms. The installed form (ReadInstalled,
// DiscoverInstalled) is metadata only. The payload form (Assemble,
// ReadInstalledPayload) also carries ManifestBytes and BinaryContent in memory;
// those fields are never serialized.
//
// This package is the single place that builds (Assemble), signs (Sign), writes
// (WriteInstalled) and reads (ReadInstalledPayload, ReadInstalled) the
// installation-root layout, for any publisher:
//
//	<root>/module.yaml   the publisher's manifest, byte for byte
//	<root>/bundle.yaml   sidecar: binaries present, every platform's digest,
//	                     signatures, content_hash (an unsigned anchor)
//	<root>/<file name>   one plain file per binary present in the root
//
// # Reader modes
//
// Full mode (ReadOptions.Platform empty; used by the cache, the git resolver and
// the publisher tool) requires every digest to have a file and every file a
// digest. Own-platform mode (ReadOptions.Platform set; what ReadInstalled and
// DiscoverInstalled use, for the running os-arch) reads only that platform's
// binary but still recomputes the content hash from the manifest bytes and the
// FULL digest list, and requires the binary to match the digest under its key.
// In both modes Bundle.ContentHash is the RECOMPUTED value, never the sidecar's:
// the sidecar content_hash is compared against it and a difference is refused.
//
// # File rules and caps
//
// A root holds nothing but module.yaml, bundle.yaml and the binaries the sidecar
// names; any other file, directory or symlink is refused unless ReadOptions
// names it (and then it must be a real directory). Binary file names are one
// plain name (ValidateBinaryFileName). module.yaml, bundle.yaml and every binary
// must be regular files, not symlinks. MaxBundleBytes, MaxBundleFileBytes and
// MaxBundleFiles bound a bundle and are enforced before bytes enter memory.
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
//
// Once installed, Manifest lives at ManifestFileName (module.yaml) under the
// installation root, and Binaries, Signatures and ContentHash live in
// BundleSidecarFileName beside it — see WriteInstalledSidecar and ReadInstalled
// in installed.go for the writer/reader that round-trip a Bundle through that
// on-disk shape.
//
// BinaryDigests maps os-arch keys to the hex SHA-256 of that platform's binary.
// It is the FULL list even when the installation root holds only one binary
// (Binaries then has one entry and BinaryDigests has one per platform).
//
// ManifestBytes and BinaryContent are the in-memory payload of a bundle built by
// Assemble or read by ReadInstalledPayload; they are never serialized.
type Bundle struct {
	Manifest      *modules.ModuleMetadata `yaml:"manifest" json:"manifest"`
	Binaries      map[string]string       `yaml:"binaries" json:"binaries"`
	BinaryDigests map[string]string       `yaml:"binary_digests,omitempty" json:"binary_digests,omitempty"`
	Signatures    []BundleSignature       `yaml:"signatures,omitempty" json:"signatures,omitempty"`
	ContentHash   string                  `yaml:"content_hash" json:"content_hash"`

	// ManifestBytes is the exact module.yaml content the hash covers.
	ManifestBytes []byte `yaml:"-" json:"-"`
	// BinaryContent maps os-arch keys to binary bytes (payload form only).
	BinaryContent map[string][]byte `yaml:"-" json:"-"`
	// InstallRoot is the installation root a bundle was read from (ReadInstalled,
	// ReadInstalledPayload, DiscoverInstalled). It is in-memory only, never
	// serialized, and empty for a bundle that was not read from disk. The steward
	// module runtime resolves and re-verifies the binary against it before exec.
	InstallRoot string `yaml:"-" json:"-"`
}

const (
	// MaxBundleBytes bounds the total size of the files of one bundle.
	MaxBundleBytes int64 = 1 << 30
	// MaxBundleFileBytes bounds any single file of a bundle.
	MaxBundleFileBytes int64 = 256 << 20
	// MaxBundleFiles bounds the number of files in a bundle root: module.yaml,
	// bundle.yaml and one binary for each of the six allowlisted platforms.
	MaxBundleFiles = 8
	// MaxBinaryFileNameLen bounds the length of a binary file name.
	MaxBinaryFileNameLen = 128
)

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

// IdentityKey returns the (publisher, name, version) tuple as a single string,
// deliberately omitting ContentHash. A publisher signature is made over
// ContentHash alone (see VerifyBundleSignature) — nothing in the signing scheme
// binds Name or Version to that hash beyond the manifest bytes that were
// originally hashed into it. Two different (publisher, name, version) claims
// for the identical ContentHash therefore cannot both be genuine: SHA-256
// collision resistance means at most one manifest byte-string produced that
// hash. Callers that persist bundles (features/controller/modules/cache) use
// this to detect a manifest replaying a previously-verified ContentHash and
// Signature under a different claimed identity (Issue #4341).
func (a ContentAddress) IdentityKey() string {
	return a.Publisher + "/" + a.Name + "/" + a.Version
}
