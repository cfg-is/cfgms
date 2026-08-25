// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestFileName is the canonical file name of a module manifest inside an
// installed bundle directory.
const ManifestFileName = "module.yaml"

var (
	// ErrContentHashMismatch is returned when the bytes of an installed bundle on
	// disk do not reproduce the bundle's recorded ContentHash. Because publisher
	// signatures are made over ContentHash (see VerifyBundleSignature), a mismatch
	// means the installed files are no longer covered by the publisher signature —
	// they have been modified since installation and must not be executed.
	ErrContentHashMismatch = errors.New("installed bundle content hash mismatch")

	// ErrBinaryPathEscapesRoot is returned when a bundle's binary path resolves
	// outside the installation root. Bundle binary paths are publisher-supplied
	// and are therefore treated as untrusted input.
	ErrBinaryPathEscapesRoot = errors.New("bundle binary path escapes installation root")
)

// InstalledBinaryPath joins a bundle-relative path onto the installation root
// and rejects any result that escapes root. Bundle-supplied relative paths are
// publisher-controlled and therefore untrusted input, so a "../../etc/shadow"
// entry must not be resolvable through this helper.
func InstalledBinaryPath(root, relPath string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve bundle root %q: %w", root, err)
	}
	joined := filepath.Join(absRoot, filepath.FromSlash(relPath))
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrBinaryPathEscapesRoot, relPath)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrBinaryPathEscapesRoot, relPath)
	}
	return joined, nil
}

// ComputeInstalledContentHash recomputes a bundle's deterministic content hash
// from the files currently on disk under root: every binary listed in b.Binaries
// (paths are relative to root) plus the manifest file (root/module.yaml).
//
// It uses ComputeContentHash, so the result is directly comparable to
// b.ContentHash and to the value the publisher signed. The returned encoding is
// therefore base64, identical to every other content hash in CFGMS — no module
// carries a second, bespoke digest encoding.
func ComputeInstalledContentHash(b *Bundle, root string) (string, error) {
	if b == nil {
		return "", errors.New("nil bundle")
	}

	binContent := make(map[string][]byte, len(b.Binaries))
	for key, relPath := range b.Binaries {
		binPath, err := InstalledBinaryPath(root, relPath)
		if err != nil {
			return "", err
		}
		// #nosec G304 -- binPath was resolved and confinement-checked against root
		// by InstalledBinaryPath above.
		content, err := os.ReadFile(binPath)
		if err != nil {
			return "", fmt.Errorf("read installed binary %q: %w", key, err)
		}
		binContent[key] = content
	}

	manifestPath, err := InstalledBinaryPath(root, ManifestFileName)
	if err != nil {
		return "", err
	}
	// #nosec G304 -- manifestPath is root/module.yaml, confinement-checked above.
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("read installed manifest: %w", err)
	}

	return ComputeContentHash(binContent, manifestBytes)
}

// VerifyInstalledContent re-derives the content hash of the bundle installed at
// root and compares it against b.ContentHash — the value publisher signatures
// are made over.
//
// This is the shared per-invocation re-check for every module that needs one:
// bundle signature verification (pkg/modules/trust) proves the ContentHash was
// signed by a trusted publisher, and this function proves the bytes on disk
// still reproduce that ContentHash. Together they bind installed files to the
// publisher signature, so tampering after installation is refused rather than
// executed best-effort.
//
// On mismatch the error wraps ErrContentHashMismatch and names the bundle's
// ContentAddress tuple so audit logs identify which bundle failed.
func VerifyInstalledContent(b *Bundle, root string) error {
	got, err := ComputeInstalledContentHash(b, root)
	if err != nil {
		return err
	}

	if got != b.ContentHash {
		addr := b.ContentAddress()
		return fmt.Errorf("%w for %s/%s@%s: installed files hash to %q but the signed bundle records %q",
			ErrContentHashMismatch, addr.Publisher, addr.Name, addr.Version, got, addr.ContentHash)
	}

	return nil
}
