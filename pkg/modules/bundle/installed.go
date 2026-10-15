// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
)

// ManifestFileName is the canonical file name of a module manifest inside an
// installed bundle directory.
const ManifestFileName = "module.yaml"

// BundleSidecarFileName is the canonical file name of the sidecar that records
// what module.yaml cannot carry: the os-arch binary path map, the publisher
// signatures, and the content hash they were made over. It is a separate file,
// not extra keys in module.yaml, because module.yaml is the publisher's own
// manifest and is covered by the signature itself — ComputeInstalledContentHash
// hashes the manifest bytes directly, so rewriting module.yaml at install time
// to add these fields would invalidate every signature over the bundle.
const BundleSidecarFileName = "bundle.yaml"

var (
	// ErrContentHashMismatch is returned when the bytes of an installed bundle on
	// disk do not reproduce the Bundle's ContentHash. Publisher signatures are
	// made over ContentHash (see VerifyBundleSignature), so when the ContentHash
	// being compared against is one a signature was verified over, a mismatch
	// means the installed files are no longer covered by that signature and must
	// not be executed. When the ContentHash came from the unsigned bundle.yaml
	// sidecar instead, a mismatch only proves the files changed independently of
	// the sidecar — see VerifyInstalledContent and ReadInstalled.
	ErrContentHashMismatch = errors.New("installed bundle content hash mismatch")

	// ErrBinaryPathEscapesRoot is returned when a bundle's binary path resolves
	// outside the installation root. Bundle binary paths are publisher-supplied
	// and are therefore treated as untrusted input.
	ErrBinaryPathEscapesRoot = errors.New("bundle binary path escapes installation root")

	// ErrManifestMissing is returned when an installation root has no
	// ManifestFileName.
	ErrManifestMissing = errors.New("installed bundle manifest missing")

	// ErrManifestInvalid is returned when ManifestFileName exists but does not
	// pass modules.ParseModuleMetadata — unparsable YAML, a missing or
	// non-semver version, a missing name or publisher, an executors list that
	// is not exactly one valid value, an invalid dependency constraint, or a
	// malformed observe_when predicate. The manifest is publisher-supplied
	// untrusted input, so an installation root carrying one that does not
	// satisfy the module contract is refused rather than half-parsed.
	ErrManifestInvalid = errors.New("installed bundle manifest invalid")

	// ErrSidecarMissing is returned when an installation root has no
	// BundleSidecarFileName.
	ErrSidecarMissing = errors.New("installed bundle sidecar missing")

	// ErrSidecarMalformed is returned when BundleSidecarFileName exists but does
	// not parse as YAML.
	ErrSidecarMalformed = errors.New("installed bundle sidecar malformed")

	// ErrDuplicateModuleName is returned by DiscoverInstalled when two
	// installation roots declare the same module name.
	ErrDuplicateModuleName = errors.New("duplicate module name across installation roots")

	// ErrNotRegularFile is returned when module.yaml, bundle.yaml or a binary is
	// not a regular file (a symlink, directory or device).
	ErrNotRegularFile = errors.New("bundle file is not a regular file")

	// ErrBundleTooLarge is returned when a bundle, one of its files or its file
	// count exceeds MaxBundleBytes, MaxBundleFileBytes or MaxBundleFiles. The
	// check is made before the bytes are read into memory.
	ErrBundleTooLarge = errors.New("bundle exceeds size limits")

	// ErrUnexpectedEntry is returned by the strict reader for any entry in an
	// installation root other than module.yaml, bundle.yaml, the binaries the
	// sidecar names and the names ReadOptions.IgnoreNames allows.
	ErrUnexpectedEntry = errors.New("unexpected entry in installation root")

	// ErrDigestListInvalid is returned when the sidecar's digest list is
	// malformed or disagrees with the binaries present: a binary without a
	// digest, a digest without a file (outside own-platform mode), or no digest
	// for the platform being read.
	ErrDigestListInvalid = errors.New("bundle digest list invalid")

	// ErrRootExists is returned by WriteInstalled when the installation root
	// already exists. The existing root is left untouched.
	ErrRootExists = errors.New("installation root already exists")
)

// maxMetadataFileBytes bounds module.yaml and bundle.yaml, which are parsed.
const maxMetadataFileBytes int64 = 1 << 20

// installedSidecar is the on-disk shape of BundleSidecarFileName. Binaries lists
// only the files present in the root; Digests lists every platform.
type installedSidecar struct {
	Binaries    map[string]string `yaml:"binaries"`
	Digests     map[string]string `yaml:"digests,omitempty"`
	Signatures  []BundleSignature `yaml:"signatures,omitempty"`
	ContentHash string            `yaml:"content_hash"`
}

func marshalSidecar(b *Bundle) ([]byte, error) {
	data, err := yaml.Marshal(installedSidecar{
		Binaries:    b.Binaries,
		Digests:     b.BinaryDigests,
		Signatures:  b.Signatures,
		ContentHash: b.ContentHash,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal installed sidecar: %w", err)
	}
	return data, nil
}

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

// openRegular opens path for reading, refusing anything but a regular file. The
// path is Lstat-checked (a symlink is refused, not followed) and the opened
// handle must be the same file, so the check cannot be raced by a swap.
func openRegular(path string) (*os.File, int64, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !li.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	// #nosec G304 -- path is confinement-checked by the caller and Lstat-checked above.
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	return f, fi.Size(), nil
}

// readBounded reads r through a limit+1 reader and refuses more than limit bytes.
func readBounded(r io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrBundleTooLarge, what, limit)
	}
	return data, nil
}

// readRegularFile reads a regular, non-symlink file of at most limit bytes. The
// size is checked before any byte is read.
func readRegularFile(path string, limit int64) ([]byte, error) {
	f, size, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if size > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrBundleTooLarge, path, size, limit)
	}
	return readBounded(f, limit, path)
}

// digestRegularFile streams a regular file through SHA-256 without holding it in
// memory, refusing one larger than MaxBundleFileBytes.
func digestRegularFile(path string) ([32]byte, error) {
	var sum [32]byte
	f, size, err := openRegular(path)
	if err != nil {
		return sum, err
	}
	defer func() { _ = f.Close() }()
	if size > MaxBundleFileBytes {
		return sum, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrBundleTooLarge, path, size, MaxBundleFileBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxBundleFileBytes+1))
	if err != nil {
		return sum, err
	}
	if n > MaxBundleFileBytes {
		return sum, fmt.Errorf("%w: %s exceeds %d bytes", ErrBundleTooLarge, path, MaxBundleFileBytes)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func ownPlatformKey() string { return runtime.GOOS + "-" + runtime.GOARCH }

// ComputeInstalledContentHash recomputes a bundle's deterministic content hash
// for the installation at root: the manifest file (root/module.yaml) plus the
// bundle's digest list (b.BinaryDigests), after checking that every binary
// present in root (b.Binaries; paths are relative to root) matches its digest.
// It does not read binaries of platforms the root does not hold, so a root
// holding only the running platform's binary verifies.
//
// A bundle with no digest list (the osquery PreExecVerifier builds those by hand)
// derives its digests from the files named in b.Binaries and hashes those.
//
// It uses ComputeContentHashFromDigests, so the result is directly comparable to
// b.ContentHash and to the value the publisher signed. The returned encoding is
// therefore base64, identical to every other content hash in CFGMS. A binary
// that differs from its digest returns an error wrapping ErrContentHashMismatch.
func ComputeInstalledContentHash(b *Bundle, root string) (string, error) {
	if b == nil {
		return "", errors.New("nil bundle")
	}

	manifestPath, err := InstalledBinaryPath(root, ManifestFileName)
	if err != nil {
		return "", err
	}
	manifestBytes, err := readRegularFile(manifestPath, maxMetadataFileBytes)
	if err != nil {
		return "", fmt.Errorf("read installed manifest: %w", err)
	}

	var digests map[string][32]byte
	if len(b.BinaryDigests) > 0 {
		digests, err = parseDigestList(b.BinaryDigests)
		if err != nil {
			return "", err
		}
	}

	present := make(map[string][32]byte, len(b.Binaries))
	for _, key := range sortedKeys(b.Binaries) {
		binPath, err := InstalledBinaryPath(root, b.Binaries[key])
		if err != nil {
			return "", err
		}
		sum, err := digestRegularFile(binPath)
		if err != nil {
			return "", fmt.Errorf("read installed binary %q: %w", key, err)
		}
		present[key] = sum
	}

	if digests == nil {
		digests = present
	} else {
		for _, key := range sortedKeys(present) {
			want, ok := digests[key]
			if !ok {
				return "", fmt.Errorf("%w: installed binary %q has no digest", ErrDigestListInvalid, key)
			}
			if want != present[key] {
				return "", fmt.Errorf("%w: installed binary %q does not match its digest", ErrContentHashMismatch, key)
			}
		}
	}

	return ComputeContentHashFromDigests(digests, manifestBytes)
}

// VerifyInstalledContent re-derives the content hash of the bundle installed at
// root and compares it against b.ContentHash — the value publisher signatures
// are made over.
//
// This is the shared per-invocation re-check for every module that needs one,
// and it is only half of an integrity gate. Bundle signature verification
// (pkg/modules/trust.VerifyBundleSignature, reached through the steward trust
// enforcer's VerifyForLoad) makes the expected hash a signed value instead of an
// unsigned local anchor; this function then binds the bytes on disk to it. Only
// the two together bind installed files to the publisher signature. Called with
// a b.ContentHash that no signature was verified over, this function proves only
// that the files and that anchor still agree, which an attacker who can write
// the installation root can restore by rewriting both.
//
// The digest list on b must itself come from a hash a signature covers (the list
// is part of the hashed stream, so a changed list changes the hash). On mismatch
// the error wraps ErrContentHashMismatch and names the bundle's ContentAddress
// tuple so audit logs identify which bundle failed.
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

// WriteInstalledSidecar writes b's Binaries, BinaryDigests, Signatures and
// ContentHash to root's BundleSidecarFileName. It does not write or touch
// module.yaml or any binary; WriteInstalled is the writer of a whole root and
// uses the same sidecar encoding.
func WriteInstalledSidecar(b *Bundle, root string) error {
	if b == nil {
		return errors.New("nil bundle")
	}

	data, err := marshalSidecar(b)
	if err != nil {
		return err
	}

	path := filepath.Join(root, BundleSidecarFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write installed sidecar %s: %w", path, err)
	}

	return nil
}

// ReadOptions selects how ReadInstalledPayload reads an installation root.
type ReadOptions struct {
	// IgnoreNames lists directory names allowed in the root beside the bundle's
	// files (the git resolver passes ".git"). Each must itself be a real
	// directory — a file or symlink of that name is refused — and nothing else is
	// ignored.
	IgnoreNames []string
	// Platform, when set, reads only that platform's binary (own-platform mode).
	// The content hash is still recomputed from the manifest bytes and the FULL
	// digest list, and the binary must match the digest under that key. Empty is
	// full mode: every digest must have a file and every file a digest.
	Platform string
}

// ReadInstalled reconstructs the *Bundle installed at root in own-platform mode
// (runtime.GOOS-runtime.GOARCH): module.yaml (parsed and validated by
// modules.ParseModuleMetadata so Manifest.Kind is derived) and
// BundleSidecarFileName (binaries, digests, signatures, content hash). A root
// installed with only the running platform's binary, whose digest list covers
// other platforms, is therefore read, not skipped. Full mode is
// ReadInstalledPayload with an empty ReadOptions.Platform. The returned Bundle
// carries no payload (ManifestBytes, BinaryContent) — only the metadata.
//
// # ReadInstalled is not a trust boundary
//
// The sidecar's content_hash is an unsigned anchor and is never trusted: it is
// compared against the hash recomputed from the manifest bytes and the digest
// list, and the Bundle's ContentHash is the RECOMPUTED value (equal to the
// anchor, or the read is refused). Likewise the digests come from the same
// unsigned sidecar. The check is therefore a self-consistency check, not an
// integrity gate: it does not survive an attacker with write access to the
// installation root, who rewrites the binary, its digest and the anchor
// together — and then the recomputed ContentHash no longer equals the one the
// publisher signed. CFGMS's threat model treats that attacker as in scope.
//
// A caller must therefore not treat a successful ReadInstalled as permission to
// execute. Gate use of the returned Bundle on publisher-signature verification
// first — features/steward/modules/trust.StewardTrustEnforcer.VerifyForLoad,
// which checks Bundle.Signatures via pkg/modules/trust.VerifyBundleSignature
// against the recomputed ContentHash. features/modules/extended/osquery.PreExecVerifier
// is the worked example of the two steps in the correct order.
//
// A missing module.yaml, a module.yaml that fails validation, and a missing or
// unparsable sidecar each return a distinct error naming the file
// (ErrManifestMissing, ErrManifestInvalid, ErrSidecarMissing,
// ErrSidecarMalformed) and a nil *Bundle.
//
// The returned Bundle.Binaries values are exactly as recorded on disk — root-
// relative — not resolved against root. A caller that needs to execute a binary
// resolves it itself via InstalledBinaryPath(root, ...).
func ReadInstalled(root string) (*Bundle, error) {
	return readInstalled(root, ReadOptions{Platform: ownPlatformKey()}, readHashed)
}

// ReadInstalledPayload reads the installation root at root into the payload
// form: ReadInstalled's metadata plus ManifestBytes and BinaryContent for every
// binary read (all of them in full mode, only opts.Platform's in own-platform
// mode). It is strict: any entry other than module.yaml, bundle.yaml and the
// files the sidecar names is refused unless opts.IgnoreNames allows it as a
// real directory. All of ReadInstalled's trust caveats apply.
func ReadInstalledPayload(root string, opts ReadOptions) (*Bundle, error) {
	return readInstalled(root, opts, readPayload)
}

// ReadInstalledMetadata reads the installation root at root in full mode
// without reading any binary bytes: the manifest, the sidecar and the root's
// layout are checked and the content hash is recomputed from the manifest bytes
// and the digest list, but the binaries are only stat-ed, never opened. The
// result carries no payload. Because no binary is hashed, it proves the
// metadata is self-consistent and nothing about the binaries — use
// ReadInstalledPayload for that. All of ReadInstalled's trust caveats apply.
func ReadInstalledMetadata(root string, opts ReadOptions) (*Bundle, error) {
	opts.Platform = ""
	return readInstalled(root, opts, readMetadataOnly)
}

// readMode selects how much of an installation root readInstalled reads.
type readMode int

const (
	// readHashed hashes each binary through a stream without keeping its bytes.
	readHashed readMode = iota
	// readPayload reads and keeps each binary's bytes.
	readPayload
	// readMetadataOnly opens no binary.
	readMetadataOnly
)

func readInstalled(root string, opts ReadOptions, mode readMode) (*Bundle, error) {
	withContent := mode == readPayload
	if opts.Platform != "" && !ValidPlatformKey(opts.Platform) {
		return nil, fmt.Errorf("read installed: platform %q is not an allowed os-arch key", opts.Platform)
	}
	for _, n := range opts.IgnoreNames {
		if err := ValidateBinaryFileName(n); err != nil {
			return nil, fmt.Errorf("read installed: ignore name: %w", err)
		}
	}

	manifestPath := filepath.Join(root, ManifestFileName)
	entries, err := listRoot(root, len(opts.IgnoreNames))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %w", ErrManifestMissing, manifestPath, err)
		}
		return nil, err
	}

	manifestBytes, err := readRegularFile(manifestPath, maxMetadataFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %w", ErrManifestMissing, manifestPath, err)
		}
		return nil, fmt.Errorf("read installed manifest %s: %w", manifestPath, err)
	}

	// The manifest is the publisher's own file and is untrusted input, so it goes
	// through the canonical validating parser rather than a bare yaml.Unmarshal:
	// ParseModuleMetadata enforces the module contract and — because
	// ModuleMetadata.Kind is yaml:"-" — is the only thing that derives
	// Manifest.Kind, which the ADR-006 module-kind confinement boundary gates on.
	manifest, err := modules.ParseModuleMetadata(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrManifestInvalid, manifestPath, err)
	}

	sidecarPath := filepath.Join(root, BundleSidecarFileName)
	sidecarBytes, err := readRegularFile(sidecarPath, maxMetadataFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %w", ErrSidecarMissing, sidecarPath, err)
		}
		return nil, fmt.Errorf("read installed sidecar %s: %w", sidecarPath, err)
	}
	var sidecar installedSidecar
	if err := yaml.Unmarshal(sidecarBytes, &sidecar); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSidecarMalformed, sidecarPath, err)
	}

	for _, key := range sortedKeys(sidecar.Binaries) {
		if _, err := InstalledBinaryPath(root, sidecar.Binaries[key]); err != nil {
			return nil, err
		}
	}
	if err := validateBinaryEntries(sidecar.Binaries); err != nil {
		return nil, err
	}
	digests, err := parseDigestList(sidecar.Digests)
	if err != nil {
		return nil, err
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("%w: sidecar records no digests", ErrDigestListInvalid)
	}
	for _, key := range sortedKeys(sidecar.Binaries) {
		if _, ok := digests[key]; !ok {
			return nil, fmt.Errorf("%w: binary %s has no digest", ErrDigestListInvalid, key)
		}
	}
	if opts.Platform == "" {
		for _, key := range sortedKeys(digests) {
			if _, ok := sidecar.Binaries[key]; !ok {
				return nil, fmt.Errorf("%w: digest for %s has no file", ErrDigestListInvalid, key)
			}
		}
	} else {
		if _, ok := digests[opts.Platform]; !ok {
			return nil, fmt.Errorf("%w: no digest for platform %s", ErrDigestListInvalid, opts.Platform)
		}
		if _, ok := sidecar.Binaries[opts.Platform]; !ok {
			return nil, fmt.Errorf("%w: root holds no binary for platform %s", ErrDigestListInvalid, opts.Platform)
		}
	}

	if err := checkRootEntries(entries, sidecar.Binaries, opts.IgnoreNames); err != nil {
		return nil, err
	}

	toRead := sortedKeys(sidecar.Binaries)
	if opts.Platform != "" {
		toRead = []string{opts.Platform}
	}
	total := int64(len(manifestBytes) + len(sidecarBytes))
	for _, key := range toRead {
		fi, err := os.Lstat(filepath.Join(root, sidecar.Binaries[key]))
		if err != nil {
			return nil, fmt.Errorf("stat installed binary %q: %w", key, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s", ErrNotRegularFile, sidecar.Binaries[key])
		}
		if fi.Size() > MaxBundleFileBytes {
			return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrBundleTooLarge, sidecar.Binaries[key], fi.Size(), MaxBundleFileBytes)
		}
		total += fi.Size()
		if total > MaxBundleBytes {
			return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrBundleTooLarge, MaxBundleBytes)
		}
	}

	var content map[string][]byte
	if withContent {
		content = make(map[string][]byte, len(toRead))
	}
	for _, key := range toRead {
		if mode == readMetadataOnly {
			break
		}
		path := filepath.Join(root, sidecar.Binaries[key])
		var got [32]byte
		if withContent {
			data, err := readRegularFile(path, MaxBundleFileBytes)
			if err != nil {
				return nil, fmt.Errorf("read installed binary %q: %w", key, err)
			}
			got = sha256.Sum256(data)
			content[key] = data
		} else {
			got, err = digestRegularFile(path)
			if err != nil {
				return nil, fmt.Errorf("read installed binary %q: %w", key, err)
			}
		}
		if got != digests[key] {
			return nil, fmt.Errorf("%w: installed binary %q does not match its digest", ErrContentHashMismatch, key)
		}
	}

	hash, err := ComputeContentHashFromDigests(digests, manifestBytes)
	if err != nil {
		return nil, err
	}
	if hash != sidecar.ContentHash {
		return nil, fmt.Errorf("%w for %s/%s@%s: manifest and digests hash to %q but the sidecar records %q",
			ErrContentHashMismatch, manifest.Publisher, manifest.Name, manifest.Version, hash, sidecar.ContentHash)
	}

	b := &Bundle{
		Manifest:      manifest,
		Binaries:      sidecar.Binaries,
		BinaryDigests: sidecar.Digests,
		Signatures:    sidecar.Signatures,
		ContentHash:   hash,
		InstallRoot:   root,
	}
	if withContent {
		b.ManifestBytes = manifestBytes
		b.BinaryContent = content
	}
	return b, nil
}

// VerifyInstalled re-checks the installation root at root for platform
// immediately before the platform's binary is executed. It recomputes the
// content hash from the manifest bytes and the FULL digest list, requires the
// root to hold nothing beyond the files the sidecar names, and compares
// sha256(binary) against the digest recorded under platform's key. The binary is
// streamed through the hash, never loaded into memory. Any difference returns an
// error (wrapping ErrContentHashMismatch for a changed binary).
//
// The sidecar is unsigned, so this alone only proves the root is self-consistent;
// use VerifyInstalledPinned to also bind it to a content hash a signature covers.
func VerifyInstalled(root, platform string) error {
	return VerifyInstalledPinned(root, platform, "", "")
}

// VerifyInstalledPinned is VerifyInstalled that additionally requires the
// recomputed content hash to equal wantContentHash (the value publisher
// signatures were verified over), so a sidecar and binary rewritten together
// after the signature check are refused. An empty wantContentHash skips that
// comparison.
//
// The content hash does not cover binary file names, so wantBinaryPath (the
// root-relative path the caller is about to execute) must equal the path the
// sidecar currently names for platform; otherwise the verified file would not be
// the executed one. An empty wantBinaryPath skips that comparison.
func VerifyInstalledPinned(root, platform, wantContentHash, wantBinaryPath string) error {
	if platform == "" {
		return errors.New("verify installed: platform is required")
	}
	b, err := readInstalled(root, ReadOptions{Platform: platform}, readHashed)
	if err != nil {
		return err
	}
	if wantBinaryPath != "" && b.Binaries[platform] != wantBinaryPath {
		return fmt.Errorf("%w: sidecar no longer names the binary that would be executed", ErrContentHashMismatch)
	}
	if wantContentHash != "" && b.ContentHash != wantContentHash {
		return fmt.Errorf("%w: installed files no longer hash to the verified content hash", ErrContentHashMismatch)
	}
	return nil
}

// listRoot lists root's entries, reading no more than the file limit (plus the
// ignorable names) so a directory of millions of entries is refused before it is
// enumerated.
func listRoot(root string, ignorable int) ([]os.DirEntry, error) {
	// #nosec G304 -- root is the caller-supplied installation root.
	d, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	limit := MaxBundleFiles + ignorable
	entries, err := d.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list installation root %s: %w", root, err)
	}
	if len(entries) > limit {
		return nil, fmt.Errorf("%w: more than %d entries in %s", ErrBundleTooLarge, limit, root)
	}
	return entries, nil
}

// checkRootEntries enforces the strict layout: every entry is module.yaml,
// bundle.yaml, a file the sidecar names, or an allowed ignorable directory.
func checkRootEntries(entries []os.DirEntry, binaries map[string]string, ignore []string) error {
	named := make(map[string]struct{}, len(binaries)+2)
	named[ManifestFileName] = struct{}{}
	named[BundleSidecarFileName] = struct{}{}
	for _, n := range binaries {
		named[n] = struct{}{}
	}
	ignored := make(map[string]struct{}, len(ignore))
	for _, n := range ignore {
		ignored[n] = struct{}{}
	}

	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		name := e.Name()
		seen[name] = struct{}{}
		if _, ok := named[name]; ok {
			if !e.Type().IsRegular() {
				return fmt.Errorf("%w: %s", ErrNotRegularFile, name)
			}
			continue
		}
		if _, ok := ignored[name]; ok {
			if !e.Type().IsDir() {
				return fmt.Errorf("%w: %s must be a real directory", ErrUnexpectedEntry, name)
			}
			continue
		}
		return fmt.Errorf("%w: %s", ErrUnexpectedEntry, name)
	}
	for _, n := range binaries {
		if _, ok := seen[n]; !ok {
			return fmt.Errorf("installed binary %q: %w", n, os.ErrNotExist)
		}
	}
	return nil
}

// InstalledBundle pairs a Bundle reconstructed by ReadInstalled with the
// installation root it was read from. Bundle.Binaries values are root-relative
// (see ReadInstalled); Root is carried alongside the Bundle so a caller can
// resolve a binary to an absolute path via InstalledBinaryPath(Root, ...)
// without having to rediscover which root produced this Bundle.
type InstalledBundle struct {
	Bundle *Bundle
	Root   string
}

// DiscoverInstalled enumerates the immediate subdirectories of dir, reads each
// as an installation root via ReadInstalled (own-platform mode, so a root
// holding only the running platform's binary is found), and returns the resulting bundles
// keyed by module name (Bundle.Manifest.Name).
//
// A subdirectory that fails to read (missing or invalid manifest, missing or
// malformed sidecar, on-disk content that disagrees with its sidecar, an
// escaping binary path) is skipped rather than aborting discovery: its error
// is collected and returned, joined, alongside whatever bundles did read
// successfully — one bad bundle never prevents the rest from being returned,
// but the failure is never silently dropped either.
//
// Two installation roots that declare the same module name are a hard error:
// the second root is not written over the first — discovery instead collects
// ErrDuplicateModuleName naming both roots, and the map keeps the first root's
// bundle for that name.
//
// Discovery inherits ReadInstalled's limits: a returned bundle has passed a
// self-consistency check against its own unsigned sidecar, not a publisher-
// signature check. See "ReadInstalled is not a trust boundary" above — every
// bundle in the returned map must still be gated on VerifyForLoad before use.
func DiscoverInstalled(dir string) (map[string]*InstalledBundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read installation directory %s: %w", dir, err)
	}

	result := make(map[string]*InstalledBundle)
	rootByName := make(map[string]string, len(entries))
	var errs []error

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), tempDirPrefix) {
			continue
		}

		root := filepath.Join(dir, entry.Name())
		b, err := ReadInstalled(root)
		if err != nil {
			errs = append(errs, fmt.Errorf("read installed bundle at %s: %w", root, err))
			continue
		}

		name := ""
		if b.Manifest != nil {
			name = b.Manifest.Name
		}

		if existingRoot, ok := rootByName[name]; ok {
			errs = append(errs, fmt.Errorf("%w: %q installed at both %s and %s", ErrDuplicateModuleName, name, existingRoot, root))
			continue
		}

		rootByName[name] = root
		result[name] = &InstalledBundle{Bundle: b, Root: root}
	}

	return result, errors.Join(errs...)
}
