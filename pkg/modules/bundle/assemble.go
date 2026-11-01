// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	modules "github.com/cfgis/cfgms/features/modules"
)

// SignatureAlgorithm is the only signature algorithm of a v1 bundle.
const SignatureAlgorithm = "ed25519"

// tempDirPrefix names the sibling temporary directory WriteInstalled stages a
// root in. DiscoverInstalled ignores directories carrying it.
const tempDirPrefix = ".cfgms-bundle-"

// ErrInvalidBinaryFileName is returned for a binary file name that is not one
// plain, portable file name (see ValidateBinaryFileName), or a platform key
// outside the os-arch allowlist.
var ErrInvalidBinaryFileName = errors.New("invalid bundle binary file name")

// windowsReservedNames are device names Windows resolves regardless of any
// extension or directory.
var windowsReservedNames = func() map[string]struct{} {
	m := map[string]struct{}{"CON": {}, "PRN": {}, "AUX": {}, "NUL": {}}
	for i := '1'; i <= '9'; i++ {
		m["COM"+string(i)] = struct{}{}
		m["LPT"+string(i)] = struct{}{}
	}
	return m
}()

// ValidateBinaryFileName reports whether name is acceptable as the file name of
// a bundle binary: one plain file name with no separator, not module.yaml or
// bundle.yaml (compared ignoring case), no drive letter or ':', no Windows
// reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without an
// extension), no trailing dot or space, no control or Windows-invalid
// characters, valid UTF-8 and at most MaxBinaryFileNameLen bytes. It is applied
// by Assemble, WriteInstalled and every reader, so a name that is unsafe on any
// supported platform is unsafe everywhere.
func ValidateBinaryFileName(name string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: %q: %s", ErrInvalidBinaryFileName, name, why)
	}
	switch {
	case name == "":
		return bad("empty")
	case len(name) > MaxBinaryFileNameLen:
		return bad(fmt.Sprintf("longer than %d bytes", MaxBinaryFileNameLen))
	case !utf8.ValidString(name):
		return bad("not valid UTF-8")
	case name == "." || name == "..":
		return bad("not a file name")
	case strings.HasSuffix(name, ".") || strings.HasSuffix(name, " "):
		return bad("trailing dot or space")
	case strings.EqualFold(name, ManifestFileName) || strings.EqualFold(name, BundleSidecarFileName):
		return bad("collides with a bundle metadata file")
	}
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			return bad("contains a path separator")
		case r == ':':
			return bad("contains ':' (drive letter or stream)")
		case r < 0x20 || r == 0x7f:
			return bad("contains a control character")
		case strings.ContainsRune(`<>"|?*`, r):
			return bad("contains a character invalid on Windows")
		}
	}
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if _, reserved := windowsReservedNames[strings.ToUpper(strings.TrimRight(base, " "))]; reserved {
		return bad("Windows reserved device name")
	}
	return nil
}

// validateBinaryEntries checks every os-arch key against the allowlist and every
// file name with ValidateBinaryFileName, and requires names to be unique ignoring
// case (two names differing only in case are one file on a case-insensitive
// filesystem).
func validateBinaryEntries(binaries map[string]string) error {
	keys := sortedKeys(binaries)
	seen := make(map[string]string, len(binaries))
	for _, k := range keys {
		if !ValidPlatformKey(k) {
			return fmt.Errorf("%w: platform key %q is not an allowed os-arch key", ErrInvalidBinaryFileName, k)
		}
		name := binaries[k]
		if err := ValidateBinaryFileName(name); err != nil {
			return err
		}
		folded := strings.ToLower(name)
		if other, dup := seen[folded]; dup {
			return fmt.Errorf("%w: %q for %s duplicates the name for %s ignoring case", ErrInvalidBinaryFileName, name, k, other)
		}
		seen[folded] = k
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hexDigests encodes digests as lowercase hex per key.
func hexDigests(digests map[string][32]byte) map[string]string {
	out := make(map[string]string, len(digests))
	for k, d := range digests {
		out[k] = hex.EncodeToString(d[:])
	}
	return out
}

// parseDigestList decodes a hex digest list. Keys must be allowlisted os-arch
// keys and values canonical (lowercase) 64-character hex.
func parseDigestList(list map[string]string) (map[string][32]byte, error) {
	out := make(map[string][32]byte, len(list))
	for k, v := range list {
		if !ValidPlatformKey(k) {
			return nil, fmt.Errorf("%w: digest platform key %q is not an allowed os-arch key", ErrDigestListInvalid, k)
		}
		raw, err := hex.DecodeString(v)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != v {
			return nil, fmt.Errorf("%w: digest for %s is not 64 lowercase hex characters", ErrDigestListInvalid, k)
		}
		var d [32]byte
		copy(d[:], raw)
		out[k] = d
	}
	return out, nil
}

// PlatformBinary names one platform's binary for Assemble: the file name it
// takes inside the root and the path it is read from.
type PlatformBinary struct {
	FileName   string
	SourcePath string
}

// AssembleSpec describes a bundle to build: the publisher's manifest and one
// binary per os-arch key. Several platforms land in one root.
type AssembleSpec struct {
	ManifestPath string
	Binaries     map[string]PlatformBinary
}

// Assemble builds the payload form of a bundle: manifest bytes verbatim, every
// platform's binary, the digest of each, and the content hash over them. The
// bundle is unsigned; see Sign. It refuses a manifest that does not parse, a
// manifest version that is not an exact semver, a platform key outside the
// allowlist, an unsafe or duplicate file name, and a bundle over the size caps.
func Assemble(spec AssembleSpec) (*Bundle, error) {
	if len(spec.Binaries) == 0 {
		return nil, errors.New("assemble: at least one platform binary is required")
	}
	if len(spec.Binaries)+2 > MaxBundleFiles {
		return nil, fmt.Errorf("%w: %d binaries exceed the file limit", ErrBundleTooLarge, len(spec.Binaries))
	}
	names := make(map[string]string, len(spec.Binaries))
	for k, pb := range spec.Binaries {
		names[k] = pb.FileName
	}
	if err := validateBinaryEntries(names); err != nil {
		return nil, fmt.Errorf("assemble: %w", err)
	}

	manifestBytes, err := readSourceFile(spec.ManifestPath, maxMetadataFileBytes)
	if err != nil {
		return nil, fmt.Errorf("assemble: read manifest: %w", err)
	}
	meta, err := modules.ParseModuleMetadata(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("assemble: manifest %s: %w", spec.ManifestPath, err)
	}
	if !IsExactSemver(meta.Version) {
		return nil, fmt.Errorf("assemble: manifest version %q is not an exact semver (MAJOR.MINOR.PATCH, no v prefix)", meta.Version)
	}

	total := int64(len(manifestBytes))
	content := make(map[string][]byte, len(spec.Binaries))
	digests := make(map[string][32]byte, len(spec.Binaries))
	for _, k := range sortedKeys(spec.Binaries) {
		data, err := readSourceFile(spec.Binaries[k].SourcePath, MaxBundleFileBytes)
		if err != nil {
			return nil, fmt.Errorf("assemble: read binary for %s: %w", k, err)
		}
		total += int64(len(data))
		if total > MaxBundleBytes {
			return nil, fmt.Errorf("assemble: %w: bundle exceeds %d bytes", ErrBundleTooLarge, MaxBundleBytes)
		}
		content[k] = data
		digests[k] = sha256.Sum256(data)
	}

	hash, err := ComputeContentHashFromDigests(digests, manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("assemble: compute content hash: %w", err)
	}
	return &Bundle{
		Manifest:      meta,
		Binaries:      names,
		BinaryDigests: hexDigests(digests),
		ContentHash:   hash,
		ManifestBytes: manifestBytes,
		BinaryContent: content,
	}, nil
}

// readSourceFile reads an operator-supplied build input, refusing one larger
// than limit before its bytes are read.
func readSourceFile(path string, limit int64) ([]byte, error) {
	// #nosec G304 -- build input paths are supplied by the trusted local operator.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrBundleTooLarge, path, fi.Size(), limit)
	}
	return readBounded(f, limit, path)
}

// Sign appends an Ed25519 signature over exactly []byte(b.ContentHash) —
// the bytes trust.VerifyBundleSignature verifies — attributed to
// b.Manifest.Publisher. When b carries its payload, the content hash is
// recomputed first and a bundle whose ContentHash does not match is refused, so
// a signature is never made over a hash its files do not reproduce.
func Sign(b *Bundle, priv ed25519.PrivateKey) error {
	if b == nil || b.Manifest == nil {
		return errors.New("sign: bundle has no manifest")
	}
	if b.Manifest.Publisher == "" {
		return errors.New("sign: manifest has no publisher")
	}
	if b.ContentHash == "" {
		return errors.New("sign: bundle has no content hash")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("sign: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if len(b.ManifestBytes) > 0 && len(b.BinaryDigests) > 0 {
		if err := checkPayloadHash(b); err != nil {
			return fmt.Errorf("sign: %w", err)
		}
	}
	b.Signatures = append(b.Signatures, BundleSignature{
		Publisher: b.Manifest.Publisher,
		Algorithm: SignatureAlgorithm,
		Signature: ed25519.Sign(priv, []byte(b.ContentHash)),
	})
	return nil
}

// checkPayloadHash recomputes b's content hash from ManifestBytes and
// BinaryDigests and requires it to equal b.ContentHash.
func checkPayloadHash(b *Bundle) error {
	digests, err := parseDigestList(b.BinaryDigests)
	if err != nil {
		return err
	}
	got, err := ComputeContentHashFromDigests(digests, b.ManifestBytes)
	if err != nil {
		return err
	}
	if got != b.ContentHash {
		addr := b.ContentAddress()
		return fmt.Errorf("%w for %s/%s@%s: manifest and digests hash to %q but the bundle records %q",
			ErrContentHashMismatch, addr.Publisher, addr.Name, addr.Version, got, b.ContentHash)
	}
	return nil
}

// WriteOptions selects what WriteInstalled writes.
type WriteOptions struct {
	// Platform, when set, writes only that platform's binary. The sidecar still
	// records the full digest list.
	Platform string
}

// writeFileHook is a test seam called after each file of a staged root is
// written; a non-nil return aborts the write.
var writeFileHook func(name string) error

// WriteInstalled writes the payload bundle b as an installation root at root.
//
// It requires the payload (ManifestBytes and BinaryContent), recomputes the
// content hash from the manifest bytes and the digest list and refuses on a
// mismatch, checks every binary against its digest, and applies the file-name
// and size rules. root must not exist (ErrRootExists): replacing an install is
// the caller's job. Files are created exclusively in a sibling temporary
// directory on the same volume and renamed into place, so a failure leaves
// nothing at root. Binaries are mode 0755 on Unix.
func WriteInstalled(b *Bundle, root string, opts WriteOptions) (err error) {
	plan, err := planWrite(b, opts)
	if err != nil {
		return err
	}

	if _, statErr := os.Lstat(root); statErr == nil {
		return fmt.Errorf("%w: %s", ErrRootExists, root)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("check installation root %s: %w", root, statErr)
	}

	parent := filepath.Dir(root)
	// #nosec G301 -- installation roots are world-readable, root-writable payload.
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create parent of installation root: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, tempDirPrefix+"*")
	if err != nil {
		return fmt.Errorf("stage installation root: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	// #nosec G302 -- installation roots are world-readable payload.
	if err := os.Chmod(tmp, 0o755); err != nil {
		return fmt.Errorf("chmod staged root: %w", err)
	}

	for _, f := range plan {
		if err := createExclusive(filepath.Join(tmp, f.name), f.data, f.mode); err != nil {
			return err
		}
		if writeFileHook != nil {
			if err := writeFileHook(f.name); err != nil {
				return err
			}
		}
	}

	if err := os.Rename(tmp, root); err != nil {
		if _, statErr := os.Lstat(root); statErr == nil {
			return fmt.Errorf("%w: %s", ErrRootExists, root)
		}
		return fmt.Errorf("install root %s: %w", root, err)
	}
	return nil
}

type plannedFile struct {
	name string
	data []byte
	mode os.FileMode
}

// planWrite validates b and returns the files of the root in write order.
func planWrite(b *Bundle, opts WriteOptions) ([]plannedFile, error) {
	if b == nil || b.Manifest == nil {
		return nil, errors.New("write installed: bundle has no manifest")
	}
	if len(b.ManifestBytes) == 0 || len(b.BinaryContent) == 0 {
		return nil, errors.New("write installed: bundle carries no payload (ManifestBytes and BinaryContent)")
	}
	if len(b.Binaries) == 0 {
		return nil, errors.New("write installed: bundle lists no binaries")
	}
	if err := validateBinaryEntries(b.Binaries); err != nil {
		return nil, fmt.Errorf("write installed: %w", err)
	}
	digests, err := parseDigestList(b.BinaryDigests)
	if err != nil {
		return nil, fmt.Errorf("write installed: %w", err)
	}
	if err := checkPayloadHash(b); err != nil {
		return nil, fmt.Errorf("write installed: %w", err)
	}

	meta, err := modules.ParseModuleMetadata(bytes.NewReader(b.ManifestBytes))
	if err != nil {
		return nil, fmt.Errorf("write installed: %w: %w", ErrManifestInvalid, err)
	}
	if meta.Name != b.Manifest.Name || meta.Version != b.Manifest.Version || meta.Publisher != b.Manifest.Publisher {
		return nil, errors.New("write installed: manifest bytes disagree with the bundle's manifest identity")
	}

	selected := b.Binaries
	if opts.Platform != "" {
		name, ok := b.Binaries[opts.Platform]
		if !ok {
			return nil, fmt.Errorf("write installed: bundle has no binary for platform %q", opts.Platform)
		}
		selected = map[string]string{opts.Platform: name}
	}
	for k := range b.BinaryContent {
		if _, ok := b.Binaries[k]; !ok {
			return nil, fmt.Errorf("write installed: content for %q has no Binaries entry", k)
		}
	}

	files := []plannedFile{{name: ManifestFileName, data: b.ManifestBytes, mode: 0o644}}
	total := int64(len(b.ManifestBytes))
	if total > maxMetadataFileBytes {
		return nil, fmt.Errorf("%w: manifest is %d bytes", ErrBundleTooLarge, total)
	}
	for _, k := range sortedKeys(selected) {
		data, ok := b.BinaryContent[k]
		if !ok {
			return nil, fmt.Errorf("write installed: no content for %s", k)
		}
		if int64(len(data)) > MaxBundleFileBytes {
			return nil, fmt.Errorf("%w: binary for %s is %d bytes", ErrBundleTooLarge, k, len(data))
		}
		want, ok := digests[k]
		if !ok {
			return nil, fmt.Errorf("%w: binary %s has no digest", ErrDigestListInvalid, k)
		}
		if sha256.Sum256(data) != want {
			return nil, fmt.Errorf("%w: binary for %s does not match its digest", ErrContentHashMismatch, k)
		}
		total += int64(len(data))
		files = append(files, plannedFile{name: selected[k], data: data, mode: 0o755})
	}
	if total > MaxBundleBytes {
		return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrBundleTooLarge, MaxBundleBytes)
	}
	if len(files)+1 > MaxBundleFiles {
		return nil, fmt.Errorf("%w: %d files exceed the limit", ErrBundleTooLarge, len(files)+1)
	}

	side, err := marshalSidecar(&Bundle{
		Binaries:      selected,
		BinaryDigests: b.BinaryDigests,
		Signatures:    b.Signatures,
		ContentHash:   b.ContentHash,
	})
	if err != nil {
		return nil, err
	}
	return append(files, plannedFile{name: BundleSidecarFileName, data: side, mode: 0o644}), nil
}

// createExclusive creates path (failing if it exists), writes data and sets the
// mode explicitly so the result does not depend on the umask.
func createExclusive(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 G302 -- path is under a staging directory this process just created; the
	// file name passed ValidateBinaryFileName or is a constant.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
