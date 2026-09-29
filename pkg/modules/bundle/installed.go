// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
)

// installedSidecar is the on-disk shape of BundleSidecarFileName.
type installedSidecar struct {
	Binaries    map[string]string `yaml:"binaries"`
	Signatures  []BundleSignature `yaml:"signatures,omitempty"`
	ContentHash string            `yaml:"content_hash"`
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
// This is the shared per-invocation re-check for every module that needs one,
// and it is only half of an integrity gate. Bundle signature verification
// (pkg/modules/trust.VerifyBundleSignature, reached through the steward trust
// enforcer's VerifyForLoad) makes the expected hash a signed value instead of an
// unsigned local anchor; this function then binds the bytes on disk to it. Only
// the two together bind installed files to the publisher signature. Called with
// a b.ContentHash that no signature was verified over — for example the value
// ReadInstalled recovers from the unsigned bundle.yaml sidecar — this function
// proves only that the files and that anchor still agree, which an attacker who
// can write the installation root can restore by rewriting both.
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

// WriteInstalledSidecar writes b's Binaries, Signatures and ContentHash to
// root's BundleSidecarFileName. It does not write or touch module.yaml —
// staging the manifest and binary files themselves is the installer's job;
// this only records the fields the manifest cannot carry.
func WriteInstalledSidecar(b *Bundle, root string) error {
	if b == nil {
		return errors.New("nil bundle")
	}

	sidecar := installedSidecar{
		Binaries:    b.Binaries,
		Signatures:  b.Signatures,
		ContentHash: b.ContentHash,
	}

	data, err := yaml.Marshal(sidecar)
	if err != nil {
		return fmt.Errorf("marshal installed sidecar: %w", err)
	}

	path := filepath.Join(root, BundleSidecarFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write installed sidecar %s: %w", path, err)
	}

	return nil
}

// ReadInstalled reconstructs the *Bundle installed at root by reading
// module.yaml (the publisher's manifest, parsed and validated by
// modules.ParseModuleMetadata so Manifest.Kind is derived) and
// BundleSidecarFileName (binaries, signatures, content hash) and joining them
// back into a Bundle.
//
// # ReadInstalled is not a trust boundary
//
// ReadInstalled calls VerifyInstalledContent before returning, but the expected
// ContentHash it compares against is read from bundle.yaml — steward-authored
// install metadata that is never signed (see BundleSidecarFileName). That check
// is therefore a self-consistency check against an unsigned local anchor, not an
// integrity gate: it catches a bundle whose files changed independently of its
// sidecar (a partial write, a replaced binary, a Binaries entry that escapes
// root — which VerifyInstalledContent rejects via InstalledBinaryPath), and it
// does not survive an attacker with write access to the installation root, who
// rewrites the binary and the sidecar's content_hash together. CFGMS's threat
// model treats that attacker as in scope: stewards run on hosts that may be
// compromised.
//
// A caller must therefore not treat a successful ReadInstalled as permission to
// execute. Gate use of the returned Bundle on publisher-signature verification
// first — features/steward/modules/trust.StewardTrustEnforcer.VerifyForLoad,
// which honours steward.cfg module_trust.mode and checks Bundle.Signatures via
// pkg/modules/trust.VerifyBundleSignature. That step is what makes the expected
// hash a signed value; ReadInstalled's own re-check is only the step that binds
// the bytes on disk to it. features/modules/extended/osquery.PreExecVerifier is
// the worked example of the two steps in the correct order.
//
// A missing module.yaml, a module.yaml that fails validation, and a missing or
// unparsable sidecar each return a distinct error naming the file
// (ErrManifestMissing, ErrManifestInvalid, ErrSidecarMissing,
// ErrSidecarMalformed) and a nil *Bundle; none of these failure paths returns a
// partially populated Bundle.
//
// The returned Bundle.Binaries values are exactly as recorded on disk — root-
// relative, per the Bundle.Binaries contract — not resolved against root. A
// caller that needs to execute a binary resolves it itself via
// InstalledBinaryPath(root, ...); root is not returned by this function
// because the caller already supplied it. DiscoverInstalled, which does not
// hand the caller a root up front, returns it explicitly.
func ReadInstalled(root string) (*Bundle, error) {
	manifestPath := filepath.Join(root, ManifestFileName)
	// #nosec G304 -- manifestPath is root/module.yaml: a fixed file name joined
	// onto a caller-supplied installation root, not publisher-controlled input.
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %w", ErrManifestMissing, manifestPath, err)
		}
		return nil, fmt.Errorf("read installed manifest %s: %w", manifestPath, err)
	}

	// The manifest is the publisher's own file and is untrusted input, so it goes
	// through the canonical validating parser rather than a bare yaml.Unmarshal:
	// ParseModuleMetadata enforces the module contract (name, semver version,
	// publisher, exactly one valid executors value, dependency constraints,
	// observe_when predicates) and — because ModuleMetadata.Kind is yaml:"-" —
	// is the only thing that derives Manifest.Kind. A bare unmarshal would hand
	// every caller a Bundle with an empty Kind, defeating the ADR-006 module-kind
	// confinement boundary for any consumer that gates execution on it.
	manifest, err := modules.ParseModuleMetadata(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrManifestInvalid, manifestPath, err)
	}

	sidecarPath := filepath.Join(root, BundleSidecarFileName)
	// #nosec G304 -- sidecarPath is root/bundle.yaml: a fixed file name joined
	// onto a caller-supplied installation root, not publisher-controlled input.
	sidecarBytes, err := os.ReadFile(sidecarPath)
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

	b := &Bundle{
		Manifest:    manifest,
		Binaries:    sidecar.Binaries,
		Signatures:  sidecar.Signatures,
		ContentHash: sidecar.ContentHash,
	}

	if err := VerifyInstalledContent(b, root); err != nil {
		return nil, err
	}

	return b, nil
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
// as an installation root via ReadInstalled, and returns the resulting bundles
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
		if !entry.IsDir() {
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
