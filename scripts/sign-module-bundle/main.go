// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Command sign-module-bundle assembles and signs a module bundle installation root: the
// publisher's module.yaml, the module binary at its manifest-relative path, and the
// bundle.yaml sidecar recording the content hash and the publisher signature. It is what
// the installers and release archives stage for every stdlib module.
//
// The signed message is exactly []byte(Bundle.ContentHash) — the bytes
// trust.VerifyBundleSignature verifies — and the signature is attributed to the publisher
// name "cfgms", the only name trust.CFGMSPublisherIdentity() answers to, so signer and
// verifier cannot drift. The sidecar is written through bundle.WriteInstalledSidecar, the
// same writer the steward-side reader (bundle.ReadInstalled) is the counterpart of. Like
// scripts/sign-steward-binary, this lives in a tracked directory on purpose: a signer that
// must stay in lockstep with the verify path cannot live in an untracked directory.
//
// WARNING — default key: by default this signs with the well-known ZERO-SEED DEV key
// (pub O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=), which is not a secret. Bundles signed
// with it are only loadable by a steward built with that public key baked in
// (STEWARD_PUBLISHER_KEY=O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=). A steward built with
// the default all-zero placeholder key refuses every bundle. To sign for a real publisher
// identity supply the seed via CFGMS_PUBLISHER_SEED (standard base64 of the 32-byte Ed25519
// seed). The seed is never written to disk or echoed. --release (and check-key) refuse the
// dev key and an absent seed, so a release can never ship dev-signed modules.
//
// Assembly is reproducible: file modes are set explicitly, the sidecar has a sorted
// single-entry binaries map and no timestamps, and Ed25519 signing is deterministic
// (RFC 8032). module.yaml is copied byte-for-byte; ComputeInstalledContentHash hashes the
// manifest bytes, so any rewrite would invalidate the signature.
//
// Usage:
//
//	sign-module-bundle assemble [--release] --manifest <module.yaml> --binary <file> \
//	    --os <os> --arch <arch> --out <root>
//	sign-module-bundle pubkey
//	sign-module-bundle check-key --expect-public-key <base64>
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

const (
	// publisherSeedEnv optionally supplies the 32-byte Ed25519 seed (standard base64).
	publisherSeedEnv = "CFGMS_PUBLISHER_SEED"

	// publisherName is the trust-anchor name the verifier resolves; every stdlib
	// module.yaml carries publisher: cfgms.
	publisherName = "cfgms"

	// devPublicKey is the public half of the zero-seed dev key.
	devPublicKey = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="

	moduleBinaryPrefix = "cfgms-module-"
)

// platformToken restricts os/arch to the characters of a Go GOOS/GOARCH value, so they
// cannot smuggle a path into the sidecar key or the binary file name.
var platformToken = regexp.MustCompile(`^[a-z0-9]+$`)

// moduleNameToken restricts the manifest name that becomes the binary file name.
var moduleNameToken = regexp.MustCompile(`^[a-z0-9_]+$`)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: sign-module-bundle <assemble|pubkey|check-key> [flags]")
	}
	switch args[0] {
	case "assemble":
		return runAssemble(args[1:], errOut)
	case "pubkey":
		priv, _, err := publisherKey()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return err
	case "check-key":
		return runCheckKey(args[1:])
	default:
		return fmt.Errorf("unknown command %q (want assemble, pubkey or check-key)", args[0])
	}
}

func runAssemble(args []string, errOut io.Writer) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifest := fs.String("manifest", "", "path to the publisher's module.yaml")
	binary := fs.String("binary", "", "path to the built module binary")
	osName := fs.String("os", "", "target GOOS")
	arch := fs.String("arch", "", "target GOARCH")
	rootDir := fs.String("out", "", "installation root to create")
	release := fs.Bool("release", false, "refuse the dev key and an absent seed")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("assemble: %w", err)
	}
	if *manifest == "" || *binary == "" || *osName == "" || *arch == "" || *rootDir == "" {
		return errors.New("assemble requires --manifest, --binary, --os, --arch and --out")
	}

	priv, usedDev, err := publisherKey()
	if err != nil {
		return err
	}
	if *release {
		if err := requireReleaseKey(usedDev); err != nil {
			return err
		}
	}

	if _, err := assembleRoot(assembleSpec{
		ManifestPath: *manifest, BinaryPath: *binary,
		OS: *osName, Arch: *arch, Root: *rootDir, Key: priv,
	}); err != nil {
		return err
	}

	if usedDev {
		if _, err := fmt.Fprintf(errOut, "WARNING: %s is not set — %s signed with the zero-seed DEV key.\n"+
			"  A steward loads it only when built with: STEWARD_PUBLISHER_KEY=%s make build-steward\n",
			publisherSeedEnv, *rootDir, devPublicKey); err != nil {
			return fmt.Errorf("write dev-key warning: %w", err)
		}
	}
	return nil
}

func runCheckKey(args []string) error {
	fs := flag.NewFlagSet("check-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	expect := fs.String("expect-public-key", "", "public key the steward is built with (base64)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("check-key: %w", err)
	}
	if *expect == "" {
		return errors.New("check-key requires --expect-public-key")
	}
	priv, usedDev, err := publisherKey()
	if err != nil {
		return err
	}
	if err := requireReleaseKey(usedDev); err != nil {
		return err
	}
	derived := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if derived == devPublicKey {
		return errors.New("the signing seed is the zero-seed dev key; a release must not ship dev-signed modules")
	}
	if derived != *expect {
		return fmt.Errorf("the public key derived from %s does not match the key baked into the steward (%s): "+
			"bundles signed with this seed would not verify", publisherSeedEnv, *expect)
	}
	return nil
}

// requireReleaseKey fails when the seed is absent (the dev fallback).
func requireReleaseKey(usedDev bool) error {
	if usedDev {
		return fmt.Errorf("%s is not set; a release must be signed with the real publisher seed, never the dev key", publisherSeedEnv)
	}
	return nil
}

// publisherKey returns the signing key and whether it is the zero-seed dev fallback
// (seed absent). An explicitly supplied all-zero seed is reported as dev too, because it
// derives the dev public key.
func publisherKey() (ed25519.PrivateKey, bool, error) {
	encoded := os.Getenv(publisherSeedEnv)
	if encoded == "" {
		return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), true, nil
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("decode %s: %w", publisherSeedEnv, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("%s must decode to %d bytes, got %d", publisherSeedEnv, ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	isDev := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) == devPublicKey
	return priv, isDev, nil
}

// signBundle signs exactly the bytes trust.VerifyBundleSignature verifies.
func signBundle(b *bundle.Bundle, priv ed25519.PrivateKey) bundle.BundleSignature {
	return bundle.BundleSignature{
		Publisher: publisherName,
		Algorithm: "ed25519",
		Signature: ed25519.Sign(priv, []byte(b.ContentHash)),
	}
}

// assembleSpec describes one installation root to build.
type assembleSpec struct {
	ManifestPath string
	BinaryPath   string
	OS           string
	Arch         string
	Root         string
	Key          ed25519.PrivateKey
}

// assembleRoot builds the installation root at spec.Root and returns the signed bundle.
// The root holds module.yaml (verbatim), the binary at cfgms-module-<name>[.exe], and the
// sidecar with a single os-arch Binaries entry for the platform the root ships to.
func assembleRoot(spec assembleSpec) (*bundle.Bundle, error) {
	if !platformToken.MatchString(spec.OS) || !platformToken.MatchString(spec.Arch) {
		return nil, fmt.Errorf("invalid platform %q/%q", spec.OS, spec.Arch)
	}

	// #nosec G304 -- build tool reads paths supplied by its trusted local operator.
	manifestBytes, err := os.ReadFile(spec.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	meta, err := modules.ParseModuleMetadata(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", spec.ManifestPath, err)
	}
	if !moduleNameToken.MatchString(meta.Name) {
		// The name becomes a file name; the manifest parser does not constrain its charset.
		return nil, fmt.Errorf("manifest name %q is not a valid module file name", meta.Name)
	}
	// #nosec G304 -- build tool reads paths supplied by its trusted local operator.
	binaryBytes, err := os.ReadFile(spec.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}

	if entries, err := os.ReadDir(spec.Root); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("installation root %s already exists and is not empty", spec.Root)
	}

	binName := moduleBinaryPrefix + meta.Name
	if spec.OS == "windows" {
		binName += ".exe"
	}
	key := spec.OS + "-" + spec.Arch

	// #nosec G301 -- installation roots are world-readable, root-writable payload.
	if err := os.MkdirAll(spec.Root, 0o755); err != nil {
		return nil, fmt.Errorf("create root: %w", err)
	}
	if err := writeFile(filepath.Join(spec.Root, bundle.ManifestFileName), manifestBytes, 0o644); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(spec.Root, binName), binaryBytes, 0o755); err != nil {
		return nil, err
	}

	hash, err := bundle.ComputeContentHash(map[string][]byte{key: binaryBytes}, manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("compute content hash: %w", err)
	}
	b := &bundle.Bundle{
		Manifest:    meta,
		Binaries:    map[string]string{key: binName},
		ContentHash: hash,
	}
	b.Signatures = []bundle.BundleSignature{signBundle(b, spec.Key)}

	if err := bundle.WriteInstalledSidecar(b, spec.Root); err != nil {
		return nil, err
	}
	// Prove the contract with the reader before anything ships.
	if err := bundle.VerifyInstalledContent(b, spec.Root); err != nil {
		return nil, fmt.Errorf("assembled root fails its own verification: %w", err)
	}
	return b, nil
}

// writeFile writes data and sets the mode explicitly so the result does not depend on the
// umask or on the source file's mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	// #nosec G306 G703 -- explicit payload modes; path is under the assembled root.
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// #nosec G703 -- path is under the operator-supplied assembled root; the file name is a
	// constant or moduleBinaryPrefix + a name validated by moduleNameToken.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
