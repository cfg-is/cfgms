// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Command sign-steward-binary produces the detached publisher signature consumed by
// `cfg installer publish --binary <file> --signature <base64>`.
//
// The signed message is the canonical contentHash|version|platform|arch composite from
// trust.StewardBinaryMessage — the same helper the controller's verify-on-upload and the
// steward's verify use, so signer and verifier cannot drift (Issue #2834). This program
// previously lived at bin/publish/sign.go, which is gitignored; a signer that must stay in
// lockstep with the verify path cannot live in an untracked directory.
//
// Key material: by default this signs with the well-known ZERO-SEED DEV key
// (pub O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=), which is not a secret and is only
// trusted by dev/lab controllers. To sign for a fleet that trusts a real publisher
// identity, supply the seed via the CFGMS_PUBLISHER_SEED environment variable
// (standard base64 of the 32-byte Ed25519 seed). The seed is never written to disk or
// echoed to stdout.
//
// Usage:
//
//	go run ./scripts/sign-steward-binary <binary> <version> <platform> <arch>
//	go run ./scripts/sign-steward-binary cfgms-steward.exe v0.9.41 windows amd64
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// publisherSeedEnv optionally supplies the 32-byte Ed25519 seed (standard base64).
const publisherSeedEnv = "CFGMS_PUBLISHER_SEED"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: sign-steward-binary <binary> <version> <platform> <arch>\n" +
			"  e.g. sign-steward-binary cfgms-steward.exe v0.9.41 windows amd64")
	}
	path, version, platform, arch := args[0], args[1], args[2], args[3]

	// #nosec G304 G703 -- this isolated build/release tool intentionally reads
	// the artifact path supplied by its trusted local operator.
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	// Build the canonical message through the shared helper so the bytes signed here
	// are exactly the bytes the controller and steward verify.
	message, err := trust.StewardBinaryMessage(contentHash, version, platform, arch)
	if err != nil {
		return err
	}

	priv, err := publisherKey()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, []byte(message))

	sigPath := path + ".sig"
	// #nosec G703 -- the isolated release tool writes only beside the exact
	// artifact path supplied by its trusted local operator.
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	// URL-safe base64 is what `cfg installer publish --signature` expects.
	if _, err := fmt.Fprintf(out,
		"pub=%s\nsha256=%s\nmessage=%s\nsignature=%s\nwrote %s (%d bytes)\n",
		base64.StdEncoding.EncodeToString(pub),
		contentHash,
		message,
		base64.RawURLEncoding.EncodeToString(sig),
		sigPath, len(sig),
	); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// publisherKey returns the signing key: the CFGMS_PUBLISHER_SEED-derived key when set,
// otherwise the zero-seed dev key.
func publisherKey() (ed25519.PrivateKey, error) {
	encoded := os.Getenv(publisherSeedEnv)
	if encoded == "" {
		return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), nil
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", publisherSeedEnv, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s must decode to %d bytes, got %d", publisherSeedEnv, ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
