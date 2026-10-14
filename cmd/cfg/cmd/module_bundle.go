// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cmd

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

const (
	// publisherSeedEnv supplies the publisher's Ed25519 seed (standard base64 of the
	// 32 raw bytes) when --seed-stdin is not given.
	publisherSeedEnv = "CFGMS_PUBLISHER_SEED"

	// devPublisherPublicKey is the public half of the well-known all-zero development
	// seed. It is not a secret, so a bundle signed with it proves nothing.
	devPublisherPublicKey = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="

	moduleBinaryPrefix = "cfgms-module-"

	// maxSeedInputBytes bounds what is read from stdin; a seed is 44 base64 characters.
	maxSeedInputBytes = 1024
)

var (
	errSeedAbsent    = errors.New("publisher seed is absent: pipe it on stdin with --seed-stdin or set " + publisherSeedEnv)
	errSeedMalformed = errors.New("publisher seed is malformed: it must be standard base64 of exactly 32 bytes")
	errSeedDevKey    = errors.New("publisher seed is the well-known development seed; generate a real one with 'cfg module keygen'")
)

// publisherNameToken restricts the manifest publisher and module name, which become
// trust-anchor and file names, to a path-safe character set.
var publisherNameToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// platformKeyToken restricts the os half and arch half of an --binary key.
var platformKeyToken = regexp.MustCompile(`^[a-z0-9]+$`)

var (
	bundleBuildManifest  string
	bundleBuildBinaries  []string
	bundleBuildOut       string
	bundleBuildSeedStdin bool

	pubkeySeedStdin bool
)

var moduleBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Build signed module bundles",
}

var moduleBundleBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build and sign a module bundle installation root",
	Long: `Build a signed bundle installation root for a module: the publisher's module.yaml
(verbatim), one binary per platform, and a bundle.yaml sidecar holding the content
hash, the digest of every binary and the publisher signature. The output directory is
ready to commit as the root of a module source repository.

The publisher name and exact version come from the manifest ('publisher' and
'version'; no 'v' prefix). The command is local: it never contacts the controller.

The signing seed is read from stdin with --seed-stdin (preferred: an environment
variable is readable by other processes of the same user and inherited by child
processes), otherwise from the ` + publisherSeedEnv + ` environment variable. The seed
is standard base64 of the 32-byte Ed25519 seed. It is never written to disk or echoed.
There is deliberately no seed flag and no key-file flag. An absent or malformed seed,
and the well-known development seed, are refused.

On success the publisher name, content hash and public key fingerprint are printed so
the operator can match them against the controller trust file.`,
	Example: `  # Create a publisher identity once; store the seed in a secrets manager
  cfg module keygen

  # Build a two-platform bundle, reading the seed from stdin
  cfg module bundle build --seed-stdin \
      --manifest module.yaml \
      --binary linux-amd64=dist/linux-amd64/mymod \
      --binary windows-amd64=dist/windows-amd64/mymod.exe \
      --out ./bundle-root < seed.txt

  # Same, with the seed in the environment
  CFGMS_PUBLISHER_SEED=<seed> cfg module bundle build --manifest module.yaml \
      --binary linux-amd64=dist/mymod --out ./bundle-root`,
	Args: cobra.NoArgs,
	RunE: runModuleBundleBuild,
}

var moduleKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a module publisher Ed25519 identity",
	Long: `Generate a new publisher identity and print the seed, the public key and the public
key SHA-256 fingerprint to stdout once. Nothing is written to disk: store the seed in
a secrets manager, and register the public key (matched by fingerprint) in the
controller trust file.`,
	Example: `  cfg module keygen`,
	Args:    cobra.NoArgs,
	RunE:    runModuleKeygen,
}

var modulePubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Show the public key and fingerprint for a publisher seed",
	Long: `Derive the public key from the publisher seed and print it with its SHA-256
fingerprint. The seed is read from stdin with --seed-stdin (preferred) or from the
` + publisherSeedEnv + ` environment variable, and is never echoed.`,
	Example: `  cfg module pubkey --seed-stdin < seed.txt
  CFGMS_PUBLISHER_SEED=<seed> cfg module pubkey`,
	Args: cobra.NoArgs,
	RunE: runModulePubkey,
}

func init() {
	moduleBundleBuildCmd.Flags().StringVar(&bundleBuildManifest, "manifest", "", "path to the publisher's module.yaml")
	moduleBundleBuildCmd.Flags().StringArrayVar(&bundleBuildBinaries, "binary", nil, "platform binary as <os>-<arch>=<path> (repeatable)")
	moduleBundleBuildCmd.Flags().StringVar(&bundleBuildOut, "out", "", "installation root to create (must not exist)")
	moduleBundleBuildCmd.Flags().BoolVar(&bundleBuildSeedStdin, "seed-stdin", false, "read the publisher seed from stdin instead of "+publisherSeedEnv)
	modulePubkeyCmd.Flags().BoolVar(&pubkeySeedStdin, "seed-stdin", false, "read the publisher seed from stdin instead of "+publisherSeedEnv)

	moduleBundleCmd.AddCommand(moduleBundleBuildCmd)
	moduleCmd.AddCommand(moduleBundleCmd, moduleKeygenCmd, modulePubkeyCmd)
}

// publisherFingerprint is the lowercase hex SHA-256 of the raw public key.
func publisherFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// loadPublisherKey reads the seed from stdin or the environment and returns the
// signing key, refusing an absent, malformed or development seed.
func loadPublisherKey(fromStdin bool, in io.Reader) (ed25519.PrivateKey, error) {
	var encoded string
	if fromStdin {
		data, err := io.ReadAll(io.LimitReader(bufio.NewReader(in), maxSeedInputBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read seed from stdin: %w", err)
		}
		if len(data) > maxSeedInputBytes {
			return nil, errSeedMalformed
		}
		encoded = string(data)
	} else {
		encoded = os.Getenv(publisherSeedEnv)
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errSeedAbsent
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errSeedMalformed
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) == devPublisherPublicKey {
		return nil, errSeedDevKey
	}
	return priv, nil
}

func runModuleKeygen(cmd *cobra.Command, _ []string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("generate seed: %w", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	out := cmd.OutOrStdout()
	_, err := fmt.Fprintf(out, "seed: %s\npublic key: %s\nfingerprint: %s\n"+
		"Store the seed securely; it is shown only once and is not written to disk.\n",
		base64.StdEncoding.EncodeToString(seed), base64.StdEncoding.EncodeToString(pub), publisherFingerprint(pub))
	return err
}

func runModulePubkey(cmd *cobra.Command, _ []string) error {
	priv, err := loadPublisherKey(pubkeySeedStdin, cmd.InOrStdin())
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "public key: %s\nfingerprint: %s\n",
		base64.StdEncoding.EncodeToString(pub), publisherFingerprint(pub))
	return err
}

// parseBinarySpecs turns repeated <os>-<arch>=<path> values into bundle inputs, naming
// each file cfgms-module-<name>[.exe]. Every file name is checked before anything is
// written.
func parseBinarySpecs(specs []string, moduleName string) (map[string]bundle.PlatformBinary, error) {
	if len(specs) == 0 {
		return nil, errors.New("at least one --binary <os>-<arch>=<path> is required")
	}
	out := make(map[string]bundle.PlatformBinary, len(specs))
	for _, s := range specs {
		key, path, ok := strings.Cut(s, "=")
		if !ok || key == "" || path == "" {
			return nil, fmt.Errorf("invalid --binary %q: want <os>-<arch>=<path>", s)
		}
		goos, goarch, ok := strings.Cut(key, "-")
		if !ok || !platformKeyToken.MatchString(goos) || !platformKeyToken.MatchString(goarch) || !bundle.ValidPlatformKey(key) {
			return nil, fmt.Errorf("invalid --binary platform %q: want <os>-<arch> such as linux-amd64", key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate --binary for platform %s", key)
		}
		name := moduleBinaryPrefix + moduleName
		if goos == "windows" {
			name += ".exe"
		}
		if err := bundle.ValidateBinaryFileName(name); err != nil {
			return nil, err
		}
		out[key] = bundle.PlatformBinary{FileName: name, SourcePath: path}
	}
	return out, nil
}

func runModuleBundleBuild(cmd *cobra.Command, _ []string) error {
	if bundleBuildManifest == "" || bundleBuildOut == "" {
		return errors.New("--manifest and --out are required")
	}

	// Validate every input before the seed is read or anything is written.
	// #nosec G304 -- the publisher names their own manifest path.
	manifestBytes, err := os.ReadFile(bundleBuildManifest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	meta, err := modules.ParseModuleMetadata(bytes.NewReader(manifestBytes))
	if err != nil {
		return fmt.Errorf("manifest %s: %w", bundleBuildManifest, err)
	}
	if !publisherNameToken.MatchString(meta.Publisher) {
		return fmt.Errorf("manifest publisher %q is not a safe name", meta.Publisher)
	}
	if !publisherNameToken.MatchString(meta.Name) {
		return fmt.Errorf("manifest name %q is not a safe module name", meta.Name)
	}
	binaries, err := parseBinarySpecs(bundleBuildBinaries, meta.Name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(bundleBuildOut); err == nil {
		return fmt.Errorf("%w: %s", bundle.ErrRootExists, bundleBuildOut)
	}

	priv, err := loadPublisherKey(bundleBuildSeedStdin, cmd.InOrStdin())
	if err != nil {
		return err
	}

	b, err := bundle.Assemble(bundle.AssembleSpec{ManifestPath: bundleBuildManifest, Binaries: binaries})
	if err != nil {
		return err
	}
	if err := bundle.Sign(b, priv); err != nil {
		return err
	}
	if err := bundle.WriteInstalled(b, bundleBuildOut, bundle.WriteOptions{}); err != nil {
		return err
	}
	// Prove the output with the strict reader before reporting success.
	if _, err := bundle.ReadInstalledPayload(bundleBuildOut, bundle.ReadOptions{}); err != nil {
		return fmt.Errorf("built bundle fails its own verification: %w", err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "publisher: %s\nmodule: %s@%s\ncontent hash: %s\npublic key fingerprint: %s\nwrote: %s\n",
		b.Manifest.Publisher, b.Manifest.Name, b.Manifest.Version, b.ContentHash, publisherFingerprint(pub), bundleBuildOut)
	return err
}
