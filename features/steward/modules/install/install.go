// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package install fetches, verifies and installs a module bundle on a steward.
//
// Given a required module (publisher, name, exact version) the Installer streams
// the bundle for the steward's OWN platform from the controller, checks that it
// received what it asked for, verifies the publisher signature under the
// configured module_trust.mode, and installs only its own platform's binary into
// the per-module layout that bundle.DiscoverInstalled and the module factory read.
//
// # Verification order
//
// Every step fails closed and nothing reaches the discovery root before the last:
//
//  1. The request is built locally; the platform is runtime.GOOS-runtime.GOARCH,
//     never taken from received data. The stream is received into memory with a
//     running byte count against bundle.MaxBundleFileBytes. No path or file name
//     from the stream builds a filesystem path: the installer derives every path
//     itself and only checks the single received file name with
//     bundle.ValidateBinaryFileName. (Memory, not a staging directory, so a
//     truncated or oversize stream cannot leave anything on disk.)
//  2. The digest list must contain an entry for the own platform, and every key
//     must be an allowlisted os-arch key with a well-formed SHA-256.
//  3. sha256(received binary) must equal the digest under the own key.
//  4. The content hash is recomputed from the received manifest bytes and the
//     FULL digest list in every trust mode (strict, controller and bypass) and
//     must equal the header hash.
//  5. The manifest publisher, name and version must equal the request.
//  6. A Bundle is built with the RECOMPUTED hash (never the header value) and
//     StewardTrustEnforcer.VerifyForLoad runs on it. In strict mode that is the
//     only gate: no controller attestation is read. bypass logs the same warning
//     the module factory logs at load.
//  7. bundle.WriteInstalled writes the own-platform tree.
//
// A publisher other than cfgms may never install a module whose name is in the
// ADR-016 stdlib set (StdlibModuleNames), and a name already installed by a
// different publisher is refused.
//
// # Install location
//
// <root>/<name>/ where root is DefaultRoot (C:\Program Files\CFGMS\modules or
// /usr/local/lib/cfgms/modules; CFGMS_MODULE_BUNDLE_DIR overrides it for tests).
// Root, the staging directory and the module directory are created through
// EnsureProtectedDir: on Windows SYSTEM and Administrators have full control,
// Users read/execute only, with no inherited user-write; on Unix mode 0755 owned
// by root or the process's effective uid. CheckProtectedTree verifies the same
// rules for a later load-time check.
//
// # Replace procedure
//
// WriteInstalled refuses an existing target and Windows cannot rename onto an
// existing directory, so an existing <name>/ is replaced as: write the new tree
// into a staging directory under root (its name starts with ".cfgms-bundle-", so
// DiscoverInstalled skips it and a half-written tree is never discoverable),
// rename the old <name>/ aside, rename the new tree in, remove the old one. If
// the second rename fails the old tree is renamed back. If the first rename fails
// (on Windows a running module holds its binary open) the old tree is untouched
// and ErrModuleInUse is returned; the next config apply retries. The same
// publisher, name, version and content hash already installed is a no-op.
package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"google.golang.org/grpc"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// Sentinel errors. None of them carries a filesystem path.
var (
	// ErrInvalidRequest is returned for a publisher, name or version that cannot
	// name a bundle.
	ErrInvalidRequest = errors.New("invalid module request")
	// ErrInstallerMisconfigured is returned when the Installer lacks a required field.
	ErrInstallerMisconfigured = errors.New("module installer misconfigured")
	// ErrFetchFailed is returned when the controller stream fails or is cut short.
	ErrFetchFailed = errors.New("module bundle fetch failed")
	// ErrStreamInvalid is returned when the stream breaks the bundle protocol:
	// a missing header, an unusable file name, wrong sizes or an oversize body.
	ErrStreamInvalid = errors.New("module bundle stream invalid")
	// ErrDigestListInvalid is returned when the digest list is malformed or has
	// no entry for the steward's own platform.
	ErrDigestListInvalid = errors.New("module bundle digest list invalid")
	// ErrBinaryDigestMismatch is returned when the received binary does not match
	// the digest recorded for the own platform.
	ErrBinaryDigestMismatch = errors.New("module binary does not match its digest")
	// ErrContentHashMismatch is returned when the hash recomputed from the manifest
	// and the digest list differs from the header hash.
	ErrContentHashMismatch = errors.New("module bundle content hash mismatch")
	// ErrIdentityMismatch is returned when the manifest names a different
	// publisher, module or version than was requested.
	ErrIdentityMismatch = errors.New("module bundle identity does not match the request")
	// ErrTrustRefused is returned when VerifyForLoad refuses the bundle.
	ErrTrustRefused = errors.New("module bundle refused by module trust policy")
	// ErrStdlibName is returned when a non-cfgms publisher asks for a stdlib name.
	ErrStdlibName = errors.New("module name is reserved for the cfgms standard library")
	// ErrPublisherMismatch is returned when the module name is already installed
	// by a different publisher.
	ErrPublisherMismatch = errors.New("module name is installed by a different publisher")
	// ErrModuleInUse is returned when the installed tree cannot be replaced
	// because something holds it open; the old tree is left intact.
	ErrModuleInUse = errors.New("installed module is in use and cannot be replaced")
	// ErrInstallFailed is returned for a local failure writing the tree.
	ErrInstallFailed = errors.New("module install failed")
)

// Client is the one RPC the Installer needs. transportpb.StewardTransportClient
// satisfies it.
type Client interface {
	FetchModuleBundle(ctx context.Context, in *transportpb.FetchModuleBundleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[transportpb.ModuleBundleChunk], error)
}

// Installer fetches, verifies and installs module bundles.
type Installer struct {
	// Root is the discovery root; empty means DefaultRoot().
	Root string
	// Mode is the configured module_trust.mode.
	Mode stewardtypes.ModuleTrustMode
	// AdditionalPublisherNames is module_trust.additional_publishers; consulted
	// in strict mode only.
	AdditionalPublisherNames []string
	// Enforcer verifies publisher signatures.
	Enforcer *trust.StewardTrustEnforcer
	// Client fetches the bundle from the controller.
	Client Client
	// Logger receives sanitized progress; nil discards.
	Logger logging.Logger

	// renameHook, when set, replaces os.Rename (test seam for forced failures).
	renameHook func(oldPath, newPath string) error
}

// Result describes a successful Install.
type Result struct {
	// Changed is false when the same bundle was already installed (no-op).
	Changed bool
	// ContentHash is the verified, recomputed content hash.
	ContentHash string
}

const (
	installedModulesWindowsRoot = `C:\Program Files\CFGMS\modules`
	installedModulesUnixRoot    = `/usr/local/lib/cfgms/modules`
	// BundleDirEnvVar overrides DefaultRoot, matching the module factory's
	// override of the same name; it is meant for test isolation.
	BundleDirEnvVar = "CFGMS_MODULE_BUNDLE_DIR"

	// stagePrefix starts the name of every transient directory under the root;
	// bundle.DiscoverInstalled skips names with this prefix.
	stagePrefix = ".cfgms-bundle-"
	// maxManifestBytes and maxSignatures bound the header fields that are not
	// covered by the file-size cap.
	maxManifestBytes = 1 << 20
	maxSignatures    = 32
)

// DefaultRoot returns the platform installed-bundle discovery root, the same
// location the module factory discovers from.
func DefaultRoot() string {
	if override := os.Getenv(BundleDirEnvVar); override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		return installedModulesWindowsRoot
	}
	return installedModulesUnixRoot
}

// ownPlatform is the steward's platform key, derived locally.
func ownPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

var componentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// validComponent reports whether s is safe as a publisher or module name and as
// a directory name on every supported platform.
func validComponent(s string) bool {
	return componentPattern.MatchString(s) && bundle.ValidateBinaryFileName(s) == nil
}

func (in *Installer) log() logging.Logger {
	if in.Logger == nil {
		return logging.NewNoopLogger()
	}
	return in.Logger
}

func (in *Installer) rename(oldPath, newPath string) error {
	if in.renameHook != nil {
		return in.renameHook(oldPath, newPath)
	}
	return os.Rename(oldPath, newPath)
}

// refuse logs the cause (sanitized) and returns the sentinel, so the returned
// error never carries a filesystem path or received text.
func (in *Installer) refuse(sentinel error, publisher, name, version string, cause error) error {
	args := []any{
		"publisher", logging.SanitizeLogValue(publisher),
		"name", logging.SanitizeLogValue(name),
		"version", logging.SanitizeLogValue(version),
		"reason", sentinel.Error(),
	}
	if cause != nil {
		args = append(args, "error", logging.SanitizeLogValue(cause.Error()))
	}
	in.log().Warn("Module bundle install refused", args...)
	return sentinel
}

// Install fetches publisher/name at the exact version, verifies it and installs
// the own-platform tree. See the package documentation for the order.
func (in *Installer) Install(ctx context.Context, publisher, name, version string) (*Result, error) {
	if in.Enforcer == nil || in.Client == nil {
		return nil, ErrInstallerMisconfigured
	}
	root := in.Root
	if root == "" {
		root = DefaultRoot()
	}
	if !validComponent(publisher) || !validComponent(name) || !bundle.IsExactSemver(version) {
		return nil, in.refuse(ErrInvalidRequest, publisher, name, version, nil)
	}
	if publisher != stdlibPublisher && isStdlibName(name) {
		return nil, in.refuse(ErrStdlibName, publisher, name, version, nil)
	}

	var additional []trust.PublisherIdentity
	switch in.Mode {
	case stewardtypes.ModuleTrustModeStrict:
		resolved, err := in.Enforcer.ResolveAdditionalPublishers(in.AdditionalPublisherNames)
		if err != nil {
			return nil, in.refuse(trust.ErrAdditionalPublisherUnresolvable, publisher, name, version, err)
		}
		additional = resolved
	case stewardtypes.ModuleTrustModeController:
	case stewardtypes.ModuleTrustModeBypass:
		in.log().Warn("installing module bundle with module_trust.mode=bypass: signature verification disabled",
			"module", logging.SanitizeLogValue(name), "mode", string(in.Mode))
	default:
		return nil, in.refuse(ErrInstallerMisconfigured, publisher, name, version, nil)
	}

	platform := ownPlatform()
	rec, err := in.receive(ctx, &transportpb.FetchModuleBundleRequest{
		Publisher: publisher, Name: name, Version: version, Platform: platform,
	})
	if err != nil {
		return nil, in.refuse(err, publisher, name, version, nil)
	}

	b, sentinel, cause := in.verify(rec, publisher, name, version, platform)
	if sentinel != nil {
		return nil, in.refuse(sentinel, publisher, name, version, cause)
	}
	if err := in.Enforcer.VerifyForLoad(b, in.Mode, additional); err != nil {
		return nil, in.refuse(ErrTrustRefused, publisher, name, version, err)
	}

	return in.place(b, root, publisher, name, version, platform)
}

// received is the unverified content of a stream.
type received struct {
	header *transportpb.ModuleBundleHeader
	data   []byte
}

// receive reads the whole stream into memory, enforcing the protocol and the
// size cap as bytes arrive. Its errors are already sentinels.
func (in *Installer) receive(ctx context.Context, req *transportpb.FetchModuleBundleRequest) (*received, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := in.Client.FetchModuleBundle(ctx, req)
	if err != nil {
		return nil, in.fetchFailed(err)
	}

	first, err := stream.Recv()
	if err != nil {
		return nil, in.fetchFailed(err)
	}
	header := first.GetHeader()
	if header == nil || len(first.GetData()) != 0 {
		return nil, ErrStreamInvalid
	}
	size := header.GetFileSize()
	if size <= 0 || size > bundle.MaxBundleFileBytes ||
		len(header.GetManifest()) == 0 || len(header.GetManifest()) > maxManifestBytes ||
		len(header.GetSignatures()) > maxSignatures ||
		len(header.GetBinaryDigests()) > bundle.MaxBundleFiles {
		return nil, ErrStreamInvalid
	}
	if err := bundle.ValidateBinaryFileName(header.GetFileName()); err != nil {
		return nil, ErrStreamInvalid
	}

	// The buffer grows with what actually arrives; a lying file_size cannot make
	// the steward reserve it up front.
	var buf bytes.Buffer
	var next int32 = 1
	final := first.GetFinal()
	for !final {
		c, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil, ErrStreamInvalid // ended without a final frame: truncated
		}
		if err != nil {
			return nil, in.fetchFailed(err)
		}
		if c.GetHeader() != nil || c.GetChunkIndex() != next {
			return nil, ErrStreamInvalid
		}
		next++
		if int64(buf.Len())+int64(len(c.GetData())) > size {
			return nil, ErrStreamInvalid // more than declared (and so over the cap)
		}
		buf.Write(c.GetData())
		final = c.GetFinal()
	}
	if int64(buf.Len()) != size {
		return nil, ErrStreamInvalid
	}
	// Nothing may follow the final frame.
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		return nil, ErrStreamInvalid
	}
	return &received{header: header, data: buf.Bytes()}, nil
}

// fetchFailed logs the transport error (sanitized) and returns ErrFetchFailed,
// which carries neither the error text nor any path.
func (in *Installer) fetchFailed(cause error) error {
	in.log().Warn("Module bundle stream failed", "error", logging.SanitizeLogValue(cause.Error()))
	return ErrFetchFailed
}

// verify runs steps 2-5 and builds the Bundle with the recomputed hash. On
// failure it returns the sentinel and the (log-only) cause.
func (in *Installer) verify(rec *received, publisher, name, version, platform string) (*bundle.Bundle, error, error) {
	h := rec.header

	digests := make(map[string][32]byte, len(h.GetBinaryDigests()))
	canonical := make(map[string]string, len(h.GetBinaryDigests()))
	for key, hexDigest := range h.GetBinaryDigests() {
		if !bundle.ValidPlatformKey(key) {
			return nil, ErrDigestListInvalid, nil
		}
		raw, err := hex.DecodeString(hexDigest)
		if err != nil || len(raw) != sha256.Size {
			return nil, ErrDigestListInvalid, nil
		}
		var d [32]byte
		copy(d[:], raw)
		digests[key] = d
		canonical[key] = hex.EncodeToString(d[:]) // lowercase, whatever spelling was received
	}
	own, ok := digests[platform]
	if !ok {
		return nil, ErrDigestListInvalid, nil
	}

	if sha256.Sum256(rec.data) != own {
		return nil, ErrBinaryDigestMismatch, nil
	}

	recomputed, err := bundle.ComputeContentHashFromDigests(digests, h.GetManifest())
	if err != nil {
		return nil, ErrDigestListInvalid, err
	}
	if recomputed != h.GetContentHash() {
		return nil, ErrContentHashMismatch, nil
	}

	manifest, err := modules.ParseModuleMetadata(bytes.NewReader(h.GetManifest()))
	if err != nil {
		return nil, ErrStreamInvalid, err
	}
	if manifest.Publisher != publisher || manifest.Name != name || manifest.Version != version {
		return nil, ErrIdentityMismatch, nil
	}

	b := &bundle.Bundle{
		Manifest:      manifest,
		ManifestBytes: h.GetManifest(),
		Binaries:      map[string]string{platform: h.GetFileName()},
		BinaryDigests: canonical,
		ContentHash:   recomputed,
		BinaryContent: map[string][]byte{platform: rec.data},
	}
	for _, s := range h.GetSignatures() {
		b.Signatures = append(b.Signatures, bundle.BundleSignature{
			Publisher: s.GetPublisher(), Algorithm: s.GetAlgorithm(), Signature: s.GetSignature(),
		})
	}
	return b, nil, nil
}

// place is step 7: it writes the verified bundle and swaps it into <root>/<name>.
func (in *Installer) place(b *bundle.Bundle, root, publisher, name, version, platform string) (*Result, error) {
	fail := func(sentinel error, cause error) (*Result, error) {
		return nil, in.refuse(sentinel, publisher, name, version, cause)
	}

	if err := EnsureProtectedDir(root); err != nil {
		return fail(ErrInstallFailed, err)
	}
	target := filepath.Join(root, name)

	existing, statErr := os.Lstat(target)
	hasOld := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fail(ErrInstallFailed, statErr)
	}
	if hasOld {
		if !existing.IsDir() {
			return fail(ErrInstallFailed, nil)
		}
		// A tree that cannot be read as a bundle is replaceable (the new bundle is
		// fully verified and the old one cannot load), but only when its manifest
		// does not name a different publisher.
		old, readErr := bundle.ReadInstalled(target)
		if readErr != nil {
			if pub, ok := manifestPublisher(target); ok && pub != publisher {
				return fail(ErrPublisherMismatch, nil)
			}
		} else if old.Manifest != nil {
			if old.Manifest.Publisher != publisher {
				return fail(ErrPublisherMismatch, nil)
			}
			if old.Manifest.Version == version && old.ContentHash == b.ContentHash {
				in.log().Info("Module bundle already installed",
					"publisher", logging.SanitizeLogValue(publisher),
					"name", logging.SanitizeLogValue(name),
					"version", logging.SanitizeLogValue(version))
				return &Result{Changed: false, ContentHash: b.ContentHash}, nil
			}
		}
	}

	stage, err := os.MkdirTemp(root, stagePrefix+"stage-*")
	if err != nil {
		return fail(ErrInstallFailed, err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := EnsureProtectedDir(stage); err != nil {
		return fail(ErrInstallFailed, err)
	}
	tree := filepath.Join(stage, "tree")
	if err := bundle.WriteInstalled(b, tree, bundle.WriteOptions{Platform: platform}); err != nil {
		return fail(ErrInstallFailed, err)
	}
	if err := CheckProtectedTree(tree); err != nil {
		return fail(ErrInstallFailed, err)
	}

	if !hasOld {
		if err := in.rename(tree, target); err != nil {
			return fail(ErrInstallFailed, err)
		}
	} else {
		aside := filepath.Join(stage, "old")
		if err := in.rename(target, aside); err != nil {
			return fail(ErrModuleInUse, err)
		}
		if err := in.rename(tree, target); err != nil {
			if rbErr := in.restore(aside, target); rbErr != nil {
				in.log().Error("Module bundle rollback failed",
					"name", logging.SanitizeLogValue(name), "error", logging.SanitizeLogValue(rbErr.Error()))
			}
			return fail(ErrInstallFailed, err)
		}
		// The deferred RemoveAll(stage) removes the old tree.
	}

	in.log().Info("Module bundle installed",
		"publisher", logging.SanitizeLogValue(publisher),
		"name", logging.SanitizeLogValue(name),
		"version", logging.SanitizeLogValue(version),
		"platform", logging.SanitizeLogValue(platform))
	return &Result{Changed: true, ContentHash: b.ContentHash}, nil
}

// manifestPublisher returns the publisher named by dir's module.yaml, if that
// file is a bounded regular file that parses.
func manifestPublisher(dir string) (string, bool) {
	path := filepath.Join(dir, bundle.ManifestFileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return "", false
	}
	f, err := os.Open(path) // #nosec G304 -- path is the installer-derived <root>/<name>/module.yaml
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	m, err := modules.ParseModuleMetadata(io.LimitReader(f, maxManifestBytes))
	if err != nil || m == nil {
		return "", false
	}
	return m.Publisher, true
}

// restore renames the old tree back with os.Rename directly: rolling back must
// not be subject to the same injected failure as the step it undoes.
func (in *Installer) restore(aside, target string) error {
	if err := os.Rename(aside, target); err != nil {
		return fmt.Errorf("restore previous module tree: %w", err)
	}
	return nil
}
