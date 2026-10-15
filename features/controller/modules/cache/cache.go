// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package cache implements the controller module cache.
// See ModuleCache for the on-disk layout.
package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

var (
	// ErrBundleNotFound is returned when the requested bundle is not in the cache.
	ErrBundleNotFound = errors.New("bundle not found in cache")

	// ErrBundlePayloadMissing is returned by Put when the bundle does not carry
	// its payload (manifest bytes and every binary's bytes). A cache entry
	// requires a payload that can be verified against the signed digests.
	ErrBundlePayloadMissing = errors.New("bundle payload missing: manifest bytes and every binary are required")

	// ErrContentAddressConflict is returned when a different bundle already exists at the
	// same (publisher, name, version) with a different content hash.
	ErrContentAddressConflict = errors.New("content address conflict: different content hash already cached for this publisher/name/version")

	// ErrContentHashIdentityConflict is returned when a bundle's content hash was
	// previously recorded in this cache under a different (publisher, name, version)
	// identity. A publisher signature is made over the content hash alone — nothing
	// in the signing scheme binds the manifest's Name/Version to that hash beyond the
	// manifest bytes that were originally hashed into it. A second manifest claiming a
	// different identity for the identical hash means the same (verified) signature
	// and hash are being replayed under a forged identity: the cache and approval key
	// must be derived from the verified record (the identity first seen for this hash),
	// not from whatever the incoming manifest currently claims (Issue #4341).
	ErrContentHashIdentityConflict = errors.New("content hash identity conflict: this content hash is already recorded under a different publisher/name/version")
)

// hashIndexDirName is the reserved top-level directory name used to persist the
// content-hash → identity reverse index (see checkAndRecordHashIdentityLocked).
// It cannot collide with a real publisher directory: bundleDir refuses any
// publisher component equal to this name.
const hashIndexDirName = ".cfgms-hash-index"

// ApprovalStatus represents the approval state of a cached bundle.
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
)

// CacheEntry is a catalog record returned by List. It is a plain value type
// describing one stored bundle — it holds no cached data and implements no
// caching behavior, so pkg/cache does not apply.
type CacheEntry struct { //architecture:allow-custom-cache -- value type describing one stored bundle, not a cache implementation
	Addr   bundle.ContentAddress
	Status ApprovalStatus
}

// approvalRecord is the on-disk format for approval state.
type approvalRecord struct {
	Status ApprovalStatus `yaml:"status"`
}

// ModuleCache is a content-addressed filesystem cache for module bundles.
// All public methods are safe for concurrent use.
//
// # On-disk layout
//
// Each entry lives in its own directory:
//
//	<root>/<publisher>/<name>/<version>/<content_hash>/
//	    root/            the complete bundle as an installation root, written by
//	                     bundle.WriteInstalled (module.yaml, bundle.yaml and
//	                     every platform's binary); signatures are stored verbatim
//	    approval.yaml    node-local approval state
//
// Put verifies the payload (content hash, every binary against its signed
// digest, size caps) before anything is created, and never stores a second
// content hash for one publisher/name/version.
//
// # Get versus GetPayload
//
// Get returns metadata only (manifest, binary index, digests, signatures,
// content hash) and reads no binary bytes; it is the cheap catalog read.
// GetPayload returns the payload and re-verifies the stored bytes on every
// call, optionally for one platform's binary only; only code that serves
// bundle bytes uses it.
//
// This is not a pkg/cache.Cache and must not be reimplemented on top of one:
// pkg/cache is an in-memory, TTL-and-eviction keyed cache, whereas this type is
// a durable on-disk store addressed by (publisher, name, version, content hash).
// Entries are the signed bundles authorizing publisher binaries to run on
// managed endpoints (ADR-006), so they must survive process restart and must
// never be evicted on a TTL or size bound — properties pkg/cache does not and
// should not provide. Approval status is the one field that is pluggable, via
// business.ModuleApprovalStore below.
type ModuleCache struct { //architecture:allow-custom-cache -- durable content-addressed on-disk bundle store, not an in-memory TTL cache; entries must never be evicted
	mu      sync.RWMutex
	rootDir string
	// store is the optional cluster-visible, CAS-protected approval-status
	// backend (Issue #3886, ADR-031 Decision 1). nil (the default) keeps
	// approval status in the local approval.yaml file, which is correct for
	// single-node deployments; SetApprovalStore wires a database-backed store
	// for clustered deployments. Bundle content (manifest/binaries/signatures)
	// stays local either way — only approval status is shared.
	store  business.ModuleApprovalStore
	logger logging.Logger
}

// New creates a ModuleCache rooted at rootDir, creating it if needed.
func New(rootDir string) (*ModuleCache, error) {
	if err := os.MkdirAll(rootDir, 0750); err != nil {
		return nil, fmt.Errorf("create module cache root: %w", err)
	}
	return &ModuleCache{rootDir: rootDir, logger: logging.NewNoopLogger()}, nil
}

// SetLogger sets the logger used for warnings about unreadable entries. nil
// restores the no-op logger.
func (c *ModuleCache) SetLogger(l logging.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l == nil {
		l = logging.NewNoopLogger()
	}
	c.logger = l
}

// SetApprovalStore wires a cluster-visible, CAS-protected ModuleApprovalStore
// backend so approval-status reads/writes become cluster-visible (Issue #3886).
// Call after New() but before serving traffic; nil (the default) keeps the
// existing local-filesystem approval.yaml behavior for single-node deployments.
func (c *ModuleCache) SetApprovalStore(s business.ModuleApprovalStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = s
}

// approvalKey derives the opaque, unique key business.ModuleApprovalStore uses to
// identify addr. Publisher/name/version are validated elsewhere to never contain
// "/", so this key is unambiguous despite ContentHash's base64 alphabet also
// containing "/".
func approvalKey(addr bundle.ContentAddress) string {
	return addr.Publisher + "/" + addr.Name + "/" + addr.Version + "/" + addr.ContentHash
}

// bundleDir returns the filesystem path for the given content address.
// The content hash is converted to a filesystem-safe directory name via hashToDir.
func (c *ModuleCache) bundleDir(addr bundle.ContentAddress) (string, error) {
	if addr.Publisher == hashIndexDirName {
		return "", fmt.Errorf("invalid publisher: %q is a reserved name", hashIndexDirName)
	}
	if err := validateComponent(addr.Publisher); err != nil {
		return "", fmt.Errorf("invalid publisher: %w", err)
	}
	if err := validateComponent(addr.Name); err != nil {
		return "", fmt.Errorf("invalid name: %w", err)
	}
	if err := validateComponent(addr.Version); err != nil {
		return "", fmt.Errorf("invalid version: %w", err)
	}
	if addr.ContentHash == "" {
		return "", fmt.Errorf("invalid content hash: must not be empty")
	}
	if strings.Contains(addr.ContentHash, "..") {
		return "", fmt.Errorf("invalid content hash: must not contain dot sequences: %q", addr.ContentHash)
	}
	return filepath.Join(c.rootDir, addr.Publisher, addr.Name, addr.Version, hashToDir(addr.ContentHash)), nil
}

// validateComponent rejects empty strings and path traversal sequences.
// Used for publisher, name, and version — not for content hashes (see hashToDir).
func validateComponent(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if strings.Contains(s, "..") || strings.ContainsRune(s, '/') || strings.ContainsRune(s, '\\') {
		return fmt.Errorf("must not contain path separators or dot sequences: %q", s)
	}
	return nil
}

// hashIdentityIndexPath returns the path of the reverse-index file recording
// which (publisher, name, version) identity a content hash was first seen
// under.
func (c *ModuleCache) hashIdentityIndexPath(contentHash string) string {
	return filepath.Join(c.rootDir, hashIndexDirName, hashToDir(contentHash)+".txt")
}

// checkAndRecordHashIdentityLocked enforces a 1:1 binding between a content
// hash and the (publisher, name, version) identity it is cached under. If
// addr.ContentHash has never been seen, it records addr's identity as
// authoritative. If it has been seen, addr's identity must match exactly —
// otherwise the incoming manifest is claiming an identity that disagrees with
// the one bound to this hash on first sight, and is refused with
// ErrContentHashIdentityConflict.
//
// c.mu must be held for writing.
func (c *ModuleCache) checkAndRecordHashIdentityLocked(addr bundle.ContentAddress) error {
	path := c.hashIdentityIndexPath(addr.ContentHash)
	want := addr.IdentityKey()

	// #nosec G304 -- path is built from rootDir and a sanitized content hash
	// (hashToDir), never from an unvalidated path component.
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if strings.TrimSpace(string(existing)) != want {
			return fmt.Errorf("%w: hash %q recorded for %q, manifest now claims %q",
				ErrContentHashIdentityConflict, addr.ContentHash, strings.TrimSpace(string(existing)), want)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		if mkErr := os.MkdirAll(filepath.Dir(path), 0750); mkErr != nil {
			return fmt.Errorf("create hash identity index dir: %w", mkErr)
		}
		return writeFileAtomic(path, []byte(want), 0640)
	default:
		return fmt.Errorf("read hash identity index: %w", err)
	}
}

// hashToDir converts a base64 content hash to a filesystem-safe directory name.
// Standard base64 uses '+', '/', and '=' which are problematic in path components.
// This replaces them with URL-safe equivalents and strips padding so the name is
// unambiguous on all supported filesystems.
func hashToDir(hash string) string {
	r := strings.NewReplacer("/", "_", "+", "-", "=", "")
	return r.Replace(hash)
}

// installedRootDirName is the entry subdirectory holding the installation root.
const installedRootDirName = "root"

// stageDirPrefix prefixes the temporary directories Put stages a bundle in.
const stageDirPrefix = ".stage-"

// entryRoot returns the installation root of the entry at dir.
func entryRoot(dir string) string { return filepath.Join(dir, installedRootDirName) }

// entryExists reports whether dir holds a stored bundle.
func entryExists(dir string) bool {
	_, err := os.Stat(filepath.Join(entryRoot(dir), bundle.ManifestFileName))
	return err == nil
}

// verifyPayload checks b's payload without touching the filesystem: the payload
// must be complete (every digest has its binary, and the reverse), every binary
// must hash to its digest, the manifest bytes must agree with the bundle's
// identity and the content hash recomputed from the manifest bytes and the
// digest list must equal b.ContentHash.
func verifyPayload(b *bundle.Bundle) error {
	if b == nil || b.Manifest == nil {
		return errors.New("bundle has no manifest")
	}
	if len(b.ManifestBytes) == 0 || len(b.BinaryContent) == 0 || len(b.BinaryDigests) == 0 {
		return ErrBundlePayloadMissing
	}
	digests := make(map[string][32]byte, len(b.BinaryDigests))
	for k, h := range b.BinaryDigests {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("%w: digest for %q is not a SHA-256 hex string", bundle.ErrDigestListInvalid, k)
		}
		var d [32]byte
		copy(d[:], raw)
		digests[k] = d
		data, ok := b.BinaryContent[k]
		if !ok {
			return fmt.Errorf("%w: digest for %q has no binary", ErrBundlePayloadMissing, k)
		}
		if sha256.Sum256(data) != d {
			return fmt.Errorf("%w: binary for %q does not match its digest", bundle.ErrContentHashMismatch, k)
		}
	}
	for k := range b.BinaryContent {
		if _, ok := digests[k]; !ok {
			return fmt.Errorf("%w: binary %q has no digest", bundle.ErrDigestListInvalid, k)
		}
	}
	meta, err := modules.ParseModuleMetadata(bytes.NewReader(b.ManifestBytes))
	if err != nil {
		return fmt.Errorf("%w: %w", bundle.ErrManifestInvalid, err)
	}
	if meta.Name != b.Manifest.Name || meta.Version != b.Manifest.Version || meta.Publisher != b.Manifest.Publisher {
		return errors.New("manifest bytes disagree with the bundle's manifest identity")
	}
	hash, err := bundle.ComputeContentHashFromDigests(digests, b.ManifestBytes)
	if err != nil {
		return err
	}
	if hash != b.ContentHash {
		return fmt.Errorf("%w: manifest and digests hash to %q but the bundle records %q",
			bundle.ErrContentHashMismatch, hash, b.ContentHash)
	}
	return nil
}

// Put stores b, which must carry its payload, in the cache.
//
// Everything is verified before any directory or approval record is created:
// ErrBundlePayloadMissing without a complete payload, bundle.ErrContentHashMismatch
// when a binary differs from its digest or the recomputed content hash differs
// from b.ContentHash, and the bundle size caps. Signatures are stored exactly as
// received.
//
// Idempotent: if b.ContentAddress() already exists in the cache (same content hash),
// Put returns nil without re-writing any files.
//
// Put is ingestion, not a decision: it seeds the approval status as pending only
// when the bundle has no status yet, and never overwrites an existing one. With
// a cluster-visible store wired (SetApprovalStore) the status is shared while
// bundle content stays node-local, so the same bundle is ingested again on every
// node that resolves it — an unconditional "seed as pending" write there would
// erase a rejection recorded on a peer node and let the bundle be auto-approved
// afresh (Issue #3886).
//
// Returns ErrContentAddressConflict if the same (publisher, name, version) tuple already
// exists under a different content hash: a second hash is never stored, so never served.
func (c *ModuleCache) Put(b *bundle.Bundle) error {
	if err := verifyPayload(b); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	addr := b.ContentAddress()
	dir, err := c.bundleDir(addr)
	if err != nil {
		return err
	}

	// Idempotent: exact content address already stored. Still ensure an approval
	// record exists — content can be present locally while the shared store has
	// no record for it (content cached before the store was wired).
	if entryExists(dir) {
		if err := c.checkAndRecordHashIdentityLocked(addr); err != nil {
			return err
		}
		_, statusErr := c.seedApprovalStatusLocked(dir, addr, ApprovalStatusPending)
		return statusErr
	}

	// Conflict check: a different hash exists for the same (publisher/name/version).
	safeHash := hashToDir(addr.ContentHash)
	versionDir := filepath.Join(c.rootDir, addr.Publisher, addr.Name, addr.Version)
	if ents, readErr := os.ReadDir(versionDir); readErr == nil {
		for _, e := range ents {
			if e.IsDir() && e.Name() != safeHash {
				return ErrContentAddressConflict
			}
		}
	}

	// Stage the whole bundle first: WriteInstalled enforces the size and file
	// caps, so a refusal leaves no entry directory behind.
	stage, err := os.MkdirTemp(c.rootDir, stageDirPrefix+"*")
	if err != nil {
		return fmt.Errorf("stage bundle: %w", err)
	}
	defer func() { _ = os.RemoveAll(stage) }()
	staged := filepath.Join(stage, installedRootDirName)
	if err := bundle.WriteInstalled(b, staged, bundle.WriteOptions{}); err != nil {
		return fmt.Errorf("store bundle: %w", err)
	}

	if err := c.checkAndRecordHashIdentityLocked(addr); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create bundle dir: %w", err)
	}
	if err := os.Rename(staged, entryRoot(dir)); err != nil {
		_ = os.Remove(dir)
		return fmt.Errorf("install bundle: %w", err)
	}

	_, statusErr := c.seedApprovalStatusLocked(dir, addr, ApprovalStatusPending)
	return statusErr
}

// Get retrieves a bundle's metadata from the cache by content address:
// manifest, binary index (os-arch to the absolute path of the stored file), digests, signatures and content hash. It reads no
// binary bytes and does not verify them; use GetPayload to serve a bundle.
// Returns ErrBundleNotFound if no bundle exists at the given address.
func (c *ModuleCache) Get(addr bundle.ContentAddress) (*bundle.Bundle, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return nil, err
	}
	if !entryExists(dir) {
		return nil, ErrBundleNotFound
	}
	b, err := bundle.ReadInstalledMetadata(entryRoot(dir), bundle.ReadOptions{})
	if err != nil {
		return nil, fmt.Errorf("read cached bundle: %w", err)
	}
	if b.ContentHash != addr.ContentHash {
		return nil, fmt.Errorf("%w: cached entry records a different content hash than its address", bundle.ErrContentHashMismatch)
	}
	// Binaries values are absolute paths of the stored files, which is what the
	// consumers that execute a cached module resolve them to.
	for k, rel := range b.Binaries {
		abs, pathErr := bundle.InstalledBinaryPath(entryRoot(dir), rel)
		if pathErr != nil {
			return nil, pathErr
		}
		b.Binaries[k] = abs
	}
	return b, nil
}

// Lookup returns the content address of the bundle stored for publisher, name
// and version, reading only that version's directory and no binary bytes. A
// version holds at most one content hash (Put refuses a second), so more than
// one entry is reported as an error rather than guessed between. Returns
// ErrBundleNotFound if nothing is stored for the triple.
func (c *ModuleCache) Lookup(publisher, name, version string) (bundle.ContentAddress, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if publisher == hashIndexDirName {
		return bundle.ContentAddress{}, fmt.Errorf("invalid publisher: %q is a reserved name", hashIndexDirName)
	}
	for _, comp := range []string{publisher, name, version} {
		if err := validateComponent(comp); err != nil {
			return bundle.ContentAddress{}, fmt.Errorf("invalid address component: %w", err)
		}
	}
	versionDir := filepath.Join(c.rootDir, publisher, name, version)
	hashes, err := os.ReadDir(versionDir)
	if errors.Is(err, os.ErrNotExist) {
		return bundle.ContentAddress{}, ErrBundleNotFound
	}
	if err != nil {
		return bundle.ContentAddress{}, fmt.Errorf("read module cache version directory: %w", err)
	}

	var found []bundle.ContentAddress
	for _, h := range hashes {
		if !h.IsDir() || strings.HasPrefix(h.Name(), stageDirPrefix) {
			continue
		}
		dir := filepath.Join(versionDir, h.Name())
		if !entryExists(dir) {
			continue
		}
		meta, readErr := bundle.ReadInstalledMetadata(entryRoot(dir), bundle.ReadOptions{})
		if readErr != nil {
			return bundle.ContentAddress{}, fmt.Errorf("read cached bundle: %w", readErr)
		}
		found = append(found, bundle.ContentAddress{Publisher: publisher, Name: name, Version: version, ContentHash: meta.ContentHash})
	}
	switch len(found) {
	case 0:
		return bundle.ContentAddress{}, ErrBundleNotFound
	case 1:
		return found[0], nil
	default:
		return bundle.ContentAddress{}, fmt.Errorf("module cache holds %d entries for one publisher/name/version", len(found))
	}
}

// GetPayload retrieves a bundle with its payload and re-verifies the stored
// bytes against the signed digests and content hash on every call. platform ""
// reads and verifies every binary; an os-arch key reads only that binary (still
// verified against its digest) and returns the full digest list, with the
// content hash recomputed from the manifest and the full list. Altered stored
// bytes fail with bundle.ErrContentHashMismatch. Returns ErrBundleNotFound if no
// bundle exists at the given address.
func (c *ModuleCache) GetPayload(addr bundle.ContentAddress, platform string) (*bundle.Bundle, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return nil, err
	}
	if !entryExists(dir) {
		return nil, ErrBundleNotFound
	}
	b, err := bundle.ReadInstalledPayload(entryRoot(dir), bundle.ReadOptions{Platform: platform})
	if err != nil {
		return nil, fmt.Errorf("read cached bundle payload: %w", err)
	}
	if b.ContentHash != addr.ContentHash {
		return nil, fmt.Errorf("%w: cached entry records a different content hash than its address", bundle.ErrContentHashMismatch)
	}
	return b, nil
}

// SetApprovalStatus overrides the approval state for a cached bundle,
// disregarding whatever state it is in. It is an administrative/seeding
// primitive — the approve/reject decision path is CompareAndSetApprovalStatus,
// and ingestion is Put, neither of which can discard another node's decision.
// Returns ErrBundleNotFound if no bundle exists at the given address.
func (c *ModuleCache) SetApprovalStatus(addr bundle.ContentAddress, status ApprovalStatus) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return err
	}
	if !entryExists(dir) {
		return ErrBundleNotFound
	}

	if c.store != nil {
		return c.overrideApprovalStatusInStore(addr, status)
	}
	return writeApprovalRecord(dir, status)
}

// overrideApprovalStatusInStore forces status onto addr's shared-store record,
// composed from the store's insert-if-absent and compare-and-set primitives:
// the interface deliberately exposes no unconditional write, so that no code
// path can overwrite a decision by accident. Retries a bounded number of times
// because a concurrent decision can land between the read and the write; a
// caller that keeps losing gets an error rather than a silent no-op.
// Assumes c.mu is held for writing.
func (c *ModuleCache) overrideApprovalStatusInStore(addr bundle.ContentAddress, status ApprovalStatus) error {
	ctx := context.Background()
	key := approvalKey(addr)
	target := business.ModuleApprovalStatus(status)

	current, err := c.store.PutApprovalStatusIfAbsent(ctx, key, target)
	if err != nil {
		return fmt.Errorf("set approval status: %w", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		if current == target {
			return nil
		}
		ok, casErr := c.store.CompareAndSetApprovalStatus(ctx, key, current, target)
		if casErr != nil {
			return fmt.Errorf("set approval status: %w", casErr)
		}
		if ok {
			return nil
		}
		observed, found, getErr := c.store.GetApprovalStatus(ctx, key)
		if getErr != nil {
			return fmt.Errorf("set approval status: %w", getErr)
		}
		if !found {
			return ErrBundleNotFound
		}
		current = observed
	}

	return fmt.Errorf("set approval status: approval status for this bundle is being changed concurrently")
}

// seedApprovalStatusLocked records status as addr's approval status only if it
// has none yet, and returns the status in force afterwards. dir must be addr's
// already-validated bundleDir and c.mu must be held for writing.
//
// This is the only write ingestion performs, so ingesting a bundle a second time
// — on this node or, through a shared store, on any peer — reports the standing
// decision instead of resetting it (Issue #3886).
func (c *ModuleCache) seedApprovalStatusLocked(dir string, addr bundle.ContentAddress, status ApprovalStatus) (ApprovalStatus, error) {
	if c.store != nil {
		effective, err := c.store.PutApprovalStatusIfAbsent(context.Background(), approvalKey(addr), business.ModuleApprovalStatus(status))
		if err != nil {
			return "", fmt.Errorf("record initial approval status: %w", err)
		}
		return ApprovalStatus(effective), nil
	}

	existing, err := readApprovalRecord(dir)
	switch {
	case err == nil:
		return existing, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", err
	}

	if err := writeApprovalRecord(dir, status); err != nil {
		return "", err
	}
	return status, nil
}

// readApprovalRecord reads the node-local approval.yaml under dir. The
// os.ErrNotExist from the underlying read is returned unwrapped-in-kind so
// callers can branch on errors.Is(err, os.ErrNotExist).
func readApprovalRecord(dir string) (ApprovalStatus, error) {
	// #nosec G304 -- dir is a validated bundleDir and approval.yaml is a fixed
	// filename beneath the private cache directory.
	recBytes, err := os.ReadFile(filepath.Join(dir, "approval.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", fmt.Errorf("read approval record: %w", err)
	}
	var rec approvalRecord
	if err := yaml.Unmarshal(recBytes, &rec); err != nil {
		return "", fmt.Errorf("unmarshal approval record: %w", err)
	}
	return rec.Status, nil
}

// writeApprovalRecord writes the node-local approval.yaml under dir.
func writeApprovalRecord(dir string, status ApprovalStatus) error {
	recBytes, err := yaml.Marshal(approvalRecord{Status: status})
	if err != nil {
		return fmt.Errorf("marshal approval record: %w", err)
	}
	return writeFileAtomic(filepath.Join(dir, "approval.yaml"), recBytes, 0640)
}

// HasSharedApprovalStore reports whether approval status is backed by the
// cluster-visible, CAS-protected store rather than this node's local
// approval.yaml files. Callers that ungate a decision on "every node sees the
// same status" must check this: without a store wired, an approve/reject
// decision is node-local and any-node service would diverge (Issue #3886).
func (c *ModuleCache) HasSharedApprovalStore() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store != nil
}

// GetApprovalStatus returns the current approval state for a cached bundle.
// Returns ErrBundleNotFound if no bundle exists at the given address.
func (c *ModuleCache) GetApprovalStatus(addr bundle.ContentAddress) (ApprovalStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return "", err
	}

	if c.store != nil {
		status, found, err := c.store.GetApprovalStatus(context.Background(), approvalKey(addr))
		if err != nil {
			return "", fmt.Errorf("get approval status: %w", err)
		}
		if !found {
			return "", ErrBundleNotFound
		}
		return ApprovalStatus(status), nil
	}

	status, err := readApprovalRecord(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrBundleNotFound
	}
	if err != nil {
		return "", err
	}
	return status, nil
}

// CompareAndSetApprovalStatus atomically transitions the approval status for
// addr from expectedCurrent to newStatus. Returns ok=false with a nil error if
// the current status is not expectedCurrent, so callers (ApprovalWorkflow) can
// distinguish "someone else already decided" from an infrastructure failure.
// Returns ErrBundleNotFound if no bundle exists at addr.
//
// In clustered mode (a store wired via SetApprovalStore) the compare-and-write
// is atomic across every controller node sharing the store, closing the
// approve/reject race a per-process mutex cannot close (Issue #3886). In
// single-node mode the in-process mutex below provides the same guarantee,
// since there is only one node to race against.
func (c *ModuleCache) CompareAndSetApprovalStatus(addr bundle.ContentAddress, expectedCurrent, newStatus ApprovalStatus) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return false, err
	}
	if !entryExists(dir) {
		return false, ErrBundleNotFound
	}

	if c.store != nil {
		ok, err := c.store.CompareAndSetApprovalStatus(context.Background(), approvalKey(addr), business.ModuleApprovalStatus(expectedCurrent), business.ModuleApprovalStatus(newStatus))
		if err != nil {
			return false, fmt.Errorf("compare-and-set approval status: %w", err)
		}
		return ok, nil
	}

	// #nosec G304 -- bundleDir validates the content address and approval.yaml
	// is a fixed filename beneath the private cache directory.
	recBytes, err := os.ReadFile(filepath.Join(dir, "approval.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return false, ErrBundleNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read approval record: %w", err)
	}
	var rec approvalRecord
	if err := yaml.Unmarshal(recBytes, &rec); err != nil {
		return false, fmt.Errorf("unmarshal approval record: %w", err)
	}
	if rec.Status != expectedCurrent {
		return false, nil
	}

	newRec := approvalRecord{Status: newStatus}
	newRecBytes, err := yaml.Marshal(newRec)
	if err != nil {
		return false, fmt.Errorf("marshal approval record: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "approval.yaml"), newRecBytes, 0640); err != nil {
		return false, err
	}
	return true, nil
}

// List returns all entries in the cache with their current approval status.
func (c *ModuleCache) List() ([]CacheEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var entries []CacheEntry

	// Stat first so we can detect non-directory roots consistently across
	// platforms — os.ReadDir on a regular file returns different error shapes
	// on Linux vs Windows, and we want the same wrapped error either way.
	info, err := os.Stat(c.rootDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat cache root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("cache root is not a directory: %s", c.rootDir)
	}

	publishers, err := os.ReadDir(c.rootDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cache root: %w", err)
	}

	for _, pub := range publishers {
		if !pub.IsDir() || pub.Name() == hashIndexDirName || strings.HasPrefix(pub.Name(), stageDirPrefix) {
			continue
		}
		names, _ := os.ReadDir(filepath.Join(c.rootDir, pub.Name()))
		for _, name := range names {
			if !name.IsDir() {
				continue
			}
			versions, _ := os.ReadDir(filepath.Join(c.rootDir, pub.Name(), name.Name()))
			for _, ver := range versions {
				if !ver.IsDir() {
					continue
				}
				hashes, _ := os.ReadDir(filepath.Join(c.rootDir, pub.Name(), name.Name(), ver.Name()))
				for _, hash := range hashes {
					if !hash.IsDir() {
						continue
					}
					hashDir := filepath.Join(c.rootDir, pub.Name(), name.Name(), ver.Name(), hash.Name())
					// Skip entries without the installation-root layout (incomplete
					// writes and entries from before the full bundle was stored).
					// Only metadata is read: no binary bytes.
					meta, readErr := bundle.ReadInstalledMetadata(entryRoot(hashDir), bundle.ReadOptions{})
					if readErr != nil {
						c.logger.Warn("skipping unreadable module cache entry",
							"entry", logging.SanitizeLogValue(filepath.Join(pub.Name(), name.Name(), ver.Name(), hash.Name())),
							"error", logging.SanitizeLogValue(readErr.Error()))
						continue
					}
					addr := bundle.ContentAddress{
						Publisher:   pub.Name(),
						Name:        name.Name(),
						Version:     ver.Name(),
						ContentHash: meta.ContentHash,
					}
					status := ApprovalStatusPending
					if c.store != nil {
						// Clustered mode: the store is authoritative — a decision
						// made on another node would leave the local approval.yaml
						// stale (Issue #3886). Fall back to pending if the store
						// has no record yet (a Put/SetApprovalStatus race window).
						if storeStatus, found, err := c.store.GetApprovalStatus(context.Background(), approvalKey(addr)); err == nil && found {
							status = ApprovalStatus(storeStatus)
						}
					} else {
						// #nosec G304 -- hashDir is assembled exclusively from nested
						// ReadDir entries beneath c.rootDir; filename is fixed.
						if recBytes, readErr := os.ReadFile(filepath.Join(hashDir, "approval.yaml")); readErr == nil {
							var rec approvalRecord
							if yaml.Unmarshal(recBytes, &rec) == nil {
								status = rec.Status
							}
						}
					}
					entries = append(entries, CacheEntry{Addr: addr, Status: status})
				}
			}
		}
	}

	return entries, nil
}

// writeFileAtomic writes data to path using a temp-file + rename for atomicity.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
