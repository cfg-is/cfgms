// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package cache implements the controller module cache.
// Bundles are stored content-addressed under:
//
//	<root>/<publisher>/<name>/<version>/<content_hash>/
//	    manifest.yaml
//	    binaries.yaml    (os-arch → relative path index)
//	    signatures.yaml
//	    approval.yaml    (approval state)
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

var (
	// ErrBundleNotFound is returned when the requested bundle is not in the cache.
	ErrBundleNotFound = errors.New("bundle not found in cache")

	// ErrContentAddressConflict is returned when a different bundle already exists at the
	// same (publisher, name, version) with a different content hash.
	ErrContentAddressConflict = errors.New("content address conflict: different content hash already cached for this publisher/name/version")
)

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
	store business.ModuleApprovalStore
}

// New creates a ModuleCache rooted at rootDir, creating it if needed.
func New(rootDir string) (*ModuleCache, error) {
	if err := os.MkdirAll(rootDir, 0750); err != nil {
		return nil, fmt.Errorf("create module cache root: %w", err)
	}
	return &ModuleCache{rootDir: rootDir}, nil
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

// hashToDir converts a base64 content hash to a filesystem-safe directory name.
// Standard base64 uses '+', '/', and '=' which are problematic in path components.
// This replaces them with URL-safe equivalents and strips padding so the name is
// unambiguous on all supported filesystems.
func hashToDir(hash string) string {
	r := strings.NewReplacer("/", "_", "+", "-", "=", "")
	return r.Replace(hash)
}

// Put stores b in the cache.
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
// exists under a different content hash — this indicates tampering or a hash collision.
func (c *ModuleCache) Put(b *bundle.Bundle) error {
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
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); err == nil {
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

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create bundle dir: %w", err)
	}

	manifestBytes, err := yaml.Marshal(b.Manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.yaml"), manifestBytes, 0640); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	sigBytes, err := yaml.Marshal(b.Signatures)
	if err != nil {
		return fmt.Errorf("marshal signatures: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "signatures.yaml"), sigBytes, 0640); err != nil {
		return fmt.Errorf("write signatures: %w", err)
	}

	binBytes, err := yaml.Marshal(b.Binaries)
	if err != nil {
		return fmt.Errorf("marshal binaries index: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "binaries.yaml"), binBytes, 0640); err != nil {
		return fmt.Errorf("write binaries index: %w", err)
	}

	// Store the original content hash so List() can recover it from the directory name.
	if err := writeFileAtomic(filepath.Join(dir, "content_hash.txt"), []byte(addr.ContentHash), 0640); err != nil {
		return fmt.Errorf("write content hash: %w", err)
	}

	_, statusErr := c.seedApprovalStatusLocked(dir, addr, ApprovalStatusPending)
	return statusErr
}

// Get retrieves a bundle from the cache by content address.
// Returns ErrBundleNotFound if no bundle exists at the given address.
func (c *ModuleCache) Get(addr bundle.ContentAddress) (*bundle.Bundle, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir, err := c.bundleDir(addr)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); errors.Is(err, os.ErrNotExist) {
		return nil, ErrBundleNotFound
	}

	// #nosec G304 -- bundleDir validates the content address and all following
	// reads use fixed filenames beneath the private cache directory.
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var meta modules.ModuleMetadata
	if err := yaml.Unmarshal(manifestBytes, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	// #nosec G304 -- dir is validated by bundleDir and signatures.yaml is a
	// fixed cache metadata filename.
	sigBytes, err := os.ReadFile(filepath.Join(dir, "signatures.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read signatures: %w", err)
	}
	var sigs []bundle.BundleSignature
	if err := yaml.Unmarshal(sigBytes, &sigs); err != nil {
		return nil, fmt.Errorf("unmarshal signatures: %w", err)
	}

	// #nosec G304 -- dir is validated by bundleDir and binaries.yaml is a fixed
	// cache metadata filename.
	binBytes, err := os.ReadFile(filepath.Join(dir, "binaries.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read binaries index: %w", err)
	}
	var binaries map[string]string
	if err := yaml.Unmarshal(binBytes, &binaries); err != nil {
		return nil, fmt.Errorf("unmarshal binaries index: %w", err)
	}

	return &bundle.Bundle{
		Manifest:    &meta,
		Binaries:    binaries,
		Signatures:  sigs,
		ContentHash: addr.ContentHash,
	}, nil
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
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); errors.Is(err, os.ErrNotExist) {
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
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); errors.Is(err, os.ErrNotExist) {
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
		if !pub.IsDir() {
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
					// Skip incomplete writes.
					if _, statErr := os.Stat(filepath.Join(hashDir, "manifest.yaml")); statErr != nil {
						continue
					}
					// Recover the original content hash (pre-sanitization).
					originalHash := hash.Name()
					// #nosec G304 -- hashDir is assembled exclusively from nested
					// ReadDir entries beneath c.rootDir; filename is fixed.
					if hashBytes, readErr := os.ReadFile(filepath.Join(hashDir, "content_hash.txt")); readErr == nil {
						originalHash = strings.TrimSpace(string(hashBytes))
					}
					addr := bundle.ContentAddress{
						Publisher:   pub.Name(),
						Name:        name.Name(),
						Version:     ver.Name(),
						ContentHash: originalHash,
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
