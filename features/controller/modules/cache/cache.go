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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
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

// CacheEntry is a catalog record returned by List.
type CacheEntry struct {
	Addr   bundle.ContentAddress
	Status ApprovalStatus
}

// approvalRecord is the on-disk format for approval state.
type approvalRecord struct {
	Status ApprovalStatus `yaml:"status"`
}

// ModuleCache is a content-addressed filesystem cache for module bundles.
// All public methods are safe for concurrent use.
type ModuleCache struct {
	mu      sync.RWMutex
	rootDir string
}

// New creates a ModuleCache rooted at rootDir, creating it if needed.
func New(rootDir string) (*ModuleCache, error) {
	if err := os.MkdirAll(rootDir, 0750); err != nil {
		return nil, fmt.Errorf("create module cache root: %w", err)
	}
	return &ModuleCache{rootDir: rootDir}, nil
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

	// Idempotent: exact content address already stored.
	if _, err := os.Stat(filepath.Join(dir, "manifest.yaml")); err == nil {
		return nil
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

	rec := approvalRecord{Status: ApprovalStatusPending}
	recBytes, err := yaml.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal approval record: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "approval.yaml"), recBytes, 0640); err != nil {
		return fmt.Errorf("write approval record: %w", err)
	}

	return nil
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

	manifestBytes, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var meta modules.ModuleMetadata
	if err := yaml.Unmarshal(manifestBytes, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	sigBytes, err := os.ReadFile(filepath.Join(dir, "signatures.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read signatures: %w", err)
	}
	var sigs []bundle.BundleSignature
	if err := yaml.Unmarshal(sigBytes, &sigs); err != nil {
		return nil, fmt.Errorf("unmarshal signatures: %w", err)
	}

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

// SetApprovalStatus updates the approval state for a cached bundle.
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

	rec := approvalRecord{Status: status}
	recBytes, err := yaml.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal approval record: %w", err)
	}
	return writeFileAtomic(filepath.Join(dir, "approval.yaml"), recBytes, 0640)
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

	recBytes, err := os.ReadFile(filepath.Join(dir, "approval.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrBundleNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read approval record: %w", err)
	}

	var rec approvalRecord
	if err := yaml.Unmarshal(recBytes, &rec); err != nil {
		return "", fmt.Errorf("unmarshal approval record: %w", err)
	}
	return rec.Status, nil
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
					if recBytes, readErr := os.ReadFile(filepath.Join(hashDir, "approval.yaml")); readErr == nil {
						var rec approvalRecord
						if yaml.Unmarshal(recBytes, &rec) == nil {
							status = rec.Status
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
