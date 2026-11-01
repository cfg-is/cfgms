// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package git provides a read-only ConfigStore backed by an external HTTPS git repository.
// Credentials are fetched from pkg/secrets at transport time and never stored in struct fields.
package git

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"

	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/security"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrReadOnlySource is returned by all write methods — external git repos are never written to.
var ErrReadOnlySource = errors.New("git config store is read-only: external git sources cannot be written to")

const (
	// DefaultMaxCloneBytes bounds the on-disk size of one clone.
	DefaultMaxCloneBytes int64 = 256 << 20
	// DefaultMaxConfigFileBytes bounds one .yaml file read by GetConfig or ListConfigs.
	DefaultMaxConfigFileBytes int64 = 1 << 20
	// DefaultMaxListReadBytes bounds the total bytes one ListConfigs walk reads.
	DefaultMaxListReadBytes int64 = 32 << 20

	// cloneWatchInterval is how often the clone directory size is sampled mid-clone.
	cloneWatchInterval = 20 * time.Millisecond

	// syncStagingSuffix names the sibling directory a sync clones into before swapping.
	syncStagingSuffix = ".sync"
	// syncRetiredSuffix names the sibling directory the replaced clone is moved to.
	syncRetiredSuffix = ".old"
)

var (
	// ErrCloneTooLarge is returned when a clone exceeds the per-clone byte limit.
	ErrCloneTooLarge = errors.New("repository exceeds the clone size limit")
	// ErrConfigFileTooLarge is returned when a config file exceeds the per-file read limit.
	ErrConfigFileTooLarge = errors.New("config file exceeds the size limit")
	// ErrConfigReadTooLarge is returned when a ListConfigs walk exceeds the total read limit.
	ErrConfigReadTooLarge = errors.New("config files exceed the total read size limit")
)

// StoreOption configures optional GitConfigStore limits. Non-positive values keep the default.
type StoreOption func(*GitConfigStore)

// WithMaxCloneBytes sets the per-clone byte limit.
func WithMaxCloneBytes(n int64) StoreOption {
	return func(s *GitConfigStore) {
		if n > 0 {
			s.maxCloneBytes = n
		}
	}
}

// WithMaxConfigFileBytes sets the per-file read limit for GetConfig and ListConfigs.
func WithMaxConfigFileBytes(n int64) StoreOption {
	return func(s *GitConfigStore) {
		if n > 0 {
			s.maxFileBytes = n
		}
	}
}

// WithMaxListReadBytes sets the total bytes one ListConfigs walk may read.
func WithMaxListReadBytes(n int64) StoreOption {
	return func(s *GitConfigStore) {
		if n > 0 {
			s.maxListBytes = n
		}
	}
}

// GitConfigStore wraps LocalRepositoryStore to provide a read-only cfgconfig.ConfigStore
// view of a single external HTTPS git repository for one mount-pointed tenant.
//
// Work directory layout: <workDir>/<tenantID>/<sha256(sourceURL)>/
// The SHA256 hash of the source URL prevents path collisions for multiple repos under the same tenant.
//
// Credentials are fetched from secretStore at transport time (clone, pull) and are
// never stored in any struct field.
type GitConfigStore struct {
	source      *pkgconfig.ConfigSourceInfo
	tenantID    string
	workDir     string
	repoDir     string
	secretStore secretsiface.SecretStore
	logger      logging.Logger

	// dirMu guards the clone directory: readers hold it shared, and SyncWithRemote holds
	// it exclusively only while swapping a freshly synced clone into repoDir.
	dirMu sync.RWMutex
	// syncMu serializes SyncWithRemote calls so they never share a staging directory.
	syncMu sync.Mutex

	maxCloneBytes int64
	maxFileBytes  int64
	maxListBytes  int64
}

// NewGitConfigStore constructs a GitConfigStore, cloning the remote repository into
// <workDir>/<tenantID>/<sha256(sourceURL)>/ on first construction.
//
// workDir must already exist before this function is called.
// tenantID is validated via security.ValidateAndCleanPath to prevent path traversal attacks.
// Credentials are fetched at transport time; the credential value is not retained in any field.
func NewGitConfigStore(
	ctx context.Context,
	source *pkgconfig.ConfigSourceInfo,
	tenantID string,
	secretStore secretsiface.SecretStore,
	workDir string,
	logger logging.Logger,
	opts ...StoreOption,
) (store *GitConfigStore, err error) {
	// Validate tenantID against workDir before constructing any paths.
	// ValidateAndCleanPath requires workDir to exist; callers must ensure this.
	// The cleaned return value (not the raw tenantID) is used in filepath.Join so that
	// the sanitizer's return value acts as a natural path-injection barrier for CodeQL.
	cleanedBase, err := security.ValidateAndCleanPath(workDir, tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenantID %q: %w", tenantID, err)
	}

	urlHash := fmt.Sprintf("%x", sha256.Sum256([]byte(source.URL)))
	repoDir := filepath.Join(cleanedBase, urlHash)

	// A directory that already holds a clone is never removed on failure.
	_, statErr := os.Stat(filepath.Join(repoDir, ".git"))
	hadClone := statErr == nil

	if err := os.MkdirAll(repoDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create repo directory: %w", err)
	}
	// Remove the directory this call created (or an empty/partial one) when construction
	// fails, so a failed source leaves nothing behind.
	constructed := false
	defer func() {
		if !constructed && !hadClone {
			if rmErr := RemoveCloneDir(workDir, repoDir); rmErr != nil && logger != nil {
				logger.Warn("git-store: failed to remove clone directory after failed construction",
					"clone_dir_hash", urlHash,
					"error_category", categorizeError(rmErr),
				)
			}
		}
	}()

	s := &GitConfigStore{
		source:      source,
		tenantID:    tenantID,
		workDir:     workDir,
		repoDir:     repoDir,
		secretStore: secretStore,
		logger:      logger,

		maxCloneBytes: DefaultMaxCloneBytes,
		maxFileBytes:  DefaultMaxConfigFileBytes,
		maxListBytes:  DefaultMaxListReadBytes,
	}
	for _, opt := range opts {
		opt(s)
	}

	// Clone only if the repo hasn't been cloned yet.
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		username, password, credErr := s.fetchCredential(ctx)
		if credErr != nil {
			return nil, fmt.Errorf("failed to fetch credential for clone: %w", credErr)
		}
		localStore := gitstorage.NewLocalRepositoryStore(username, password)
		cloneErr := s.cloneWithLimit(ctx, localStore, repoDir)
		if cloneErr != nil {
			stripped := sanitizeCredential(cloneErr, password)
			password = "" //nolint:ineffassign // zeroize before return
			if errors.Is(cloneErr, ErrCloneTooLarge) {
				stripped = ErrCloneTooLarge
			}
			return nil, fmt.Errorf("failed to clone %s: %w", logging.SanitizeLogValue(source.URL), stripped)
		}
		password = "" //nolint:ineffassign // zeroize after success
	}

	constructed = true
	return s, nil
}

// cloneWithLimit makes a shallow single-branch clone and enforces maxCloneBytes. go-git
// has no transfer limit, so a watcher samples the clone directory and cancels the fetch
// once it grows past the limit; the size is checked once more after the fetch returns.
// The fetch does not check out the worktree: checkoutWithinLimit sizes the HEAD tree
// first and checks it out only when it fits. The caller removes the directory on error.
func (s *GitConfigStore) cloneWithLimit(ctx context.Context, localStore *gitstorage.LocalRepositoryStore, dir string) error {
	cloneCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var exceeded bool
	var mu sync.Mutex
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(cloneWatchInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if dirSize(dir) > s.maxCloneBytes {
					mu.Lock()
					exceeded = true
					mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()

	err := localStore.CloneShallow(cloneCtx, s.source.URL, dir)
	close(stop)
	<-finished

	mu.Lock()
	over := exceeded
	mu.Unlock()
	if over || dirSize(dir) > s.maxCloneBytes {
		return ErrCloneTooLarge
	}
	if err != nil {
		return err
	}
	if err := s.checkoutWithinLimit(dir); err != nil {
		return err
	}
	if dirSize(dir) > s.maxCloneBytes {
		return ErrCloneTooLarge
	}
	return nil
}

// checkoutWithinLimit checks out HEAD of the fetched-but-not-checked-out clone in dir,
// but only after proving the checkout fits maxCloneBytes. Cancelling a context cannot
// stop a go-git checkout, and a small, highly compressible pack can inflate to far more
// than the limit, so the inflated size is computed first from object headers (no object
// is inflated to size it): the on-disk fetch plus the commit, every tree and every blob
// occurrence in the HEAD tree. Repeated subtrees and blobs are counted per occurrence,
// because checkout writes each occurrence. Nothing is written to the worktree when the
// total exceeds the limit.
func (s *GitConfigStore) checkoutWithinLimit(dir string) error {
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		return fmt.Errorf("failed to open clone: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to read HEAD: %w", err)
	}

	budget := &cloneBudget{used: dirSize(dir), limit: s.maxCloneBytes}
	if err := budget.addObject(repo.Storer, head.Hash()); err != nil {
		return err
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return fmt.Errorf("failed to read HEAD commit: %w", err)
	}
	if err := budget.addTree(repo.Storer, commit.TreeHash); err != nil {
		return err
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to open worktree: %w", err)
	}
	// Same reset a non-NoCheckout clone performs.
	if err := w.Reset(&gogit.ResetOptions{Mode: gogit.MergeReset, Commit: head.Hash()}); err != nil {
		return fmt.Errorf("failed to check out HEAD: %w", err)
	}
	return nil
}

// cloneBudget accumulates the bytes a checkout would produce against a limit.
type cloneBudget struct {
	used  int64
	limit int64
}

// objectSizer is implemented by go-git's filesystem storage: it reads an object's size
// from its (pack or loose) header without inflating the object.
type objectSizer interface {
	EncodedObjectSize(plumbing.Hash) (int64, error)
}

// addObject adds the inflated size of object h, read from its header, and fails with
// ErrCloneTooLarge once the budget is exceeded.
func (b *cloneBudget) addObject(st storer.EncodedObjectStorer, h plumbing.Hash) error {
	sizer, ok := st.(objectSizer)
	if !ok {
		return fmt.Errorf("clone storage cannot size objects")
	}
	size, err := sizer.EncodedObjectSize(h)
	if err != nil {
		return fmt.Errorf("failed to size object: %w", err)
	}
	b.used += size
	if size < 0 || b.used > b.limit {
		return ErrCloneTooLarge
	}
	return nil
}

// addTree walks the tree rooted at root, adding every tree (sized before it is decoded)
// and every blob occurrence to the budget. Submodule entries are not checked out by a
// NoRecurseSubmodules checkout and are skipped.
func (b *cloneBudget) addTree(st storer.EncodedObjectStorer, root plumbing.Hash) error {
	pending := []plumbing.Hash{root}
	for len(pending) > 0 {
		h := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if err := b.addObject(st, h); err != nil {
			return err
		}
		tree, err := object.GetTree(st, h)
		if err != nil {
			return fmt.Errorf("failed to read tree: %w", err)
		}
		for _, e := range tree.Entries {
			switch e.Mode {
			case filemode.Dir:
				pending = append(pending, e.Hash)
			case filemode.Submodule:
				continue
			default:
				if err := b.addObject(st, e.Hash); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// dirSize returns the total size of the regular files under dir. Entries that vanish
// or cannot be read are skipped.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, infoErr := d.Info(); infoErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// CloneBytes returns the on-disk size of this store's clone.
func (s *GitConfigStore) CloneBytes() int64 {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	return dirSize(s.repoDir)
}

// RepoDir returns the clone directory of this store.
func (s *GitConfigStore) RepoDir() string { return s.repoDir }

// RemoveCloneDir deletes a clone directory and its tenant directory when that is left
// empty. dir is removed only when its cleaned path is strictly inside workDir
// (security.ValidateAndCleanPath); anything else is refused with an error.
func RemoveCloneDir(workDir, dir string) error {
	rel, err := relativeToWorkDir(workDir, dir)
	if err != nil {
		return fmt.Errorf("refusing to remove clone directory: %w", err)
	}
	cleaned, err := security.ValidateAndCleanPath(workDir, rel)
	if err != nil {
		return fmt.Errorf("refusing to remove clone directory: %w", err)
	}
	cleanedBase, err := security.ValidateAndCleanPath(workDir, ".")
	if err != nil {
		return fmt.Errorf("refusing to remove clone directory: %w", err)
	}
	if cleaned == cleanedBase {
		return errors.New("refusing to remove clone directory: path is the work directory itself")
	}
	if err := os.RemoveAll(cleaned); err != nil {
		return fmt.Errorf("failed to remove clone directory: %w", err)
	}
	// Best effort: drop the tenant directory when this was its last clone. os.Remove
	// fails (and is ignored) on a non-empty directory.
	if parent := filepath.Dir(cleaned); parent != cleanedBase {
		_ = os.Remove(parent)
	}
	return nil
}

// relativeToWorkDir returns dir relative to workDir. An absolute dir may be spelled
// against the raw workDir or against its symlink-resolved form (a store's repoDir is
// built from the resolved path: /private/var on macOS, long names on Windows), so both
// are tried. A dir outside both is returned unchanged for ValidateAndCleanPath to reject.
func relativeToWorkDir(workDir, dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return dir, nil
	}
	rawBase, err := filepath.Abs(workDir)
	if err != nil {
		return "", err
	}
	bases := []string{rawBase}
	if resolved, evalErr := filepath.EvalSymlinks(rawBase); evalErr == nil && resolved != rawBase {
		bases = append(bases, resolved)
	}
	// The target may itself be spelled through a symlink (/var vs /private/var), and
	// may be partly removed already, so resolve its deepest existing ancestor too.
	targets := []string{filepath.Clean(dir)}
	if resolved := evalDeepestExisting(targets[0]); resolved != targets[0] {
		targets = append(targets, resolved)
	}
	for _, b := range bases {
		for _, t := range targets {
			rel, relErr := filepath.Rel(b, t)
			if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
				return rel, nil
			}
		}
	}
	return dir, nil
}

// evalDeepestExisting resolves symlinks on the longest existing ancestor of p and
// re-appends the non-existent tail. It returns p unchanged when nothing resolves.
func evalDeepestExisting(p string) string {
	tail := ""
	cur := p
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, tail)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		tail = filepath.Join(filepath.Base(cur), tail)
		cur = parent
	}
}

// SyncWithRemote fetches the remote's current HEAD and, on success, returns its SHA.
//
// A sync is held to the same limits as the first clone: it makes a fresh shallow
// single-branch clone into a staging directory beside the clone (cloneWithLimit: the
// size watcher cancels the fetch past maxCloneBytes and the HEAD tree is sized before
// it is checked out), and only a clone that fits is swapped into place. On any failure
// — including ErrCloneTooLarge — the staging directory is removed and the store keeps
// serving the previously cloned state (last-known-good); the error is logged with
// sanitized fields and returned. Error messages never contain credential material.
func (s *GitConfigStore) SyncWithRemote(ctx context.Context) (string, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	username, password, err := s.fetchCredential(ctx)
	if err != nil {
		category := categorizeError(err)
		s.logger.Warn("git-store: sync credential fetch failed",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"url", logging.SanitizeLogValue(s.source.URL),
			"error_category", category,
		)
		return "", err
	}

	staging := s.repoDir + syncStagingSuffix
	if err := s.removeSibling(staging); err != nil {
		password = "" //nolint:ineffassign // zeroize before return
		return "", fmt.Errorf("sync: failed to clear staging directory: %w", err)
	}
	if err := os.MkdirAll(staging, 0750); err != nil {
		password = "" //nolint:ineffassign // zeroize before return
		return "", fmt.Errorf("sync: failed to create staging directory: %w", err)
	}

	localStore := gitstorage.NewLocalRepositoryStore(username, password)
	cloneErr := s.cloneWithLimit(ctx, localStore, staging)
	if cloneErr != nil {
		stripped := sanitizeCredential(cloneErr, password)
		password = "" //nolint:ineffassign // zeroize before warn/return
		if errors.Is(cloneErr, ErrCloneTooLarge) {
			stripped = ErrCloneTooLarge
		}
		s.discardStaging(staging)
		s.logger.Warn("git-store: sync pull failed",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"url", logging.SanitizeLogValue(s.source.URL),
			"error_category", categorizeError(stripped),
		)
		return "", stripped
	}
	password = "" //nolint:ineffassign // zeroize after success

	sha, err := headSHA(staging)
	if err != nil {
		s.discardStaging(staging)
		return "", fmt.Errorf("sync: failed to read HEAD of synced clone: %w", err)
	}
	if err := s.swapInClone(staging); err != nil {
		s.discardStaging(staging)
		return "", fmt.Errorf("sync: failed to replace clone: %w", err)
	}
	return sha, nil
}

// headSHA returns the HEAD commit SHA of the clone in dir.
func headSHA(dir string) (string, error) {
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		return "", err
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}
	return head.Hash().String(), nil
}

// swapInClone replaces repoDir with the clone in staging. Readers are excluded only for
// the two renames; when the second rename fails the original clone is restored.
func (s *GitConfigStore) swapInClone(staging string) error {
	retired := s.repoDir + syncRetiredSuffix
	if err := s.removeSibling(retired); err != nil {
		return err
	}

	s.dirMu.Lock()
	if err := os.Rename(s.repoDir, retired); err != nil {
		s.dirMu.Unlock()
		return err
	}
	if err := os.Rename(staging, s.repoDir); err != nil {
		restoreErr := os.Rename(retired, s.repoDir)
		s.dirMu.Unlock()
		if restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	s.dirMu.Unlock()

	if err := s.removeSibling(retired); err != nil && s.logger != nil {
		s.logger.Warn("git-store: failed to remove replaced clone directory",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"error_category", categorizeError(err),
		)
	}
	return nil
}

// removeSibling removes a sync staging or retired directory if it exists.
func (s *GitConfigStore) removeSibling(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	}
	return RemoveCloneDir(s.workDir, dir)
}

// discardStaging removes a failed sync's staging directory, logging a removal failure.
func (s *GitConfigStore) discardStaging(staging string) {
	if err := s.removeSibling(staging); err != nil && s.logger != nil {
		s.logger.Warn("git-store: failed to remove sync staging directory",
			"tenant_id", logging.SanitizeLogValue(s.tenantID),
			"error_category", categorizeError(err),
		)
	}
}

// GetCurrentSHA returns the HEAD commit SHA of the local clone.
// Returns an empty string (not an error) when the repository has no commits yet.
func (s *GitConfigStore) GetCurrentSHA() (string, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	repo, err := gogit.PlainOpen(s.repoDir)
	if err != nil {
		return "", fmt.Errorf("get current SHA: failed to open repo: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("get current SHA: failed to read HEAD: %w", err)
	}
	return head.Hash().String(), nil
}

// --- cfgconfig.ConfigStore read methods ---

// GetConfig reads the config file at <repoDir>/<subPath>/<namespace>/<name>.yaml.
func (s *GitConfigStore) GetConfig(_ context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return nil, err
	}
	// Validate for traversal, then read through a root that refuses symlinks:
	// the clone is an external source and may hold committed links.
	if _, err := security.ValidateAndCleanPath(s.repoDir, relPath); err != nil {
		return nil, fmt.Errorf("invalid config key path: %w", err)
	}

	// Refuse an oversized file before reading it.
	if size, sizeErr := s.lstatSize(relPath); sizeErr == nil && size > s.maxFileBytes {
		s.logOversize("get")
		return nil, ErrConfigFileTooLarge
	}

	data, info, err := security.ReadRegularFileNoSymlinks(s.repoDir, relPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cfgconfig.ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	if int64(len(data)) > s.maxFileBytes {
		s.logOversize("get")
		return nil, ErrConfigFileTooLarge
	}

	return &cfgconfig.ConfigEntry{
		Key:       key,
		Data:      data,
		Format:    cfgconfig.ConfigFormatYAML,
		UpdatedAt: info.ModTime(),
		CreatedAt: info.ModTime(),
	}, nil
}

// lstatSize returns the size of relPath inside the clone without following links.
func (s *GitConfigStore) lstatSize(relPath string) (int64, error) {
	root, err := os.OpenRoot(s.repoDir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(filepath.FromSlash(relPath))
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// logOversize records a refused read; only the operation and tenant are logged
// (no file name, since key-derived paths may name secret entries).
func (s *GitConfigStore) logOversize(op string) {
	if s.logger == nil {
		return
	}
	s.logger.Warn("git-store: refused over-limit config file",
		"tenant_id", logging.SanitizeLogValue(s.tenantID),
		"operation", op,
	)
}

// ListConfigs enumerates config files under <repoDir>/<subPath>/<filter.Namespace>/.
// When filter.TenantID is non-empty it is validated and the walk is skipped entirely
// if the filter names a different tenant than this store holds — matching the scoping
// behaviour of the flatfile and database providers.
func (s *GitConfigStore) ListConfigs(_ context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	base := s.repoDir
	if s.source.SubPath != "" {
		var err error
		base, err = security.ValidateAndCleanPath(s.repoDir, s.source.SubPath)
		if err != nil {
			return nil, fmt.Errorf("invalid subPath: %w", err)
		}
	}

	// Scope by TenantID: validate to catch traversal attempts, then skip the walk
	// entirely when the filter names a tenant other than the one this store holds.
	// Empty TenantID preserves today's unscoped-walk behaviour.
	if filter != nil && filter.TenantID != "" {
		if _, err := security.ValidateAndCleanPath(s.repoDir, filter.TenantID); err != nil {
			return nil, fmt.Errorf("invalid tenant ID in filter: %w", err)
		}
		if filter.TenantID != s.tenantID {
			return nil, nil
		}
	}

	namespace := ""
	if filter != nil {
		namespace = filter.Namespace
	}

	searchDir := base
	if namespace != "" {
		var err error
		searchDir, err = security.ValidateAndCleanPath(base, namespace)
		if err != nil {
			return nil, fmt.Errorf("invalid namespace: %w", err)
		}
	}

	configRoot, err := os.OpenRoot(searchDir)
	if err != nil {
		return nil, fmt.Errorf("open config search root: %w", err)
	}
	defer func() { _ = configRoot.Close() }()

	var entries []*cfgconfig.ConfigEntry
	var totalRead int64
	err = filepath.Walk(searchDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		relativePath, relErr := filepath.Rel(searchDir, path)
		if relErr != nil {
			return nil
		}
		if info.Size() > s.maxFileBytes {
			s.logOversize("list")
			return ErrConfigFileTooLarge
		}
		if totalRead+info.Size() > s.maxListBytes {
			s.logOversize("list")
			return ErrConfigReadTooLarge
		}
		data, readErr := configRoot.ReadFile(relativePath)
		if readErr != nil {
			return fmt.Errorf("read config file: %w", readErr)
		}
		totalRead += int64(len(data))
		if int64(len(data)) > s.maxFileBytes {
			s.logOversize("list")
			return ErrConfigFileTooLarge
		}
		if totalRead > s.maxListBytes {
			return ErrConfigReadTooLarge
		}

		rel, relErr := filepath.Rel(base, path)
		if relErr != nil {
			return nil
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 {
			return nil
		}
		ns := parts[0]
		name := strings.TrimSuffix(parts[len(parts)-1], ".yaml")

		entries = append(entries, &cfgconfig.ConfigEntry{
			Key: &cfgconfig.ConfigKey{
				TenantID:  s.tenantID,
				Namespace: ns,
				Name:      name,
			},
			Data:      data,
			Format:    cfgconfig.ConfigFormatYAML,
			UpdatedAt: info.ModTime(),
			CreatedAt: info.ModTime(),
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to list configs: %w", err)
	}
	return entries, nil
}

// headCommitFile returns the HEAD commit and the file at relPath in it. The clone is
// shallow (depth 1), so HEAD is the only commit available locally. found is false when
// the file does not exist at HEAD.
func (s *GitConfigStore) headCommitFile(relPath string) (commit *object.Commit, file *object.File, found bool, err error) {
	repo, err := gogit.PlainOpen(s.repoDir)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to open repo: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to read HEAD: %w", err)
	}
	commit, err = repo.CommitObject(head.Hash())
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to get commit object: %w", err)
	}
	file, err = commit.File(relPath)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return commit, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("failed to read file at HEAD: %w", err)
	}
	return commit, file, true, nil
}

// GetConfigHistory returns the history of the config file. Clones are shallow, so the
// history holds at most one entry: the HEAD commit, when it contains the file.
func (s *GitConfigStore) GetConfigHistory(_ context.Context, key *cfgconfig.ConfigKey, limit int) ([]*cfgconfig.ConfigEntry, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return nil, err
	}
	commit, _, found, err := s.headCommitFile(relPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get config history: %w", err)
	}
	entries := []*cfgconfig.ConfigEntry{}
	if !found || limit == 0 {
		return entries, nil
	}
	return append(entries, &cfgconfig.ConfigEntry{
		Key:       key,
		Data:      []byte(commit.Hash.String()),
		Format:    cfgconfig.ConfigFormatYAML,
		Version:   1,
		UpdatedAt: commit.Author.When,
		CreatedAt: commit.Author.When,
		UpdatedBy: commit.Author.Name,
		CreatedBy: commit.Author.Name,
	}), nil
}

// GetConfigVersion returns the config file content at a version. version is 1-indexed
// (1 = HEAD). Clones are shallow, so only version 1 exists.
func (s *GitConfigStore) GetConfigVersion(_ context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	if version < 1 {
		return nil, fmt.Errorf("version must be >= 1, got %d", version)
	}
	relPath, err := s.keyToRelativePath(key)
	if err != nil {
		return nil, err
	}
	if version > 1 {
		return nil, cfgconfig.ErrConfigNotFound
	}
	commit, file, found, err := s.headCommitFile(relPath)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, cfgconfig.ErrConfigNotFound
	}
	if file.Size > s.maxFileBytes {
		s.logOversize("version")
		return nil, ErrConfigFileTooLarge
	}
	content, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read file contents at version %d: %w", version, err)
	}
	return &cfgconfig.ConfigEntry{
		Key:       key,
		Data:      []byte(content),
		Format:    cfgconfig.ConfigFormatYAML,
		Version:   version,
		UpdatedAt: commit.Author.When,
		CreatedAt: commit.Author.When,
		UpdatedBy: commit.Author.Name,
		CreatedBy: commit.Author.Name,
	}, nil
}

// ResolveConfigWithInheritance delegates to GetConfig — inheritance resolution for
// external git sources is handled by the router layer, not the store.
func (s *GitConfigStore) ResolveConfigWithInheritance(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return s.GetConfig(ctx, key)
}

// ValidateConfig checks that the entry has a valid YAML format.
func (s *GitConfigStore) ValidateConfig(_ context.Context, config *cfgconfig.ConfigEntry) error {
	if config == nil {
		return fmt.Errorf("config entry is nil")
	}
	if config.Format != cfgconfig.ConfigFormatYAML {
		return cfgconfig.ErrInvalidFormat
	}
	return nil
}

// GetConfigStats computes basic stats by walking the repo directory.
func (s *GitConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	s.dirMu.RLock()
	defer s.dirMu.RUnlock()
	stats := &cfgconfig.ConfigStats{
		ConfigsByTenant:    make(map[string]int64),
		ConfigsByFormat:    make(map[string]int64),
		ConfigsByNamespace: make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	base := s.repoDir
	if s.source.SubPath != "" {
		var err error
		base, err = security.ValidateAndCleanPath(s.repoDir, s.source.SubPath)
		if err != nil {
			return nil, fmt.Errorf("invalid subPath for stats: %w", err)
		}
	}

	walkErr := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		stats.TotalConfigs++
		stats.TotalSize += info.Size()
		stats.ConfigsByFormat[string(cfgconfig.ConfigFormatYAML)]++
		stats.ConfigsByTenant[s.tenantID]++

		rel, relErr := filepath.Rel(base, path)
		if relErr == nil {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 1 {
				stats.ConfigsByNamespace[parts[0]]++
			}
		}

		modTime := info.ModTime()
		if stats.OldestConfig == nil || modTime.Before(*stats.OldestConfig) {
			t := modTime
			stats.OldestConfig = &t
		}
		if stats.NewestConfig == nil || modTime.After(*stats.NewestConfig) {
			t := modTime
			stats.NewestConfig = &t
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return nil, fmt.Errorf("failed to walk config directory: %w", walkErr)
	}

	if stats.TotalConfigs > 0 {
		stats.AverageSize = stats.TotalSize / stats.TotalConfigs
	}
	return stats, nil
}

// --- cfgconfig.ConfigStore write methods — always return ErrReadOnlySource ---

func (s *GitConfigStore) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return ErrReadOnlySource
}

func (s *GitConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return ErrReadOnlySource
}

// --- path helpers ---

// keyToRelativePath builds the relative path within the repo for a ConfigKey.
// Result: <subPath>/<namespace>/<name>.yaml (subPath may be empty)
// Uses path.Join (always forward slashes) so the result is valid for both git
// tree operations (go-git always uses forward slashes) and security.ValidateAndCleanPath
// (filepath.Clean normalises forward slashes on all platforms).
func (s *GitConfigStore) keyToRelativePath(key *cfgconfig.ConfigKey) (string, error) {
	parts := []string{}
	if s.source.SubPath != "" {
		parts = append(parts, s.source.SubPath)
	}
	parts = append(parts, key.Namespace, key.Name+".yaml")
	return path.Join(parts...), nil
}

// --- credential and error helpers ---

// fetchCredential retrieves the HTTPS credential from secretStore at transport time.
// Returns empty strings when no CredentialRef is set. The credential value is never
// stored in any GitConfigStore field.
func (s *GitConfigStore) fetchCredential(ctx context.Context) (username, password string, err error) {
	if s.source.CredentialRef == "" {
		return "", "", nil
	}
	secret, err := s.secretStore.GetSecret(ctx, s.source.CredentialRef)
	if err != nil {
		return "", "", fmt.Errorf("failed to get credential %q: %w", s.source.CredentialRef, err)
	}
	// Refuse a credential not bound to this repository before its value is
	// returned for use in an Authorization header. The binding comes from the
	// secret's own metadata; a store that returns none fails closed.
	if err := pkgconfig.CheckCredentialBinding(secret, s.source.URL); err != nil {
		return "", "", err
	}
	return "x-access-token", secret.Value, nil
}

// sanitizeCredential removes occurrences of the credential value from an error's message.
// This prevents go-git transport errors from leaking credential material.
func sanitizeCredential(err error, credential string) error {
	if err == nil || credential == "" {
		return err
	}
	sanitized := strings.ReplaceAll(err.Error(), credential, "[REDACTED]")
	return errors.New(sanitized)
}

// categorizeError returns a coarse error category string suitable for structured logging.
// Raw error text is never included — only a category label to avoid leaking internals.
func categorizeError(err error) string {
	if err == nil {
		return "none"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "auth") || strings.Contains(msg, "credential") || strings.Contains(msg, "unauthorized"):
		return "authentication_failure"
	case strings.Contains(msg, "network") || strings.Contains(msg, "connect") || strings.Contains(msg, "dial") || strings.Contains(msg, "timeout"):
		return "network_failure"
	case strings.Contains(msg, "not found") || strings.Contains(msg, "no such"):
		return "not_found"
	default:
		return "unknown"
	}
}
