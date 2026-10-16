// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gogithttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/security"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// gitsyncLeaseNamePrefix namespaces per-scope lease names so they cannot
// collide with any other package's cluster-singleton lease population
// (ADR-031 Decision 4).
const gitsyncLeaseNamePrefix = "controller-gitsync-scope-"

// LeaseJobFactory constructs the lease.SingletonJob a scope's polling cycle
// runs behind, given that scope's unique key. Each scope is an independent
// singleton (many scopes may legitimately sync concurrently across a
// cluster), so the factory is called once per scope rather than sharing one
// lease name across all of them.
type LeaseJobFactory func(name string) (lease.SingletonJob, error)

// SyncState represents the current state of a scope sync.
type SyncState string

const (
	SyncStateIdle    SyncState = "idle"
	SyncStateSyncing SyncState = "syncing"
	SyncStateError   SyncState = "error"
)

// ScopeStatus reports the current sync status for a scope.
type ScopeStatus struct {
	TenantPath    string     `json:"tenant_path"`
	Namespace     string     `json:"namespace"`
	State         SyncState  `json:"state"`
	LastSyncedSHA string     `json:"last_synced_sha,omitempty"`
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// Syncer pulls config entries from external git origins and writes them
// through to a ConfigStore. It is v1 read-only — it never writes back to
// any git origin.
type Syncer struct {
	mu            sync.RWMutex
	store         cfgconfig.ConfigStore
	bindings      *BindingStore
	workDir       string // local directory for cloned repos
	logger        logging.Logger
	statusMap     map[string]*ScopeStatus
	cancelFuncs   map[string]context.CancelFunc
	scopeLocks    sync.Map // scope key -> *sync.Mutex; serializes syncScope per scope
	ctx           context.Context
	cancel        context.CancelFunc
	newTickerFunc func(d time.Duration) (<-chan time.Time, func())
	syncNotify    chan<- struct{} // optional; receives a value after each TriggerSync call
	secretStore   secretsif.SecretStore

	// leaseJobFactory, when non-nil, builds the per-scope cluster-singleton
	// lease claim (ADR-031 Decision 4) each scope's polling cycle runs behind.
	// nil (the default) means no shared lease substrate is wired — polling runs
	// unconditionally, the correct behavior for a single-node deployment.
	// Webhook-triggered syncs (pkg/gitsync/webhook.go) never consult this: a
	// webhook must run on whichever node received the HTTP request, not on
	// whichever node holds the scope's polling lease.
	leaseJobFactory LeaseJobFactory
}

// Option is a functional option for NewSyncer.
type Option func(*Syncer)

// WithTickerFunc replaces the ticker factory used by polling goroutines.
// The factory must return a channel that emits ticks and a stop function.
// This option is intended for testing; production code should not set it.
func WithTickerFunc(fn func(d time.Duration) (<-chan time.Time, func())) Option {
	return func(s *Syncer) {
		s.newTickerFunc = fn
	}
}

// WithSyncNotify sets a channel that receives an empty struct after each
// TriggerSync call completes (whether successful or not). This option is
// intended for testing; production code should not set it.
func WithSyncNotify(ch chan<- struct{}) Option {
	return func(s *Syncer) {
		s.syncNotify = ch
	}
}

// WithSecretStore configures the SecretStore used to resolve "secret:<key>"
// credential and webhook-secret references. When nil (the default), any ref
// with the "secret:" prefix returns an error.
func WithSecretStore(store secretsif.SecretStore) Option {
	return func(s *Syncer) {
		s.secretStore = store
	}
}

// WithLeaseJobFactory configures the per-scope cluster-singleton lease claim
// (ADR-031 Decision 4) each scope's polling cycle runs behind. See
// Syncer.leaseJobFactory.
func WithLeaseJobFactory(f LeaseJobFactory) Option {
	return func(s *Syncer) {
		s.leaseJobFactory = f
	}
}

// NewSyncer creates a new Syncer. workDir is used for local git clones and is
// created if it does not already exist. Optional functional options (see
// WithTickerFunc, WithSyncNotify) may be provided for testing.
func NewSyncer(
	store cfgconfig.ConfigStore,
	bindings *BindingStore,
	workDir string,
	logger logging.Logger,
	opts ...Option,
) (*Syncer, error) {
	if err := os.MkdirAll(workDir, 0750); err != nil {
		return nil, fmt.Errorf("gitsync: failed to create work directory: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Syncer{
		store:       store,
		bindings:    bindings,
		workDir:     workDir,
		logger:      logger,
		statusMap:   make(map[string]*ScopeStatus),
		cancelFuncs: make(map[string]context.CancelFunc),
		ctx:         ctx,
		cancel:      cancel,
		newTickerFunc: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Start begins polling goroutines for all bindings that have a non-zero
// polling interval. Bindings added after Start is called also need an
// explicit AddBinding call to begin polling.
func (s *Syncer) Start(ctx context.Context) error {
	for _, b := range s.bindings.List() {
		s.startScope(b)
	}
	return nil
}

// startScope starts (or restarts) the polling goroutine for b. It initializes
// status if this is the first time we have seen this scope. If b.PollingInterval
// is zero, only a status entry is created — no goroutine is launched.
func (s *Syncer) startScope(b ScopeBinding) {
	key := b.key()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.statusMap[key]; !ok {
		s.statusMap[key] = &ScopeStatus{
			TenantPath:    b.TenantPath,
			Namespace:     b.Namespace,
			State:         SyncStateIdle,
			LastSyncedSHA: b.LastSyncedSHA,
		}
	}

	if b.PollingInterval == 0 {
		return // webhook-only scope; no polling goroutine
	}

	// Cancel existing polling goroutine if any.
	if cancel, ok := s.cancelFuncs[key]; ok {
		cancel()
	}

	scopeCtx, cancel := context.WithCancel(s.ctx)
	s.cancelFuncs[key] = cancel

	// Built once per scope-start (not per tick): the lease claim is stable for
	// the lifetime of this polling goroutine, matching every other converted
	// background loop's construction-time wiring (ADR-031 Decision 4).
	leaseJob := lease.SingletonJob{}
	if s.leaseJobFactory != nil {
		job, err := s.leaseJobFactory(gitsyncLeaseNamePrefix + key)
		if err != nil {
			s.logger.Error("gitsync: failed to construct per-scope lease job; polling will run ungated",
				"tenant_path", logging.SanitizeLogValue(b.TenantPath),
				"namespace", logging.SanitizeLogValue(b.Namespace),
				"error", logging.SanitizeLogValue(err.Error()))
		} else {
			leaseJob = job
		}
	}

	go func() {
		tickCh, stopTicker := s.newTickerFunc(b.PollingInterval)
		defer stopTicker()
		for {
			select {
			case <-scopeCtx.Done():
				return
			case <-tickCh:
				leaseJob.RunIfLeader(scopeCtx, func(ctx context.Context) {
					if err := s.TriggerSync(ctx, b); err != nil {
						s.logger.Error("gitsync: polling sync failed",
							"tenant_path", logging.SanitizeLogValue(b.TenantPath),
							"namespace", logging.SanitizeLogValue(b.Namespace),
							"error", logging.SanitizeLogValue(err.Error()))
					}
				})
			}
		}
	}()
}

// Stop shuts down all polling goroutines. After Stop returns, no further
// syncs are initiated.
func (s *Syncer) Stop() {
	s.cancel()
}

// TriggerSync performs an immediate sync for the given scope binding.
// Errors in one scope do not propagate to others — the caller is responsible
// for per-scope error handling (e.g., logging and continuing).
func (s *Syncer) TriggerSync(ctx context.Context, b ScopeBinding) error {
	key := b.key()

	s.mu.Lock()
	status, ok := s.statusMap[key]
	if !ok {
		status = &ScopeStatus{
			TenantPath: b.TenantPath,
			Namespace:  b.Namespace,
			State:      SyncStateIdle,
		}
		s.statusMap[key] = status
	}
	status.State = SyncStateSyncing
	s.mu.Unlock()

	err := s.syncScope(ctx, b)

	s.mu.Lock()
	now := time.Now()
	if err != nil {
		status.State = SyncStateError
		status.LastError = err.Error()
		s.logger.Error("gitsync: sync failed",
			"tenant_path", logging.SanitizeLogValue(b.TenantPath),
			"namespace", logging.SanitizeLogValue(b.Namespace),
			"origin_url", logging.SanitizeLogValue(b.OriginURL),
			"error", logging.SanitizeLogValue(err.Error()))
	} else {
		status.State = SyncStateIdle
		status.LastError = ""
		status.LastSyncedAt = &now
	}
	s.mu.Unlock()

	// Notify test observers (WithSyncNotify option) that this sync cycle is done.
	if s.syncNotify != nil {
		select {
		case s.syncNotify <- struct{}{}:
		default:
		}
	}

	return err
}

// syncScope performs the actual git clone/pull and config import for one
// binding.
//
// Syncs of one scope are serialized: webhook goroutines and the polling loop
// may call in concurrently, and an interleaved import/prune/SHA update could
// delete entries the other sync just wrote.
func (s *Syncer) syncScope(ctx context.Context, b ScopeBinding) error {
	lk, _ := s.scopeLocks.LoadOrStore(b.key(), &sync.Mutex{})
	mu := lk.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// sanitizeKey already replaces "/" (TenantPath and Namespace are attacker-
	// influenceable via the binding API), but a ".."-only segment or a stray
	// backslash on Windows could otherwise still walk outside workDir — bound
	// the result against workDir by a cleaned, symlink-resolved containment
	// check rather than trusting the character replacement alone (Issue #4340).
	repoDir, err := security.ValidateAndCleanPath(s.workDir, sanitizeKey(b.key()))
	if err != nil {
		return fmt.Errorf("gitsync: invalid scope path: %w", err)
	}

	auth, err := resolveCredentials(ctx, b.CredentialsRef, s.secretStore)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}

	branch := b.Branch
	if branch == "" {
		branch = "main"
	}

	var repo *gogit.Repository
	if _, statErr := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(statErr) {
		// Initial clone.
		cloneOpts := &gogit.CloneOptions{
			URL:           b.OriginURL,
			Auth:          auth,
			ReferenceName: plumbing.NewBranchReferenceName(branch),
			SingleBranch:  true,
		}
		repo, err = gogit.PlainCloneContext(ctx, repoDir, false, cloneOpts)
		if err != nil {
			return classifyGitError(err)
		}
	} else {
		// Incremental pull.
		repo, err = gogit.PlainOpen(repoDir)
		if err != nil {
			return fmt.Errorf("gitsync: failed to open local repo: %w", err)
		}
		worktree, err := repo.Worktree()
		if err != nil {
			return fmt.Errorf("gitsync: failed to get worktree: %w", err)
		}
		pullOpts := &gogit.PullOptions{
			RemoteName:    "origin",
			ReferenceName: plumbing.NewBranchReferenceName(branch),
			Auth:          auth,
			Force:         false,
		}
		if pullErr := worktree.PullContext(ctx, pullOpts); pullErr != nil && pullErr != gogit.NoErrAlreadyUpToDate {
			return classifyGitError(pullErr)
		}
	}

	// Determine current HEAD SHA.
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("gitsync: failed to read HEAD: %w", err)
	}
	currentSHA := head.Hash().String()

	// Idempotency check: skip if we already imported this commit.
	currentBinding, ok := s.bindings.Get(b.TenantPath, b.Namespace)
	if ok && currentBinding.LastSyncedSHA == currentSHA {
		s.logger.Info("gitsync: already up to date, skipping import",
			"tenant_path", logging.SanitizeLogValue(b.TenantPath),
			"namespace", logging.SanitizeLogValue(b.Namespace),
			"sha", currentSHA[:min(8, len(currentSHA))])
		return nil
	}

	// Import all config files from the repo root.
	written, err := s.importConfigs(ctx, b, repoDir, currentSHA)
	if err != nil {
		return err
	}

	// Remove store entries for config files deleted or renamed at the origin.
	if err := s.pruneRemoved(ctx, b, written); err != nil {
		return err
	}

	// Advance last-synced SHA in persistent store.
	if updateErr := s.bindings.UpdateSHA(b.TenantPath, b.Namespace, currentSHA); updateErr != nil {
		// Non-fatal: configs were imported; only the idempotency check for the
		// next call is affected.
		s.logger.Error("gitsync: failed to update last-synced SHA",
			"tenant_path", logging.SanitizeLogValue(b.TenantPath),
			"namespace", logging.SanitizeLogValue(b.Namespace),
			"error", logging.SanitizeLogValue(updateErr.Error()))
	}

	// Update in-memory status.
	s.mu.Lock()
	if st := s.statusMap[b.key()]; st != nil {
		st.LastSyncedSHA = currentSHA
	}
	s.mu.Unlock()

	s.logger.Info("gitsync: sync complete",
		"tenant_path", logging.SanitizeLogValue(b.TenantPath),
		"namespace", logging.SanitizeLogValue(b.Namespace),
		"sha", currentSHA[:min(8, len(currentSHA))])
	return nil
}

// importConfigs scans the top-level directory of repoDir for YAML and JSON
// files and writes each one as a ConfigEntry to the ConfigStore. Subdirectories
// are skipped (v1 flat-file-per-config layout only). It returns the set of
// config names written; the set is only valid when the error is nil.
func (s *Syncer) importConfigs(ctx context.Context, b ScopeBinding, repoDir, sha string) (map[string]struct{}, error) {
	dirEntries, err := os.ReadDir(repoDir)
	if err != nil {
		return nil, fmt.Errorf("gitsync: failed to read repo directory: %w", err)
	}

	// All reads go through a root handle so a path cannot resolve outside the
	// checkout, even if an entry is swapped for a link after the type check.
	root, err := os.OpenRoot(repoDir)
	if err != nil {
		return nil, fmt.Errorf("gitsync: failed to open repo directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	written := make(map[string]struct{})

	sourceSHA := sha
	if len(sourceSHA) > 8 {
		sourceSHA = sourceSHA[:8]
	}
	sourceTag := gitSyncSourcePrefix + logging.SanitizeLogValue(b.OriginURL) + "@" + sourceSHA

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue // skip directories including .git
		}

		name := dirEntry.Name()
		var format cfgconfig.ConfigFormat
		var configName string

		switch {
		case strings.HasSuffix(name, ".yaml"):
			format = cfgconfig.ConfigFormatYAML
			configName = strings.TrimSuffix(name, ".yaml")
		case strings.HasSuffix(name, ".yml"):
			format = cfgconfig.ConfigFormatYAML
			configName = strings.TrimSuffix(name, ".yml")
		case strings.HasSuffix(name, ".json"):
			format = cfgconfig.ConfigFormatJSON
			configName = strings.TrimSuffix(name, ".json")
		default:
			continue // skip non-config files
		}

		// Only regular files are imported. DirEntry.Type() does not follow
		// links, so symlinks and other special entries are refused here.
		if !dirEntry.Type().IsRegular() {
			s.warnSkippedEntry(b, name)
			continue
		}

		data, readErr := readRegularFile(root, name)
		if readErr != nil {
			if errors.Is(readErr, errNotRegular) {
				s.warnSkippedEntry(b, name)
				continue
			}
			return nil, fmt.Errorf("gitsync: failed to read config file %s: %w", name, readErr)
		}

		configEntry := &cfgconfig.ConfigEntry{
			Key: &cfgconfig.ConfigKey{
				TenantID:  b.TenantPath,
				Namespace: b.Namespace,
				Name:      configName,
			},
			Data:      data,
			Format:    format,
			Source:    sourceTag,
			CreatedBy: "git-sync",
			UpdatedBy: "git-sync",
		}

		if storeErr := s.store.StoreConfig(ctx, configEntry); storeErr != nil {
			return nil, fmt.Errorf("gitsync: failed to store config %s: %w", configName, storeErr)
		}
		written[configName] = struct{}{}
	}
	return written, nil
}

// gitSyncSourcePrefix marks store entries written by importConfigs.
const gitSyncSourcePrefix = "git-sync:"

// pruneRemoved deletes every entry in the binding's tenant and namespace that
// git sync wrote (Source starts with "git-sync:") but whose name is not in
// written. A tenant and namespace pair has exactly one binding, so any such
// entry belongs to it. Entries not written by git sync are never deleted.
func (s *Syncer) pruneRemoved(ctx context.Context, b ScopeBinding, written map[string]struct{}) error {
	entries, err := s.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		TenantID:  b.TenantPath,
		Namespace: b.Namespace,
	})
	if err != nil {
		return fmt.Errorf("gitsync: failed to list configs for pruning: %w", err)
	}

	var stale []*cfgconfig.ConfigKey
	for _, e := range entries {
		if e == nil || e.Key == nil || !strings.HasPrefix(e.Source, gitSyncSourcePrefix) {
			continue
		}
		if _, ok := written[e.Key.Name]; ok {
			continue
		}
		stale = append(stale, e.Key)
	}

	if len(stale) > 0 && len(written) == 0 {
		s.logger.Warn("gitsync: repository root yielded no config files, removing all git-sync entries",
			"tenant_path", logging.SanitizeLogValue(b.TenantPath),
			"namespace", logging.SanitizeLogValue(b.Namespace),
			"count", len(stale))
	}

	for _, key := range stale {
		if delErr := s.store.DeleteConfig(ctx, key); delErr != nil {
			return fmt.Errorf("gitsync: failed to delete config %s: %w", key.Name, delErr)
		}
	}
	return nil
}

// Status returns a snapshot of the current sync status for all known scopes.
func (s *Syncer) Status() []ScopeStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopeStatus, 0, len(s.statusMap))
	for _, st := range s.statusMap {
		out = append(out, *st)
	}
	return out
}

// AddBinding adds a scope binding to the persistent store and starts (or
// restarts) its polling goroutine.
func (s *Syncer) AddBinding(b ScopeBinding) error {
	if err := s.bindings.Add(b); err != nil {
		return err
	}
	s.startScope(b)
	return nil
}

// sanitizeKey converts a binding key to a filesystem-safe directory name by
// replacing path separators and other special characters with underscores.
func sanitizeKey(key string) string {
	return strings.NewReplacer("/", "_", ":", "_", " ", "_", "@", "_").Replace(key)
}

// resolveCredentials resolves a CredentialsRef string to a go-git auth method.
//
// Resolution rules:
//
//	"" (empty)       → anonymous access (nil auth)
//	"secret:<KEY>"   → retrieve password from SecretStore using KEY
//	"env:<VAR>"      → read password from environment variable VAR
//	any other string → treat as a filesystem path; read the password from the file
func resolveCredentials(ctx context.Context, ref string, store secretsif.SecretStore) (*gogithttp.BasicAuth, error) {
	if ref == "" {
		return nil, nil
	}
	if strings.HasPrefix(ref, "secret:") {
		if store == nil {
			return nil, fmt.Errorf("gitsync: secret: credential reference requires a configured SecretStore")
		}
		key := strings.TrimPrefix(ref, "secret:")
		s, err := store.GetSecret(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve credential from SecretStore for key %q: %w", key, err)
		}
		return &gogithttp.BasicAuth{Username: "git", Password: s.Value}, nil
	}
	if strings.HasPrefix(ref, "env:") {
		envVar := strings.TrimPrefix(ref, "env:")
		token := os.Getenv(envVar)
		if token == "" {
			return nil, fmt.Errorf("environment variable %s is not set or is empty", envVar)
		}
		return &gogithttp.BasicAuth{Username: "git", Password: token}, nil
	}
	// Treat as file path.
	raw, err := os.ReadFile(ref) // #nosec G304 - admin-supplied credential file path
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file %q: %w", ref, err)
	}
	token := strings.TrimSpace(string(raw))
	return &gogithttp.BasicAuth{Username: "git", Password: token}, nil
}

// classifyGitError maps go-git errors to gitsync sentinel errors where
// possible. Unknown errors are wrapped and returned as-is.
func classifyGitError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "authentication required") ||
		strings.Contains(msg, "authorization failed") ||
		strings.Contains(msg, "invalid credentials"):
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	case strings.Contains(msg, "repository not found") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "unable to connect") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "connection refused"):
		return fmt.Errorf("%w: %v", ErrOriginUnreachable, err)
	case strings.Contains(msg, "reference not found") ||
		strings.Contains(msg, "couldn't find remote ref"):
		return fmt.Errorf("%w: %v", ErrBranchNotFound, err)
	case strings.Contains(msg, "non-fast-forward") ||
		strings.Contains(msg, "diverged"):
		return fmt.Errorf("%w: %v", ErrConflictDetected, err)
	default:
		return fmt.Errorf("gitsync: git operation failed: %w", err)
	}
}

// errNotRegular reports that an opened entry is not a regular file.
var errNotRegular = errors.New("not a regular file")

// readRegularFile reads name through root and confirms, on the open handle,
// that it is a regular file before using its bytes.
func readRegularFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	return io.ReadAll(f)
}

// warnSkippedEntry logs a refused non-regular config entry. The link target is
// deliberately not logged.
func (s *Syncer) warnSkippedEntry(b ScopeBinding, name string) {
	s.logger.Warn("gitsync: skipping non-regular config entry",
		"tenant_path", logging.SanitizeLogValue(b.TenantPath),
		"namespace", logging.SanitizeLogValue(b.Namespace),
		"entry", logging.SanitizeLogValue(name))
}
