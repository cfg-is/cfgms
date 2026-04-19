// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gitsync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gogithttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

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
	ctx           context.Context
	cancel        context.CancelFunc
	newTickerFunc func(d time.Duration) (<-chan time.Time, func())
	syncNotify    chan<- struct{} // optional; receives a value after each TriggerSync call
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

	go func() {
		tickCh, stopTicker := s.newTickerFunc(b.PollingInterval)
		defer stopTicker()
		for {
			select {
			case <-scopeCtx.Done():
				return
			case <-tickCh:
				if err := s.TriggerSync(scopeCtx, b); err != nil {
					s.logger.Error("gitsync: polling sync failed",
						"tenant_path", logging.SanitizeLogValue(b.TenantPath),
						"namespace", logging.SanitizeLogValue(b.Namespace),
						"error", err.Error())
				}
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
			"error", err.Error())
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
func (s *Syncer) syncScope(ctx context.Context, b ScopeBinding) error {
	repoDir := filepath.Join(s.workDir, sanitizeKey(b.key()))

	auth, err := resolveCredentials(b.CredentialsRef)
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
	if err := s.importConfigs(ctx, b, repoDir, currentSHA); err != nil {
		return err
	}

	// Advance last-synced SHA in persistent store.
	if updateErr := s.bindings.UpdateSHA(b.TenantPath, b.Namespace, currentSHA); updateErr != nil {
		// Non-fatal: configs were imported; only the idempotency check for the
		// next call is affected.
		s.logger.Error("gitsync: failed to update last-synced SHA",
			"tenant_path", logging.SanitizeLogValue(b.TenantPath),
			"namespace", logging.SanitizeLogValue(b.Namespace),
			"error", updateErr.Error())
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
// are skipped (v1 flat-file-per-config layout only).
func (s *Syncer) importConfigs(ctx context.Context, b ScopeBinding, repoDir, sha string) error {
	dirEntries, err := os.ReadDir(repoDir)
	if err != nil {
		return fmt.Errorf("gitsync: failed to read repo directory: %w", err)
	}

	sourceSHA := sha
	if len(sourceSHA) > 8 {
		sourceSHA = sourceSHA[:8]
	}
	sourceTag := "git-sync:" + logging.SanitizeLogValue(b.OriginURL) + "@" + sourceSHA

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

		data, readErr := os.ReadFile(filepath.Join(repoDir, name))
		if readErr != nil {
			return fmt.Errorf("gitsync: failed to read config file %s: %w", name, readErr)
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
			return fmt.Errorf("gitsync: failed to store config %s: %w", configName, storeErr)
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
// Resolution rules (v1):
//
//	"" (empty)     → anonymous access (nil auth)
//	"env:<VAR>"    → read password from environment variable VAR
//	any other string → treat as a filesystem path; read the password from the file
//
// TODO: integrate with pkg/secrets SecretStore once sub-story H lands.
func resolveCredentials(ref string) (*gogithttp.BasicAuth, error) {
	if ref == "" {
		return nil, nil
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
