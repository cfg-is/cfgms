// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package configrouting provides per-tenant config source routing with background sync.
package configrouting

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gogittransport "github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/cfgis/cfgms/pkg/audit"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	configroutingiface "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// minPollInterval is the lower bound applied to every tenant's configured PollInterval.
const minPollInterval = time.Minute

// ErrCrossRootBoundary is returned by Register when the tenant's hierarchy root does
// not match the rootTenantID established at construction time.
// Multi-root operation requires separate SyncService instances per root.
var ErrCrossRootBoundary = errors.New("tenant belongs to a different root: cross-root sync is not supported in single-root deployments")

// tenantRemoteSyncer is the optional extension interface that a ConfigSourceRouter
// may implement to support background remote pull. controllerRouter satisfies this.
type tenantRemoteSyncer interface {
	SyncTenantWithRemote(ctx context.Context, tenantID string) (prevSHA, newSHA string, err error)
}

// SyncService polls all git-sourced tenants under a fixed root at their configured
// PollInterval. On each tick it:
//   - calls SyncTenantWithRemote via the router
//   - records a "config_source_sync" audit event when new commits arrive (both SHAs included)
//   - records a "config_source_sync_failed" audit event with failure_category on error
//   - calls cascadeFn only after a successful pull that introduced new commits
//
// Single-root boundary: all tenants must descend from the rootTenantID provided at
// construction. Register returns ErrCrossRootBoundary for tenants from a different tree.
type SyncService struct {
	router       configroutingiface.ConfigSourceRouter
	tenantStore  business.TenantStore
	auditManager *audit.Manager
	logger       logging.Logger
	cascadeFn    func(ctx context.Context, tenantID string) error
	rootTenantID string

	mu        sync.Mutex
	stops     map[string]context.CancelFunc
	wg        sync.WaitGroup
	runCtx    context.Context
	runCancel context.CancelFunc
	started   bool
}

// NewSyncService constructs a SyncService.
// cascadeFn is invoked after a successful pull that introduced new commits; pass a
// no-op (func(ctx,id) error { return nil }) in Phase 2 and wire the real cascade in Phase 3.
// rootTenantID defines the Apache OSS single-root scope for this service instance.
func NewSyncService(
	router configroutingiface.ConfigSourceRouter,
	tenantStore business.TenantStore,
	auditManager *audit.Manager,
	logger logging.Logger,
	cascadeFn func(ctx context.Context, tenantID string) error,
	rootTenantID string,
) *SyncService {
	return &SyncService{
		router:       router,
		tenantStore:  tenantStore,
		auditManager: auditManager,
		logger:       logger,
		cascadeFn:    cascadeFn,
		rootTenantID: rootTenantID,
		stops:        make(map[string]context.CancelFunc),
	}
}

// Run starts background sync goroutines for all tenants currently under rootTenantID
// that have a ConfigSourceTypeGit source. Cancelling ctx stops all goroutines.
// Run is idempotent — a second call after the first is a no-op.
func (s *SyncService) Run(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.runCtx, s.runCancel = context.WithCancel(ctx)
	s.started = true
	s.mu.Unlock()

	tenants, err := s.findGitTenants(s.runCtx)
	if err != nil {
		s.logger.Warn("sync-service: failed to enumerate git tenants on start",
			"root_tenant_id", logging.SanitizeLogValue(s.rootTenantID),
			"error_category", "initialization_failure",
		)
		return
	}

	for _, tenantID := range tenants {
		info, infoErr := s.router.GetEffectiveConfigSource(s.runCtx, tenantID)
		if infoErr != nil || info.Type != pkgconfig.ConfigSourceTypeGit {
			continue
		}
		s.startSyncGoroutine(tenantID, info)
	}
}

// Register adds a sync goroutine for tenantID after Run is already active.
// Returns ErrCrossRootBoundary when the tenant's hierarchy root differs from rootTenantID.
// Returns nil without starting a goroutine for non-git tenants.
func (s *SyncService) Register(tenantID string) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return fmt.Errorf("sync-service: Register called before Run")
	}
	if _, running := s.stops[tenantID]; running {
		s.mu.Unlock()
		return nil
	}
	ctx := s.runCtx
	s.mu.Unlock()

	path, err := s.tenantStore.GetTenantPath(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("sync-service: Register: failed to get tenant path for %q: %w", tenantID, err)
	}
	if len(path) == 0 || path[0] != s.rootTenantID {
		return ErrCrossRootBoundary
	}

	info, infoErr := s.router.GetEffectiveConfigSource(ctx, tenantID)
	if infoErr != nil || info.Type != pkgconfig.ConfigSourceTypeGit {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, running := s.stops[tenantID]; !running {
		s.startSyncGoroutineLocked(tenantID, info)
	}
	return nil
}

// Stop cancels all sync goroutines and blocks until they have drained.
// Returns an error if ctx is cancelled before all goroutines exit.
func (s *SyncService) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.runCancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("sync-service: Stop: timed out waiting for goroutines to drain: %w", ctx.Err())
	}
}

// startSyncGoroutine acquires mu and launches the per-tenant sync loop.
func (s *SyncService) startSyncGoroutine(tenantID string, info *pkgconfig.ConfigSourceInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startSyncGoroutineLocked(tenantID, info)
}

// startSyncGoroutineLocked launches the per-tenant sync loop. Caller must hold s.mu.
func (s *SyncService) startSyncGoroutineLocked(tenantID string, info *pkgconfig.ConfigSourceInfo) {
	tenantCtx, cancel := context.WithCancel(s.runCtx)
	s.stops[tenantID] = cancel

	interval := effectivePollInterval(info.PollInterval)
	copied := *info
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.syncLoop(tenantCtx, tenantID, &copied, interval)
	}()
}

// effectivePollInterval returns d floored to minPollInterval when d is zero, negative,
// or less than minPollInterval. This is a pure function exposed for unit testing.
func effectivePollInterval(d time.Duration) time.Duration {
	if d <= 0 || d < minPollInterval {
		return minPollInterval
	}
	return d
}

// syncLoop runs the periodic sync ticker for one tenant until ctx is cancelled.
func (s *SyncService) syncLoop(ctx context.Context, tenantID string, info *pkgconfig.ConfigSourceInfo, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncOnce(ctx, tenantID, info)
		}
	}
}

// syncOnce performs one pull-audit-cascade cycle for tenantID.
// Cascade is NOT triggered on pull failure — last-known-good is preserved.
func (s *SyncService) syncOnce(ctx context.Context, tenantID string, info *pkgconfig.ConfigSourceInfo) {
	syncer, ok := s.router.(tenantRemoteSyncer)
	if !ok {
		return
	}

	prevSHA, newSHA, err := syncer.SyncTenantWithRemote(ctx, tenantID)
	if err != nil {
		category := classifySyncFailure(err)
		s.logger.Warn("sync-service: git pull failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"url", logging.SanitizeLogValue(info.URL),
			"failure_category", category,
		)
		if auditErr := s.auditManager.RecordEvent(ctx, audit.NewEventBuilder().
			Tenant(tenantID).
			Type(business.AuditEventConfiguration).
			Action("config_source_sync_failed").
			User(audit.SystemUserID, business.AuditUserTypeSystem).
			Resource("config_source", tenantID, tenantID).
			Result(business.AuditResultError).
			Detail("failure_category", category).
			Detail("url", logging.SanitizeLogValue(info.URL))); auditErr != nil {
			s.logger.Warn("sync-service: failed to record sync_failed audit event",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error_category", "audit_failure",
			)
		}
		return
	}

	if prevSHA == newSHA {
		return // no new commits — nothing to cascade
	}

	if auditErr := s.auditManager.RecordEvent(ctx, audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action("config_source_sync").
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("config_source", tenantID, tenantID).
		Result(business.AuditResultSuccess).
		Detail("url", logging.SanitizeLogValue(info.URL)).
		Detail("previous_sha", prevSHA).
		Detail("new_sha", newSHA)); auditErr != nil {
		s.logger.Warn("sync-service: failed to record sync audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error_category", "audit_failure",
		)
	}

	if err := s.cascadeFn(ctx, tenantID); err != nil {
		s.logger.Warn("sync-service: cascade recompilation failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error_category", "cascade_failure",
		)
	}
}

// findGitTenants returns IDs of all tenants under rootTenantID with a git config source,
// walking the hierarchy recursively.
func (s *SyncService) findGitTenants(ctx context.Context) ([]string, error) {
	var result []string

	rootInfo, _ := s.router.GetEffectiveConfigSource(ctx, s.rootTenantID)
	if rootInfo != nil && rootInfo.Type == pkgconfig.ConfigSourceTypeGit {
		result = append(result, s.rootTenantID)
	}

	var walk func(parentID string) error
	walk = func(parentID string) error {
		children, err := s.tenantStore.GetChildTenants(ctx, parentID)
		if err != nil {
			return err
		}
		for _, child := range children {
			info, infoErr := s.router.GetEffectiveConfigSource(ctx, child.ID)
			if infoErr == nil && info.Type == pkgconfig.ConfigSourceTypeGit {
				result = append(result, child.ID)
			}
			if err := walk(child.ID); err != nil {
				return err
			}
		}
		return nil
	}
	return result, walk(s.rootTenantID)
}

// classifySyncFailure maps a sync error to one of the required failure categories:
// "credential_rejected", "network_unreachable", "repository_not_found", or "unknown".
func classifySyncFailure(err error) string {
	if errors.Is(err, gogittransport.ErrAuthorizationFailed) ||
		errors.Is(err, gogittransport.ErrAuthenticationRequired) {
		return "credential_rejected"
	}
	if errors.Is(err, gogittransport.ErrRepositoryNotFound) {
		return "repository_not_found"
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "401") || strings.Contains(msg, "403") ||
		strings.Contains(msg, "unauthorized") || strings.Contains(msg, "auth") ||
		strings.Contains(msg, "credential"):
		return "credential_rejected"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "dns") ||
		strings.Contains(msg, "dial") || strings.Contains(msg, "connect") ||
		strings.Contains(msg, "refused") || strings.Contains(msg, "network"):
		return "network_unreachable"
	case strings.Contains(msg, "not found") || strings.Contains(msg, "404") ||
		strings.Contains(msg, "repository not found"):
		return "repository_not_found"
	default:
		return "unknown"
	}
}
