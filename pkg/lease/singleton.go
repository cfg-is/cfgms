// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// SingletonJob wraps a cluster background loop's per-cycle execution so it
// runs on at most one node at a time, using this package's fenced lease as
// the singleton claim (ADR-031 Decision 4). A loop constructs one
// SingletonJob per lease name and calls RunIfLeader on every tick instead of
// hand-rolling its own acquire/renew/release sequence.
type SingletonJob struct {
	// Manager is the shared lease.Manager this job contends on. A nil Manager
	// means no shared substrate is wired — SingleServerMode has exactly one
	// node and nothing to exclude (ADR-029 Decision 4, mirrored by
	// ha.Manager.HasLeadership's own SingleServerMode short-circuit) — so
	// RunIfLeader always executes fn in that case.
	Manager *Manager

	// Name is this loop's lease name. Must be unique per loop within Manager.
	Name string

	// HolderID identifies this node/process contending for the lease.
	HolderID string

	// TTL is the lease TTL passed to Manager.TryAcquire/Renew; must equal
	// Manager's configured LeaseTTL.
	TTL time.Duration

	// RenewInterval controls how often RunIfLeader renews the lease while fn
	// is still running, so a cycle slower than TTL does not lose the lease
	// mid-execution and trigger a duplicate run elsewhere. Must be well under
	// TTL (mirroring pkg/lease.SafetyMargin's derivation).
	RenewInterval time.Duration

	// Logger receives acquire/renew diagnostics. May be nil.
	Logger logging.Logger
}

// NewSingletonJob constructs a SingletonJob, validating name/holderID are
// non-empty and, when manager is non-nil, that ttl and renewInterval are
// strictly positive. A nil manager skips the TTL/renewInterval checks — those
// parameters are meaningless without a lease substrate to apply them to.
func NewSingletonJob(manager *Manager, name, holderID string, ttl, renewInterval time.Duration, logger logging.Logger) (SingletonJob, error) {
	if name == "" {
		return SingletonJob{}, fmt.Errorf("lease: singleton job name cannot be empty")
	}
	if holderID == "" {
		return SingletonJob{}, fmt.Errorf("lease: singleton job holder ID cannot be empty")
	}
	if manager != nil {
		if ttl <= 0 {
			return SingletonJob{}, fmt.Errorf("lease: singleton job %q ttl must be positive", name)
		}
		if renewInterval <= 0 {
			return SingletonJob{}, fmt.Errorf("lease: singleton job %q renew interval must be positive", name)
		}
	}
	return SingletonJob{
		Manager:       manager,
		Name:          name,
		HolderID:      holderID,
		TTL:           ttl,
		RenewInterval: renewInterval,
		Logger:        logger,
	}, nil
}

// RunIfLeader attempts to claim j's lease for this cycle and, only on
// success, calls fn with a context that is cancelled if the lease is lost to
// a renewal failure before fn returns. Returns true iff fn was invoked.
//
// While fn runs, a background goroutine renews the lease every
// RenewInterval. If a renewal fails — the store is unreachable, or (should
// TTL/RenewInterval ever be misconfigured) the lease was actually lost to
// another holder — RunIfLeader cancels fn's context so fn can stop rather
// than keep mutating state after authority is gone. The lease itself is not
// explicitly released when fn returns; it is left to expire at TTL, which is
// simpler than a release round-trip and equally correct since no other node
// can acquire it before then regardless.
func (j SingletonJob) RunIfLeader(ctx context.Context, fn func(ctx context.Context)) bool {
	if j.Manager == nil {
		fn(ctx)
		return true
	}

	token, acquired, err := j.Manager.TryAcquire(ctx, j.Name, j.HolderID, j.TTL)
	if err != nil {
		j.logWarn("lease: acquire failed; skipping this cycle", err)
		return false
	}
	if !acquired {
		return false
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	renewalStopped := make(chan struct{})
	go func() {
		defer close(renewalStopped)
		j.renewWhileRunning(runCtx, cancelRun, token)
	}()

	fn(runCtx)
	cancelRun()
	<-renewalStopped
	return true
}

// renewWhileRunning renews j's lease every RenewInterval until ctx is done.
// A renewal failure invokes onLost (cancelling fn's context) and returns.
func (j SingletonJob) renewWhileRunning(ctx context.Context, onLost context.CancelFunc, token uint64) {
	ticker := time.NewTicker(j.RenewInterval)
	defer ticker.Stop()

	current := token
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newToken, err := j.Manager.Renew(ctx, j.Name, j.HolderID, current)
			if err != nil {
				j.logWarn("lease: renew failed mid-cycle; cancelling remaining work to avoid a duplicate run", err)
				onLost()
				return
			}
			current = newToken
		}
	}
}

func (j SingletonJob) logWarn(msg string, err error) {
	if j.Logger == nil {
		return
	}
	// j.Name is caller-supplied and can be tenant-derived (e.g. gitsync builds
	// it from TenantPath + Namespace), so it is tainted at this sink exactly
	// like the error text beside it.
	j.Logger.Warn(msg,
		"lease_name", logging.SanitizeLogValue(j.Name),
		"error", logging.SanitizeLogValue(err.Error()))
}
