// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package registration provides the pending-registration expiry job (Issue #1697).
package registration

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	defaultPendingTimeout       = 5 * 24 * time.Hour
	defaultPendingCheckInterval = time.Hour
)

// PendingExpiryConfig holds construction parameters for PendingExpiryJob.
type PendingExpiryConfig struct {
	// Store is the pending-registration durable storage backend.
	Store business.PendingRegistrationStore

	// Timeout is the maximum time a pending registration may wait before it is
	// automatically expired. Defaults to 5 days when zero.
	Timeout time.Duration

	// CheckInterval controls how often the expiry sweep runs. Defaults to 1 hour.
	CheckInterval time.Duration

	// Logger is used for diagnostic output.
	Logger logging.Logger
}

// PendingExpiryJob marks pending registration entries older than Timeout as
// expired. It delegates to PendingRegistrationStore.ExpireStale and is
// idempotent — sweeping already-expired entries is a no-op (Issue #1697).
type PendingExpiryJob struct {
	store         business.PendingRegistrationStore
	timeout       time.Duration
	checkInterval time.Duration
	logger        logging.Logger
	cancel        context.CancelFunc
}

// NewPendingExpiryJob creates a PendingExpiryJob with the given configuration.
func NewPendingExpiryJob(cfg PendingExpiryConfig) *PendingExpiryJob {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultPendingTimeout
	}
	checkInterval := cfg.CheckInterval
	if checkInterval == 0 {
		checkInterval = defaultPendingCheckInterval
	}
	return &PendingExpiryJob{
		store:         cfg.Store,
		timeout:       timeout,
		checkInterval: checkInterval,
		logger:        cfg.Logger,
	}
}

// Start begins the background expiry sweep. It returns immediately; the sweep
// runs in a goroutine until ctx is cancelled or Stop is called.
func (j *PendingExpiryJob) Start(ctx context.Context) error {
	ctx, j.cancel = context.WithCancel(ctx)
	go j.run(ctx)
	j.logger.Info("Pending-registration expiry job started",
		"timeout", j.timeout,
		"check_interval", j.checkInterval)
	return nil
}

// Stop cancels the background sweep goroutine.
func (j *PendingExpiryJob) Stop() {
	if j.cancel != nil {
		j.cancel()
	}
	j.logger.Info("Pending-registration expiry job stopped")
}

func (j *PendingExpiryJob) run(ctx context.Context) {
	ticker := time.NewTicker(j.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.expireStale(ctx)
		}
	}
}

// expireStale marks pending entries whose ExpiresAt is older than the timeout
// cutoff as expired.
func (j *PendingExpiryJob) expireStale(ctx context.Context) {
	cutoff := time.Now().Add(-j.timeout)
	n, err := j.store.ExpireStale(ctx, cutoff)
	if err != nil {
		j.logger.Error("Pending-registration expiry: sweep failed", "error", err)
		return
	}
	if n > 0 {
		j.logger.Info("Pending-registration expiry: expired stale entries",
			"count", n,
			"cutoff", cutoff)
	}
}
