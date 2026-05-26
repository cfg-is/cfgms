// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package registration provides the IP-trust expiry job (Issue #1697).
package registration

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	defaultIPTrustDarkWindow    = 30 * 24 * time.Hour
	defaultIPTrustCheckInterval = time.Hour
)

// IPTrustExpiryConfig holds construction parameters for IPTrustExpiryJob.
type IPTrustExpiryConfig struct {
	// Store is the IP-trust durable storage backend.
	Store business.IPTrustStore

	// TenantStore is used to discover all tenant IDs for per-tenant sweeps.
	TenantStore business.TenantStore

	// DarkWindow is the inactivity period after which a non-pre-seeded trusted
	// IP range is auto-revoked. Defaults to 30 days when zero.
	DarkWindow time.Duration

	// CheckInterval controls how often the expiry sweep runs. Defaults to 1 hour.
	CheckInterval time.Duration

	// Logger is used for diagnostic output.
	Logger logging.Logger
}

// IPTrustExpiryJob revokes trusted IP ranges that have been dark (no registrations
// and no healthy stewards) for longer than DarkWindow. Pre-seeded entries are always
// exempt from auto-revocation (Issue #1697).
type IPTrustExpiryJob struct {
	store         business.IPTrustStore
	tenants       business.TenantStore
	darkWindow    time.Duration
	checkInterval time.Duration
	logger        logging.Logger
	cancel        context.CancelFunc
}

// NewIPTrustExpiryJob creates an IPTrustExpiryJob with the given configuration.
func NewIPTrustExpiryJob(cfg IPTrustExpiryConfig) *IPTrustExpiryJob {
	darkWindow := cfg.DarkWindow
	if darkWindow == 0 {
		darkWindow = defaultIPTrustDarkWindow
	}
	checkInterval := cfg.CheckInterval
	if checkInterval == 0 {
		checkInterval = defaultIPTrustCheckInterval
	}
	return &IPTrustExpiryJob{
		store:         cfg.Store,
		tenants:       cfg.TenantStore,
		darkWindow:    darkWindow,
		checkInterval: checkInterval,
		logger:        cfg.Logger,
	}
}

// Start begins the background expiry sweep. It returns immediately; the sweep
// runs in a goroutine until ctx is cancelled or Stop is called.
func (j *IPTrustExpiryJob) Start(ctx context.Context) error {
	ctx, j.cancel = context.WithCancel(ctx)
	go j.run(ctx)
	j.logger.Info("IP-trust expiry job started",
		"dark_window", j.darkWindow,
		"check_interval", j.checkInterval)
	return nil
}

// Stop cancels the background sweep goroutine.
func (j *IPTrustExpiryJob) Stop() {
	if j.cancel != nil {
		j.cancel()
	}
	j.logger.Info("IP-trust expiry job stopped")
}

func (j *IPTrustExpiryJob) run(ctx context.Context) {
	ticker := time.NewTicker(j.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.expireStaleEntries(ctx)
		}
	}
}

// expireStaleEntries lists all tenants and revokes IP trust entries whose
// LastActivity is older than the dark window and that are not pre-seeded.
func (j *IPTrustExpiryJob) expireStaleEntries(ctx context.Context) {
	now := time.Now()
	cutoff := now.Add(-j.darkWindow)

	tenants, err := j.tenants.ListTenants(ctx, nil)
	if err != nil {
		j.logger.Error("IP-trust expiry: failed to list tenants", "error", err)
		return
	}

	for _, t := range tenants {
		entries, err := j.store.ListTrustedRanges(ctx, t.ID)
		if err != nil {
			j.logger.Error("IP-trust expiry: failed to list trusted ranges",
				"tenant_id", t.ID, "error", err)
			continue
		}

		for _, entry := range entries {
			if entry.Revoked || entry.PreSeeded {
				continue
			}
			if entry.LastActivity.Before(cutoff) {
				if err := j.store.RevokeTrustedRange(ctx, t.ID, entry.CIDR); err != nil {
					j.logger.Error("IP-trust expiry: failed to revoke stale range",
						"tenant_id", t.ID,
						"cidr", entry.CIDR,
						"last_activity", entry.LastActivity,
						"error", err)
					continue
				}
				j.logger.Info("IP-trust expiry: revoked dark-window range",
					"tenant_id", t.ID,
					"cidr", entry.CIDR,
					"last_activity", entry.LastActivity,
					"dark_window", j.darkWindow)
			}
		}
	}
}
