// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package registration provides the IP-trust establishment evaluator (Issue #1694).
package registration

import (
	"context"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const defaultIPTrustThreshold = 30 * time.Minute

// IPTrustEvaluatorConfig holds construction parameters for IPTrustEvaluator.
type IPTrustEvaluatorConfig struct {
	// Store is the IP-trust durable storage backend.
	Store business.IPTrustStore

	// Threshold is the continuous-liveness window required before an IP is
	// promoted to trusted. Defaults to 30 minutes when zero.
	Threshold time.Duration

	// Logger is used for diagnostic output.
	Logger logging.Logger
}

// IPTrustEvaluator implements the 30-minute sustained-liveness IP-trust gate
// (Issue #1694, epic #1664). Once an approved steward has been continuously
// healthy from a given IP for at least Threshold, the evaluator calls
// store.AddTrustedRange to promote that IP to trusted status.
//
// In-memory timer state is intentionally non-durable: on a controller restart
// the 30-minute clock resets, which is fail-safe — existing trust entries in
// the store survive and are not re-evaluated.
type IPTrustEvaluator struct {
	store     business.IPTrustStore
	threshold time.Duration
	logger    logging.Logger

	mu     sync.Mutex
	timers map[string]time.Time // key: tenantID+"\x00"+ip → first-seen-healthy-at
}

// NewIPTrustEvaluator creates an IPTrustEvaluator with the given configuration.
func NewIPTrustEvaluator(cfg IPTrustEvaluatorConfig) *IPTrustEvaluator {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = defaultIPTrustThreshold
	}
	return &IPTrustEvaluator{
		store:     cfg.Store,
		threshold: threshold,
		logger:    cfg.Logger,
		timers:    make(map[string]time.Time),
	}
}

// HasTimer returns true if a liveness timer is active for the given
// (tenantID, ip) pair. Used by tests to inspect internal state.
func (e *IPTrustEvaluator) HasTimer(tenantID, ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.timers[tenantID+"\x00"+ip]
	return ok
}

// ForceTimerExpiry back-dates the liveness timer for (tenantID, ip) so the
// next healthy RecordLiveness call will exceed the threshold. Used by tests.
func (e *IPTrustEvaluator) ForceTimerExpiry(tenantID, ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := tenantID + "\x00" + ip
	if _, ok := e.timers[key]; ok {
		e.timers[key] = time.Now().Add(-e.threshold)
	}
}

// RecordLiveness records a liveness event for the given (tenantID, ip) pair.
//
// On healthy=true: upserts a per-(tenantID,ip) in-memory timer recording
// first-seen-healthy-at. When now−firstSeen ≥ threshold, calls
// store.AddTrustedRange(ctx, tenantID, ip+"/32", false) and clears the entry.
//
// On healthy=false: clears the timer entry, resetting the liveness clock.
func (e *IPTrustEvaluator) RecordLiveness(ctx context.Context, tenantID, stewardID, ip string, healthy bool) error {
	if ip == "" {
		return nil
	}

	key := tenantID + "\x00" + ip

	e.mu.Lock()
	defer e.mu.Unlock()

	if !healthy {
		if _, had := e.timers[key]; had {
			delete(e.timers, key)
			e.logger.Debug("IP trust timer reset — steward offline",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"steward_id", logging.SanitizeLogValue(stewardID),
				"ip", logging.SanitizeLogValue(ip))
		}
		return nil
	}

	// healthy=true path
	firstSeen, exists := e.timers[key]
	if !exists {
		e.timers[key] = time.Now()
		e.logger.Debug("IP trust timer started",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"steward_id", logging.SanitizeLogValue(stewardID),
			"ip", logging.SanitizeLogValue(ip),
			"threshold", e.threshold)
		return nil
	}

	elapsed := time.Since(firstSeen)
	if elapsed < e.threshold {
		return nil
	}

	// Threshold reached — but re-check current revocation state before promoting.
	// The in-memory timer only measures elapsed wall-clock time since it was
	// started; it knows nothing about a revocation an operator may have recorded
	// against this exact CIDR in the meantime (compromised host, incident
	// response). Re-arming trust from a stale liveness signal would silently
	// undo that decision — revocation must only be reversed by an explicit
	// re-trust action, never by the same kind of signal it was meant to stop
	// trusting.
	cidr := ip + "/32"
	revoked, err := e.isRevoked(ctx, tenantID, cidr)
	if err != nil {
		e.logger.Error("Failed to check IP trust revocation state before promotion",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"steward_id", logging.SanitizeLogValue(stewardID),
			"cidr", logging.SanitizeLogValue(cidr),
			"error", logging.SanitizeLogValue(err.Error()))
		return err
	}
	if revoked {
		delete(e.timers, key)
		e.logger.Warn("IP trust promotion refused — CIDR is currently revoked",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"steward_id", logging.SanitizeLogValue(stewardID),
			"cidr", logging.SanitizeLogValue(cidr))
		return nil
	}

	// Promote to trusted.
	if err := e.store.AddTrustedRange(ctx, tenantID, cidr, false); err != nil {
		e.logger.Error("Failed to add trusted IP range",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"steward_id", logging.SanitizeLogValue(stewardID),
			"cidr", logging.SanitizeLogValue(cidr),
			"error", logging.SanitizeLogValue(err.Error()))
		return err
	}

	delete(e.timers, key)
	e.logger.Info("IP promoted to trusted status",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"steward_id", logging.SanitizeLogValue(stewardID),
		"cidr", logging.SanitizeLogValue(cidr),
		"elapsed", elapsed)
	return nil
}

// isRevoked reports whether tenantID already has a revoked trust entry for the
// exact CIDR. ListTrustedRanges is used rather than IsTrusted because IsTrusted
// only answers "is this IP currently trusted" — it cannot distinguish "no entry
// ever existed" from "an entry exists but was revoked", and that distinction is
// exactly what a re-promotion decision needs.
func (e *IPTrustEvaluator) isRevoked(ctx context.Context, tenantID, cidr string) (bool, error) {
	entries, err := e.store.ListTrustedRanges(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.CIDR == cidr && entry.Revoked {
			return true, nil
		}
	}
	return false, nil
}
