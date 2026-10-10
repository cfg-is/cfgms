// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenantCrossingExpirySweepInterval is how often the sweep looks for crossings that have
// reached ExpiresAt. The break-glass window is 30 minutes, so a minute keeps the expired
// meta-log entry close to the real expiry.
const tenantCrossingExpirySweepInterval = time.Minute

// tenantCrossingSweepActor is the audit actor recorded for expired crossing entries.
const tenantCrossingSweepActor = "system"

// startTenantCrossingExpirySweep starts the background goroutine that records the
// expired crossing meta-log entry (ADR-025 Amendment 8 A8.3). It mirrors
// startCredentialRequestSweep: its own stop/done channel pair, gated by a cluster lease.
func (s *Server) startTenantCrossingExpirySweep() {
	go func() {
		defer close(s.tenantCrossingExpirySweepDone)
		ticker := time.NewTicker(tenantCrossingExpirySweepInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopTenantCrossingExpirySweep:
				return
			case <-ticker.C:
				s.tenantCrossingExpirySweepLease.RunIfLeader(ctxkeys.WithSystem(context.Background()), func(ctx context.Context) {
					s.sweepExpiredTenantCrossings(ctx)
				})
			}
		}
	}()
}

// sweepExpiredTenantCrossings writes the expired meta-log entry for every crossing that
// reached ExpiresAt without being revoked. Each crossing is claimed with a conditional
// store UPDATE before its entries are written, so only the caller that wins the claim
// writes — the lease bounds the work to one node per cycle, the claim is what keeps it
// exactly-once across a lease handoff or a restart. Claiming first means a crash between
// the claim and the audit drain loses the entry rather than duplicating it.
func (s *Server) sweepExpiredTenantCrossings(ctx context.Context) {
	if s.tenantCrossingStore == nil {
		return
	}
	// A crossing is never claimed with only one of its two scopes writable.
	if s.rootTenantID(ctx) == "" {
		s.logger.Error("Tenant crossing expiry sweep: root tenant not resolvable, nothing claimed")
		return
	}
	now := time.Now().UTC()
	expired, err := s.tenantCrossingStore.ListUnrecordedExpiredTenantCrossings(ctx, now)
	if err != nil {
		s.logger.Error("Tenant crossing expiry sweep: failed to list expired crossings",
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, c := range expired {
		claimed, err := s.tenantCrossingStore.MarkTenantCrossingExpiryRecorded(ctx, c.ID, now)
		if err != nil {
			s.logger.Error("Tenant crossing expiry sweep: failed to claim crossing",
				"crossing_id", logging.SanitizeLogValue(c.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		if !claimed {
			continue
		}
		action, severity := "tenant.crossing_grant_expired", business.AuditSeverityHigh
		if c.Kind == business.TenantCrossingKindBreakGlass {
			action, severity = "tenant.crossing_break_glass_expired", business.AuditSeverityCritical
		}
		s.recordTenantCrossingAuditCtx(ctx, c.TenantID, tenantCrossingSweepActor, business.AuditUserTypeSystem, c, severity,
			action, "expired", map[string]string{"approval_state": string(c.ApprovalState)})
	}
}
