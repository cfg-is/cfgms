// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"time"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// syncStewardConfig delivers a steward's current effective configuration after an
// edit that changes it (tag or role change): it records a durable sync_config
// CommandRecord and triggers a config sync, then updates the delivery status to
// match the outcome — the same sequence a config upload uses. A failed delivery is
// logged and the record is left pending; it never fails the caller's request, since
// the edit that prompted the sync is already stored. It is a no-op when either the
// command store or the command publisher is not configured.
func (s *Server) syncStewardConfig(ctx context.Context, stewardID, tenantID, issuedBy string) {
	s.mu.RLock()
	store := s.commandStore
	s.mu.RUnlock()
	if store == nil || s.commandPublisher == nil {
		return
	}

	stewardIDForLog := logging.SanitizeLogValue(stewardID)
	rec := &business.CommandRecord{
		ID:             fmt.Sprintf("cfg-effective-%s-%d", stewardID, time.Now().UnixNano()),
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      stewardID,
		TenantID:       tenantID,
		IssuedAt:       time.Now().UTC(),
		IssuedBy:       issuedBy,
		DeliveryStatus: business.DeliveryStatusPending,
	}
	if err := store.CreateCommandRecord(ctx, rec); err != nil {
		s.logger.Warn("Failed to durably record effective-config sync",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	if _, err := s.commandPublisher.TriggerConfigSync(ctx, stewardID); err != nil {
		s.logger.Warn("Failed to trigger config sync after effective-config change",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
		if updErr := store.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusPending, logging.SanitizeLogValue(err.Error())); updErr != nil {
			s.logger.Warn("Failed to record delivery attempt failure",
				"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(updErr.Error()))
		}
		return
	}
	if err := store.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusDelivered, ""); err != nil {
		s.logger.Warn("Failed to record delivered status",
			"steward_id", stewardIDForLog, "error", logging.SanitizeLogValue(err.Error()))
	}
}

// syncStewardsMatchingRoleSelectors syncs every steward in tenantID whose selector
// match changes with a role edit: it matches any of the given selectors (the new
// selector and/or the replaced or deleted one). Matches are evaluated first via the
// controller's role-selector evaluator, and only matching stewards are published to.
func (s *Server) syncStewardsMatchingRoleSelectors(ctx context.Context, tenantID, issuedBy string, selectors ...string) {
	if s.controllerService == nil {
		return
	}
	s.mu.RLock()
	hasStore := s.commandStore != nil
	s.mu.RUnlock()
	if !hasStore || s.commandPublisher == nil {
		return
	}
	// Unscoped, system-internal read: the tenant filter below is the authoritative
	// scope (role fragments only apply within the role's own tenant).
	for _, st := range s.controllerService.ListFleetStewards(ctxkeys.WithSystem(ctx)) {
		if st.TenantID != tenantID {
			continue
		}
		for _, expr := range selectors {
			if expr == "" {
				continue
			}
			matched, err := s.controllerService.StewardMatchesSelector(ctx, st.ID, expr)
			if err != nil {
				s.logger.Warn("Skipping unparseable role selector during effective-config sync",
					"error", logging.SanitizeLogValue(err.Error()))
				continue
			}
			if matched {
				s.syncStewardConfig(ctx, st.ID, tenantID, issuedBy)
				break
			}
		}
	}
}
