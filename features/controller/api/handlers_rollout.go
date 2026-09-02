// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultRolloutHaltThreshold is the per-ring failure rate (failed/(on_version+failed)) that
// triggers an automatic halt when a ring spec does not configure its own halt_threshold.
const defaultRolloutHaltThreshold = 0.05

// startRolloutRequest is the JSON body for POST /api/v1/rollout.
type startRolloutRequest struct {
	TargetVersion string `json:"target_version"`
	TenantID      string `json:"tenant_id"`
}

// startRolloutResponse is returned by POST /api/v1/rollout on 202 Accepted.
type startRolloutResponse struct {
	RolloutID string `json:"rollout_id"`
	Status    string `json:"status"`
}

// rolloutStatusResponse is returned by GET /api/v1/rollout/{rollout_id}.
//
// HealthMetricsAvailable reports whether the live health metrics (OnVersionPct,
// FailedCount, PendingCount) reflect a successful fleet query. When the fleet query
// fails for an in-progress rollout the metrics are unknown — not zero — so this flag
// is false and HealthMetricsError explains why. Operators must not read the zeroed
// metrics as "healthy ring, no failures" when HealthMetricsAvailable is false.
type rolloutStatusResponse struct {
	RolloutID              string     `json:"rollout_id"`
	TargetVersion          string     `json:"target_version"`
	CurrentRing            string     `json:"current_ring"`
	Status                 string     `json:"status"`
	OnVersionPct           float64    `json:"on_version_pct"`
	FailedCount            int        `json:"failed_count"`
	PendingCount           int        `json:"pending_count"`
	HealthMetricsAvailable bool       `json:"health_metrics_available"`
	HealthMetricsError     string     `json:"health_metrics_error,omitempty"`
	RingsCompleted         int        `json:"rings_completed"`
	RingsTotal             int        `json:"rings_total"`
	StartedAt              time.Time  `json:"started_at"`
	HaltedAt               *time.Time `json:"halted_at,omitempty"`
	Error                  string     `json:"error,omitempty"`
}

// rolloutHaltChans tracks per-rollout halt-signal channels. The goroutine selects on the
// channel; handleHaltRollout closes it to signal the goroutine to stop advancing.
var rolloutHaltChans sync.Map // map[rolloutID string] chan struct{}

// handleStartRollout handles POST /api/v1/rollout.
//
// Creates a RolloutRecord in the store and starts a background goroutine that advances
// the target version through the ordered ring set. Rings are processed in the order
// returned by cfg.EffectiveRings(); each ring soaks then passes a health gate before
// the next ring is advanced. If a ring's failure rate exceeds its halt_threshold the
// rollout transitions to halted and no further promotions occur.
func (s *Server) handleStartRollout(w http.ResponseWriter, r *http.Request) {
	if s.rolloutStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Rollout store not configured; durable RolloutStore is required",
			"ROLLOUT_STORE_UNAVAILABLE")
		return
	}

	_, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	var req startRolloutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode start rollout body", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}

	if req.TargetVersion == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "target_version is required", "MISSING_FIELDS")
		return
	}
	if !stewardBinaryVersionRe.MatchString(req.TargetVersion) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid target_version: "+logging.SanitizeLogValue(req.TargetVersion)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return
	}

	// Tenant scope: a caller may only target its own tenant subtree via req.TenantID; a
	// caller that supplies a tenant outside that subtree is rejected rather than silently
	// redirected. Only an unscoped caller (empty tenant — mTLS admin) may target any tenant.
	// The principal's GlobalScope flag is deliberately NOT consulted: GlobalScope is a
	// read-visibility axis (cross-tenant fleet queries), not an authorization gate for
	// which tenants a caller may target. Both session paths now compute it from actual
	// scope — web-session from acct.RootScope (middleware.go:433), cfg-CLI Bearer from
	// sess.TenantID=="" (middleware.go:357) — but using it for write isolation would be
	// the wrong signal. The explicit callerTenantID + isWithinTenantScope check was the
	// fix for Issue #3143 (a tenant-scoped caller could drive another tenant's rollout
	// when GlobalScope was relied on) and is the correct isolation mechanism here. This
	// mirrors the cross-tenant guard in handlers_upgrade.go (Issue #2340).
	tenantID := callerTenantID
	if req.TenantID != "" && req.TenantID != callerTenantID {
		if !isWithinTenantScope(callerTenantID, req.TenantID) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Cannot start a rollout for another tenant",
				"CROSS_TENANT")
			return
		}
		tenantID = req.TenantID
	}

	rings := s.effectiveRings()
	if len(rings.Rings) == 0 {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"No deployment rings configured",
			"NO_RINGS")
		return
	}

	rolloutID := uuid.New().String()
	record := &business.RolloutRecord{
		ID:             rolloutID,
		TenantID:       tenantID,
		TargetVersion:  req.TargetVersion,
		CurrentRing:    rings.Rings[0].Name,
		RingsCompleted: 0,
		RingsTotal:     len(rings.Rings),
		Status:         business.RolloutStatusInProgress,
		StartedAt:      time.Now().UTC(),
	}

	if err := s.rolloutStore.CreateRollout(r.Context(), record); err != nil {
		s.logger.Error("Failed to create rollout record",
			"error", logging.SanitizeLogValue(err.Error()),
			"target_version", logging.SanitizeLogValue(req.TargetVersion))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create rollout record", "CREATE_RECORD_ERROR")
		return
	}

	haltCh := make(chan struct{})
	rolloutHaltChans.Store(rolloutID, haltCh)

	// #nosec G118 -- rollout is persisted and intentionally survives the
	// initiating request; haltCh and per-command deadlines bound its lifecycle.
	go s.runRollout(context.Background(), record, rings.Rings, haltCh)

	s.logger.Info("Rollout started",
		"rollout_id", logging.SanitizeLogValue(rolloutID),
		"target_version", logging.SanitizeLogValue(req.TargetVersion),
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"rings_total", len(rings.Rings))

	s.writeResponse(w, http.StatusAccepted, startRolloutResponse{
		RolloutID: rolloutID,
		Status:    string(business.RolloutStatusInProgress),
	})
}

// handleGetRollout handles GET /api/v1/rollout/{rollout_id}.
//
// Returns the current rollout state: per-ring progress, on_version_pct, failed_count,
// pending_count, and overall status. Health metrics are computed live for in-progress
// rollouts against the current ring; terminal states (halted, completed) carry the
// last metrics observed at the time of the state transition.
func (s *Server) handleGetRollout(w http.ResponseWriter, r *http.Request) {
	if s.rolloutStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Rollout store not configured",
			"ROLLOUT_STORE_UNAVAILABLE")
		return
	}

	_, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	rolloutID := mux.Vars(r)["rollout_id"]
	if rolloutID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "rollout_id is required", "MISSING_ROLLOUT_ID")
		return
	}

	record, err := s.rolloutStore.GetRollout(r.Context(), rolloutID)
	if err != nil {
		if errors.Is(err, business.ErrRolloutNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Rollout record not found", "ROLLOUT_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve rollout record",
			"error", logging.SanitizeLogValue(err.Error()),
			"rollout_id", logging.SanitizeLogValue(rolloutID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve rollout record", "GET_RECORD_ERROR")
		return
	}

	// Tenant isolation: non-admin callers may only view their own tenant's rollouts.
	if callerTenantID != "" && record.TenantID != callerTenantID {
		s.writeErrorResponse(w, http.StatusForbidden, "Access denied", "FORBIDDEN")
		return
	}

	resp := rolloutStatusResponse{
		RolloutID:      record.ID,
		TargetVersion:  record.TargetVersion,
		CurrentRing:    record.CurrentRing,
		Status:         string(record.Status),
		RingsCompleted: record.RingsCompleted,
		RingsTotal:     record.RingsTotal,
		StartedAt:      record.StartedAt,
		HaltedAt:       record.HaltedAt,
		Error:          record.Error,
	}

	// Compute live health metrics for the current ring when in-progress. A failed fleet
	// query yields unknown counts, not zeros: surfacing them as 0% on_version / 0 failed /
	// 0 pending would give operators silently false data to base rollout decisions on. On
	// failure we log at warn level, leave the metrics at their zero value, and flag them as
	// unavailable so the response is unambiguous rather than deceptively healthy-looking.
	if record.Status == business.RolloutStatusInProgress && record.CurrentRing != "" && s.fleetQuery != nil {
		onVersion, failed, pending, qErr := s.queryRingHealthCounts(r.Context(), record.CurrentRing, record.TargetVersion, record.TenantID)
		if qErr != nil {
			s.logger.Warn("Ring health query failed for rollout status; reporting metrics as unavailable",
				"rollout_id", logging.SanitizeLogValue(rolloutID),
				"ring", logging.SanitizeLogValue(record.CurrentRing),
				"error", qErr)
			resp.HealthMetricsError = "ring health metrics are unavailable: the fleet query failed"
		} else {
			total := onVersion + failed + pending
			if total > 0 {
				resp.OnVersionPct = 100.0 * float64(onVersion) / float64(total)
			}
			resp.FailedCount = failed
			resp.PendingCount = pending
			resp.HealthMetricsAvailable = true
		}
	}

	s.writeSuccessResponse(w, resp)
}

// handleHaltRollout handles POST /api/v1/rollout/{rollout_id}/halt.
//
// Signals the rollout goroutine to stop advancing and transitions the rollout record
// to halted status. Idempotent: halting an already-halted rollout returns 200.
func (s *Server) handleHaltRollout(w http.ResponseWriter, r *http.Request) {
	if s.rolloutStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Rollout store not configured",
			"ROLLOUT_STORE_UNAVAILABLE")
		return
	}

	_, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	rolloutID := mux.Vars(r)["rollout_id"]
	if rolloutID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "rollout_id is required", "MISSING_ROLLOUT_ID")
		return
	}

	record, err := s.rolloutStore.GetRollout(r.Context(), rolloutID)
	if err != nil {
		if errors.Is(err, business.ErrRolloutNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Rollout record not found", "ROLLOUT_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to retrieve rollout record for halt",
			"error", logging.SanitizeLogValue(err.Error()),
			"rollout_id", logging.SanitizeLogValue(rolloutID))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve rollout record", "GET_RECORD_ERROR")
		return
	}

	// Tenant isolation.
	if callerTenantID != "" && record.TenantID != callerTenantID {
		s.writeErrorResponse(w, http.StatusForbidden, "Access denied", "FORBIDDEN")
		return
	}

	// If already terminal, report the current state without modifying it.
	if record.Status == business.RolloutStatusHalted || record.Status == business.RolloutStatusCompleted {
		s.writeSuccessResponse(w, startRolloutResponse{
			RolloutID: rolloutID,
			Status:    string(record.Status),
		})
		return
	}

	// Signal the goroutine to stop.
	if ch, loaded := rolloutHaltChans.Load(rolloutID); loaded {
		select {
		case <-ch.(chan struct{}):
			// already closed
		default:
			close(ch.(chan struct{}))
		}
	}

	now := time.Now().UTC()
	if updErr := s.rolloutStore.UpdateRolloutProgress(r.Context(), rolloutID,
		business.RolloutStatusHalted, record.CurrentRing, record.RingsCompleted,
		&now, "halted by operator"); updErr != nil {
		s.logger.Warn("Failed to persist halt for rollout",
			"rollout_id", logging.SanitizeLogValue(rolloutID), "error", logging.SanitizeLogValue(updErr.Error()))
	}

	s.logger.Info("Rollout halted by operator",
		"rollout_id", logging.SanitizeLogValue(rolloutID),
		"target_version", logging.SanitizeLogValue(record.TargetVersion))

	s.writeSuccessResponse(w, startRolloutResponse{
		RolloutID: rolloutID,
		Status:    string(business.RolloutStatusHalted),
	})
}

// runRollout is the background ring-advance goroutine. It processes rings in order:
// soak, check health, halt or advance. See handlers_rollout_test.go for the required tests.
//
// Durability note (v1): this goroutine runs in memory. A controller restart during a
// rollout loses orchestration state; the operator re-issues the rollout. Ring
// desired_version mutations persisted via setRingDesiredVersion survive (they are
// git-backed); only the progress tracking is lost. See ADR-008 for the durable
// workflow execution roadmap.
func (s *Server) runRollout(ctx context.Context, record *business.RolloutRecord, rings []controllerconfig.RingSpec, haltCh <-chan struct{}) {
	defer rolloutHaltChans.Delete(record.ID)

	for i, ring := range rings {
		// Check operator halt before processing each ring.
		select {
		case <-haltCh:
			return
		default:
		}

		// Advance this ring: update its desired_version in the in-memory config so
		// health checks can use the current target.
		s.setRingDesiredVersion(ring.Name, record.TargetVersion)

		// Persist current ring in the rollout record.
		if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
			business.RolloutStatusInProgress, ring.Name, i, nil, ""); updErr != nil {
			s.logger.Warn("Failed to update rollout current ring",
				"rollout_id", record.ID, "ring", ring.Name, "error", updErr)
		}

		// Soak: wait the ring's configured soak duration; skip if zero.
		soakDur := time.Duration(ring.Soak)
		if soakDur > 0 {
			// Signal that this ring's in-progress state is committed and the goroutine is
			// about to block on the soak. Tests use this to synchronize an operator halt
			// deterministically; nil in production.
			if s.onRolloutSoak != nil {
				s.onRolloutSoak(record.ID)
			}
			select {
			case <-haltCh:
				return
			case <-time.After(soakDur):
			}
		}

		// Query ring health after soak.
		onVersion, failed, pending, err := s.queryRingHealthCounts(ctx, ring.Name, record.TargetVersion, record.TenantID)
		if err != nil {
			s.logger.Error("Ring health query failed, halting rollout",
				"rollout_id", record.ID,
				"ring", ring.Name,
				"error", err)
			now := time.Now().UTC()
			if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
				business.RolloutStatusHalted, ring.Name, i, &now,
				"ring health query failed: "+err.Error()); updErr != nil {
				s.logger.Error("Failed to persist halted rollout status after ring health query failure",
					"rollout_id", record.ID, "ring", ring.Name, "error", updErr)
			}
			s.notifyRolloutTerminal(record.ID)
			return
		}

		// Identify failed stewards and add them to the deferred-retry list.
		failedIDs := s.failedStewardIDs(ctx, ring.Name, record.TargetVersion, record.TenantID)
		if len(failedIDs) > 0 {
			if appendErr := s.rolloutStore.AppendDeferredStewards(ctx, record.ID, failedIDs); appendErr != nil {
				s.logger.Warn("Failed to append deferred stewards",
					"rollout_id", record.ID, "ring", ring.Name, "error", appendErr)
			}
		}

		// Halt threshold: failed / (on_version + failed) > threshold.
		// Pending stewards are excluded: they are still in-flight and will be retried.
		// References: implementation notes in Issue #2340.
		threshold := ring.HaltThreshold
		if threshold == 0 {
			threshold = defaultRolloutHaltThreshold
		}
		denominator := float64(onVersion + failed)
		if denominator > 0 && float64(failed)/denominator > threshold {
			now := time.Now().UTC()
			haltMsg := fmt.Sprintf(
				"ring %q failure rate %.1f%% (failed=%d, on_version=%d) exceeds halt_threshold %.1f%%; pending=%d",
				ring.Name,
				float64(failed)/denominator*100,
				failed, onVersion,
				threshold*100,
				pending,
			)
			s.logger.Error("Rollout halted: failure rate exceeded threshold",
				"rollout_id", record.ID,
				"ring", ring.Name,
				"failed", failed,
				"on_version", onVersion,
				"threshold", threshold)
			if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
				business.RolloutStatusHalted, ring.Name, i, &now, haltMsg); updErr != nil {
				s.logger.Error("Failed to persist halted rollout status after failure-rate threshold exceeded",
					"rollout_id", record.ID, "ring", ring.Name, "error", updErr)
			}
			s.notifyRolloutTerminal(record.ID)
			return
		}

		// Ring cleared health gate. Mark it completed.
		if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
			business.RolloutStatusInProgress, "", i+1, nil, ""); updErr != nil {
			s.logger.Warn("Failed to advance rollout ring count",
				"rollout_id", record.ID, "ring", ring.Name, "error", updErr)
		}
		s.logger.Info("Ring advanced successfully",
			"rollout_id", record.ID,
			"ring", ring.Name,
			"on_version", onVersion,
			"failed", failed,
			"pending", pending)
	}

	// All rings passed. Mark the rollout completed.
	if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
		business.RolloutStatusCompleted, "", len(rings), nil, ""); updErr != nil {
		s.logger.Error("Failed to persist completed rollout status",
			"rollout_id", record.ID, "error", updErr)
	}
	s.logger.Info("Rollout completed",
		"rollout_id", record.ID,
		"target_version", logging.SanitizeLogValue(record.TargetVersion))
	s.notifyRolloutTerminal(record.ID)
}

// notifyRolloutTerminal fires the terminal lifecycle hook when configured. It is invoked
// after runRollout commits a terminal (completed or halted) store update so that tests can
// synchronize on the transition without polling; the hook is nil in production.
func (s *Server) notifyRolloutTerminal(rolloutID string) {
	if s.onRolloutTerminal != nil {
		s.onRolloutTerminal(rolloutID)
	}
}

// queryRingHealthCounts returns the count of stewards in a ring classified as
// on-version, failed, or pending for the given desired version.
//
// A steward is on-version when its RunningVersion matches desiredVersion.
// A steward is failed when it has a terminal-failure upgrade record for desiredVersion.
// All other stewards are pending (including those with no upgrade record yet).
func (s *Server) queryRingHealthCounts(ctx context.Context, ring, desiredVersion, tenantID string) (onVersion, failed, pending int, err error) {
	if s.fleetQuery == nil {
		return 0, 0, 0, fmt.Errorf("fleet query not configured")
	}
	stewards, err := s.fleetQuery.Search(ctx, fleet.Filter{
		TenantID:      tenantID,
		DNAAttributes: map[string]string{"deployment_ring": ring},
	})
	if err != nil {
		return 0, 0, 0, fmt.Errorf("fleet query for ring %q failed: %w", ring, err)
	}

	for _, st := range stewards {
		if st.RunningVersion == desiredVersion {
			onVersion++
			continue
		}
		if s.upgradeStore == nil {
			pending++
			continue
		}
		records, lerr := s.upgradeStore.ListUpgradesBySteward(ctx, st.ID)
		if lerr != nil {
			return 0, 0, 0, fmt.Errorf("upgrade list for steward %q failed: %w", st.ID, lerr)
		}
		classified := false
		for _, rec := range records {
			if rec.Version == desiredVersion {
				if rec.Status == business.UpgradeStatusFailed || rec.Status == business.UpgradeStatusRolledBack {
					failed++
				} else {
					pending++
				}
				classified = true
				break
			}
		}
		if !classified {
			pending++
		}
	}
	return onVersion, failed, pending, nil
}

// failedStewardIDs returns the IDs of stewards in ring that have a terminal-failure
// upgrade record for desiredVersion. Used to populate RolloutRecord.DeferredStewards.
func (s *Server) failedStewardIDs(ctx context.Context, ring, desiredVersion, tenantID string) []string {
	if s.fleetQuery == nil || s.upgradeStore == nil {
		return nil
	}
	stewards, err := s.fleetQuery.Search(ctx, fleet.Filter{
		TenantID:      tenantID,
		DNAAttributes: map[string]string{"deployment_ring": ring},
	})
	if err != nil {
		return nil
	}
	var ids []string
	for _, st := range stewards {
		if st.RunningVersion == desiredVersion {
			continue
		}
		records, lerr := s.upgradeStore.ListUpgradesBySteward(ctx, st.ID)
		if lerr != nil {
			continue
		}
		for _, rec := range records {
			if rec.Version == desiredVersion &&
				(rec.Status == business.UpgradeStatusFailed || rec.Status == business.UpgradeStatusRolledBack) {
				ids = append(ids, st.ID)
				break
			}
		}
	}
	return ids
}

// setRingDesiredVersion updates the in-memory ring configuration to set the target
// version for the named ring. Protected by the server mutex. The git-backed config
// is the durable source of truth; this in-memory update is visible to health checks
// within this controller process for the lifetime of the current rollout.
func (s *Server) setRingDesiredVersion(ringName, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil || s.cfg.DeploymentRings == nil {
		return
	}
	for i := range s.cfg.DeploymentRings.Rings {
		if s.cfg.DeploymentRings.Rings[i].Name == ringName {
			s.cfg.DeploymentRings.Rings[i].DesiredVersion = version
			return
		}
	}
}

// effectiveRings returns the effective ring configuration, protected by the server mutex.
//
// When deployment_rings is entirely unconfigured (nil), the default four-ring set applies
// so an out-of-the-box controller can still orchestrate rollouts. An explicitly-configured
// ring set is returned as-is, including an explicitly empty one: unlike Config.EffectiveRings
// — which substitutes the four-ring default for an empty set so tenant/ring resolution always
// has rings — a rollout must not silently run against defaults the operator deliberately
// removed. An operator-declared empty ring set is a distinct operational state that the
// handleStartRollout NO_RINGS guard surfaces as an error rather than masks.
func (s *Server) effectiveRings() controllerconfig.DeploymentRingConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil || s.cfg.DeploymentRings == nil {
		return controllerconfig.DefaultDeploymentRingConfig()
	}
	rc := *s.cfg.DeploymentRings
	if rc.FallbackRing == "" {
		rc.FallbackRing = controllerconfig.DefaultFallbackRing
	}
	return rc
}
