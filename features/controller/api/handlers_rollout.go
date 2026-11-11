// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultRolloutHaltThreshold is the per-ring failure rate (failed/(on_version+failed)) that
// triggers an automatic halt when a ring spec does not configure its own halt_threshold.
const defaultRolloutHaltThreshold = 0.05

// defaultRolloutHaltPollInterval is how often runRollout re-reads the rollout record
// from the shared rolloutStore while waiting out a ring's soak duration, so a halt
// persisted by a peer node (Server.rolloutHaltChans is per-process; POST .../halt
// against a different node than the one running the goroutine) is noticed without
// waiting for the full soak to elapse.
const defaultRolloutHaltPollInterval = 5 * time.Second

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

// principalID returns the principal's ID, or "" when there is no principal.
func principalID(p *Principal) string {
	if p == nil {
		return ""
	}
	return p.ID
}

// rolloutAuditTenant returns the tenant to attribute a rollout audit event to,
// falling back to the system tenant for an unscoped rollout.
func rolloutAuditTenant(tenantID string) string {
	if tenantID == "" {
		return audit.SystemTenantID
	}
	return tenantID
}

// decodeStartRolloutRequest reads the start rollout body and validates
// target_version, writing the 400 response when it is rejected.
func (s *Server) decodeStartRolloutRequest(w http.ResponseWriter, r *http.Request) (startRolloutRequest, bool) {
	var req startRolloutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode start rollout body", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return req, false
	}

	if req.TargetVersion == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "target_version is required", "MISSING_FIELDS")
		return req, false
	}
	if !stewardBinaryVersionRe.MatchString(req.TargetVersion) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Invalid target_version: "+logging.SanitizeLogValue(req.TargetVersion)+"; must match ^v\\d+\\.\\d+\\.\\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?",
			"INVALID_VERSION")
		return req, false
	}
	return req, true
}

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

	principal, callerTenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	req, ok := s.decodeStartRolloutRequest(w, r)
	if !ok {
		return
	}

	tenantID, ok := s.resolveRolloutTenant(w, r, callerTenantID, req.TenantID)
	if !ok {
		return
	}

	if s.refuseUnattendedRollout(w, r, principal, tenantID, gateRouteStartRollout) {
		return
	}

	// Refuse before any record exists: every platform and arch the rollout reaches
	// must have an approved binary for the target version (Issue #6053).
	if s.refuseUnapprovedRolloutTarget(w, r, tenantID, req.TargetVersion) {
		return
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
		InitiatedBy:    principalID(principal),
		TargetVersion:  req.TargetVersion,
		CurrentRing:    rings.Rings[0].Name,
		RingsCompleted: 0,
		RingsTotal:     len(rings.Rings),
		Status:         business.RolloutStatusInProgress,
		StartedAt:      time.Now().UTC(),
		OwnerNodeID:    s.rolloutOwnerNodeID(),
	}

	if err := s.rolloutStore.CreateRollout(r.Context(), record); err != nil {
		s.logger.Error("Failed to create rollout record",
			"error", logging.SanitizeLogValue(err.Error()),
			"target_version", logging.SanitizeLogValue(req.TargetVersion))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create rollout record", "CREATE_RECORD_ERROR")
		return
	}

	s.emitOperatorDeployEvent(r, principal, rolloutAuditEvent{
		tenantID:     tenantID,
		action:       auditRolloutStarted,
		markerKind:   markerKindRolloutStarted,
		resourceType: "rollout",
		resourceID:   rolloutID,
		revision:     req.TargetVersion,
		severity:     business.AuditSeverityHigh,
		details: map[string]interface{}{
			"rollout_id":     rolloutID,
			"target_version": req.TargetVersion,
			"tenant_id":      tenantID,
		},
	})

	haltCh := make(chan struct{})
	s.rolloutHaltChans.Store(rolloutID, haltCh)

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

// rolloutBinaryTarget names the stored binary a steward reaches: the blob tenant
// its own tenant maps to, with its platform and arch.
type rolloutBinaryTarget struct{ tenant, platform, arch string }

// Fixed, caller-safe refusals of the rollout approval check's fleet lookup.
var (
	errRolloutFleetQueryNotConfigured = errors.New("fleet query not configured; cannot verify the target version is approved")
	errRolloutFleetQueryFailed        = errors.New("fleet query failed; cannot verify the target version is approved")
)

// rolloutBinaryTargets returns the distinct (blob tenant, platform, arch) targets
// of the stewards the rollout's tenant scope matches, in a stable order. A steward
// that has not reported its platform and arch cannot be matched to a binary here;
// nothing is handed to it without approval regardless, because self-fetch and
// dispatch each check the approval record themselves.
func (s *Server) rolloutBinaryTargets(ctx context.Context, tenantID string) ([]rolloutBinaryTarget, error) {
	if s.fleetQuery == nil {
		return nil, errRolloutFleetQueryNotConfigured
	}
	stewards, err := s.fleetQuery.Search(ctx, fleet.Filter{TenantID: tenantID})
	if err != nil {
		s.logger.Error("Fleet query failed during rollout approval check", "error", logging.SanitizeLogValue(err.Error()))
		return nil, errRolloutFleetQueryFailed
	}
	seen := make(map[rolloutBinaryTarget]bool)
	var targets []rolloutBinaryTarget
	for _, st := range stewards {
		platform, arch := stewardBinaryPlatform(st)
		t := rolloutBinaryTarget{tenant: installerBlobTenant(st.TenantID), platform: platform, arch: arch}
		if platform == "" || arch == "" || seen[t] {
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	sortRolloutBinaryTargets(targets)
	return targets, nil
}

func sortRolloutBinaryTargets(targets []rolloutBinaryTarget) {
	sort.Slice(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		if a.platform != b.platform {
			return a.platform < b.platform
		}
		if a.arch != b.arch {
			return a.arch < b.arch
		}
		return a.tenant < b.tenant
	})
}

// rolloutApprovalCheck answers whether a target has an approved binary for one
// version, remembering each stored blob's state so the shared "default" binary is
// read once per platform and arch.
type rolloutApprovalCheck struct {
	s       *Server
	ctx     context.Context
	version string
	memo    map[rolloutBinaryTarget]bool
}

// blobApproved reports the approval state of the one blob stored for t.
func (c *rolloutApprovalCheck) blobApproved(t rolloutBinaryTarget) (bool, error) {
	if v, ok := c.memo[t]; ok {
		return v, nil
	}
	v, err := c.s.stewardBinaryBlobApproved(c.ctx, t.tenant, c.version, t.platform, t.arch)
	if err == nil {
		c.memo[t] = v
	}
	return v, err
}

// covered reports whether t has an approved binary in the order a steward fetches
// it: its own tenant's blob, then "default".
func (c *rolloutApprovalCheck) covered(t rolloutBinaryTarget) (bool, error) {
	approved, err := c.blobApproved(t)
	if err == nil && !approved && t.tenant != "default" {
		approved, err = c.blobApproved(rolloutBinaryTarget{tenant: "default", platform: t.platform, arch: t.arch})
	}
	return approved, err
}

// refuseUnapprovedRolloutTarget checks that every (platform, arch) pair among the
// stewards the rollout's tenant scope matches has an approved steward binary for
// version, and writes the refusal and returns true when it does not. A steward
// fetches its own tenant's binary and falls back to "default" when that one is
// absent (installerBlobTenant, client_transport_upgrade.go), so a pair is covered
// when the first blob in that order that has an approval record for its recomputed
// SHA-256 exists. No matching stewards means nothing to check. An unavailable
// fleet query, binary store or approval store, or a failed read, refuses with 503:
// the check fails closed.
func (s *Server) refuseUnapprovedRolloutTarget(w http.ResponseWriter, r *http.Request, tenantID, version string) bool {
	targets, err := s.rolloutBinaryTargets(r.Context(), tenantID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, err.Error(), "FLEET_QUERY_UNAVAILABLE")
		return true
	}
	if len(targets) == 0 {
		return false
	}
	if s.blobStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Binary storage not available", "BINARY_STORE_UNAVAILABLE")
		return true
	}
	if s.StewardBinaryApprovalStore() == nil {
		s.writeApprovalUnavailable(w, errStewardBinaryApprovalUnavailable)
		return true
	}
	check := &rolloutApprovalCheck{s: s, ctx: r.Context(), version: version, memo: make(map[rolloutBinaryTarget]bool)}
	for _, t := range targets {
		approved, err := check.covered(t)
		if err != nil {
			s.writeApprovalUnavailable(w, err)
			return true
		}
		if !approved {
			s.writeErrorResponse(w, http.StatusForbidden,
				fmt.Sprintf("No approved steward binary for %s on %s/%s; approve the published binary before starting a rollout",
					logging.SanitizeLogValue(version), logging.SanitizeLogValue(t.platform), logging.SanitizeLogValue(t.arch)),
				"NOT_APPROVED")
			return true
		}
	}
	return false
}

// stewardBinaryPlatform returns the platform and arch of the binary a steward runs:
// the runtime_os and runtime_arch it reported from the Go runtime, else the os and
// arch DNA attributes. Either is empty when the steward has not reported it.
func stewardBinaryPlatform(st fleet.StewardResult) (platform, arch string) {
	platform, arch = st.DNAAttributes["runtime_os"], st.DNAAttributes["runtime_arch"]
	if platform == "" {
		platform = st.OS
	}
	if arch == "" {
		arch = st.Architecture
	}
	return platform, arch
}

// stewardBinaryBlobApproved reports whether the blob stored under blobTenant for
// version, platform and arch exists and has an approval record for its recomputed
// SHA-256. A missing blob is not approved and is not an error.
func (s *Server) stewardBinaryBlobApproved(ctx context.Context, blobTenant, version, platform, arch string) (bool, error) {
	if !validPlatforms[platform] || !validArchs[arch] {
		return false, nil
	}
	sum, err := s.storedStewardBinarySHA256(ctx, stewardBinaryBlobKey(blobTenant, version, platform, arch))
	if err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %v", errStewardBinaryApprovalRead, err)
	}
	return s.stewardBinaryApproved(ctx, blobTenant, version, platform, arch, sum)
}

// resolveRolloutTenant returns the tenant a rollout targets, or false after writing
// the rejection response.
//
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
func (s *Server) resolveRolloutTenant(w http.ResponseWriter, r *http.Request, callerTenantID, reqTenantID string) (string, bool) {
	if reqTenantID == "" || reqTenantID == callerTenantID {
		return callerTenantID, true
	}
	if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), reqTenantID, "POST /api/v1/rollout"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, reqTenantID) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Cannot start a rollout for another tenant",
				"CROSS_TENANT")
		}
		return "", false
	}
	return reqTenantID, true
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

	_, _, ok := s.authRunAccess(w, r)
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

	// Tenant isolation (Issue #4335): migrated to ctxkeys.TenantScope, and the
	// response now matches the not-found case (ROLLOUT_NOT_FOUND) rather than a
	// distinguishable 403 FORBIDDEN, so a cross-tenant caller cannot use the
	// response to tell "does not exist" apart from "exists in another tenant".
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, record.TenantID, "GET /api/v1/rollout/{rollout_id}"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Rollout record not found", "ROLLOUT_NOT_FOUND")
		}
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
				"error", logging.SanitizeLogValue(qErr.Error()))
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

	principal, _, ok := s.authRunAccess(w, r)
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

	// Tenant isolation (Issue #4335): migrated to ctxkeys.TenantScope, and the
	// response now matches the not-found case (ROLLOUT_NOT_FOUND) rather than a
	// distinguishable 403 FORBIDDEN, so a cross-tenant caller cannot use the
	// response to tell "does not exist" apart from "exists in another tenant".
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, record.TenantID, "POST /api/v1/rollout/{rollout_id}/halt"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, record.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Rollout record not found", "ROLLOUT_NOT_FOUND")
		}
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

	// Persist the halt FIRST. The persisted store record is the cross-node source of
	// truth — a peer node's runRollout goroutine only learns of this halt by re-reading
	// it (see rolloutShouldStop) — so a write failure here means the halt has not
	// actually happened anywhere and must be reported as such, not masked as a warning
	// while the response claims success (Issue #3761 residual review).
	now := time.Now().UTC()
	if updErr := s.rolloutStore.UpdateRolloutProgress(r.Context(), rolloutID,
		business.RolloutStatusHalted, record.CurrentRing, record.RingsCompleted,
		&now, "halted by operator"); updErr != nil {
		s.logger.Error("Failed to persist halt for rollout",
			"rollout_id", logging.SanitizeLogValue(rolloutID), "error", logging.SanitizeLogValue(updErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to persist rollout halt", "HALT_PERSIST_ERROR")
		return
	}

	// Fast-path signal for the case where this node happens to be the one running the
	// rollout goroutine: closing the channel wakes it immediately rather than waiting
	// for the next rolloutHaltPollInterval re-read of the now-halted store record.
	s.signalRolloutHalt(rolloutID)

	s.logger.Info("Rollout halted by operator",
		"rollout_id", logging.SanitizeLogValue(rolloutID),
		"target_version", logging.SanitizeLogValue(record.TargetVersion))

	s.emitOperatorDeployEvent(r, principal, rolloutAuditEvent{
		tenantID:     record.TenantID,
		action:       auditRolloutHalted,
		markerKind:   markerKindRolloutHalted,
		resourceType: "rollout",
		resourceID:   rolloutID,
		revision:     record.TargetVersion,
		severity:     business.AuditSeverityHigh,
		details: map[string]interface{}{
			"rollout_id":     rolloutID,
			"target_version": record.TargetVersion,
			"tenant_id":      record.TenantID,
		},
	})

	s.writeSuccessResponse(w, startRolloutResponse{
		RolloutID: rolloutID,
		Status:    string(business.RolloutStatusHalted),
	})
}

// signalRolloutHalt wakes the runRollout goroutine for rolloutID when this node runs it,
// by closing its halt channel. It is a no-op when no channel is registered or the channel
// is already closed.
func (s *Server) signalRolloutHalt(rolloutID string) {
	ch, loaded := s.rolloutHaltChans.Load(rolloutID)
	if !loaded {
		return
	}
	select {
	case <-ch.(chan struct{}):
		// already closed
	default:
		close(ch.(chan struct{}))
	}
}

// RolloutStore returns the wired rollout store, or nil when none is wired and the
// rollout endpoints answer 503 ROLLOUT_STORE_UNAVAILABLE.
func (s *Server) RolloutStore() business.RolloutStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rolloutStore
}

// rolloutOwnerNodeID returns the ID recorded as the owner of a rollout this node
// starts: the local HA node ID, or empty when the controller runs without an HA
// manager. In the non-single HA modes the ID comes from CFGMS_NODE_ID and is
// stable across restarts of the same node.
func (s *Server) rolloutOwnerNodeID() string {
	if s.haManager == nil {
		return ""
	}
	return s.haManager.GetLocalNode().ID
}

// rolloutOrphanedReason is the halt reason recorded by HaltOrphanedRollouts.
const rolloutOrphanedReason = "advancing node stopped"

// HaltOrphanedRollouts transitions every in-progress rollout owned by this node to
// halted, recording rolloutOrphanedReason. It is the controller-startup sweep: the
// goroutine advancing those rollouts died with the previous process, so without it
// they would read in-progress forever.
//
// The sweep makes no authority decision across nodes. It touches only rollouts whose
// OwnerNodeID equals this node's ID (empty for a controller without an HA manager)
// and never a peer's, so it needs neither HasLeadership nor the raw Raft primitive.
// It returns the number of rollouts halted. A failure on one rollout is logged and
// does not stop the others; the first error is returned alongside the count.
// Automatic resumption is out of scope.
func (s *Server) HaltOrphanedRollouts(ctx context.Context) (int, error) {
	s.mu.RLock()
	store := s.rolloutStore
	s.mu.RUnlock()
	if store == nil {
		return 0, nil
	}
	owner := s.rolloutOwnerNodeID()
	records, err := store.ListInProgressRollouts(ctx)
	if err != nil {
		return 0, fmt.Errorf("list in-progress rollouts: %w", err)
	}
	var halted int
	var firstErr error
	for _, rec := range records {
		if rec.OwnerNodeID != owner {
			continue
		}
		now := time.Now().UTC()
		if err := store.UpdateRolloutProgress(ctx, rec.ID, business.RolloutStatusHalted,
			rec.CurrentRing, rec.RingsCompleted, &now, rolloutOrphanedReason); err != nil {
			s.logger.Warn("Failed to halt orphaned rollout",
				"rollout_id", logging.SanitizeLogValue(rec.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			if firstErr == nil {
				firstErr = fmt.Errorf("halt rollout %s: %w", logging.SanitizeLogValue(rec.ID), err)
			}
			continue
		}
		halted++
		s.logger.Info("Halted rollout orphaned by a restart of its advancing node",
			"rollout_id", logging.SanitizeLogValue(rec.ID),
			"target_version", logging.SanitizeLogValue(rec.TargetVersion),
			"current_ring", logging.SanitizeLogValue(rec.CurrentRing))
	}
	return halted, firstErr
}

// runRollout is the background ring-advance goroutine. It processes rings in order:
// soak, check health, halt or advance. See handlers_rollout_test.go for the required tests.
//
// Durability note: the rollout record, ring progress, halt metadata and deferred
// stewards are persisted in the shared RolloutStore, so they survive a controller
// restart and are visible from every node. This goroutine is not: it runs in memory
// on the node that accepted the request, which the record names in OwnerNodeID. When
// that node restarts, HaltOrphanedRollouts halts its in-progress rollouts with a
// recorded reason; nothing resumes automatically, and the operator re-issues the
// rollout. See ADR-008 for the durable workflow execution roadmap.
func (s *Server) runRollout(ctx context.Context, record *business.RolloutRecord, rings []controllerconfig.RingSpec, haltCh <-chan struct{}) {
	defer s.rolloutHaltChans.Delete(record.ID)

	for i, ring := range rings {
		// Check operator halt before processing each ring: either this node served the
		// halt (haltCh) or a peer node did and persisted it to the shared store.
		if s.rolloutShouldStop(ctx, haltCh, record.ID) {
			return
		}

		// Advance this ring: update its desired_version in the in-memory config so
		// health checks can use the current target.
		s.setRingDesiredVersion(ring.Name, record.TargetVersion)

		// Persist current ring in the rollout record.
		if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
			business.RolloutStatusInProgress, ring.Name, i, nil, ""); updErr != nil {
			s.logger.Warn("Failed to update rollout current ring",
				"rollout_id", logging.SanitizeLogValue(record.ID), "ring", ring.Name, "error", logging.SanitizeLogValue(updErr.Error()))
		}

		// Soak: wait the ring's configured soak duration; skip if zero.
		if s.soakRing(ctx, haltCh, record.ID, time.Duration(ring.Soak)) {
			return
		}

		// Query ring health after soak.
		onVersion, failed, pending, err := s.queryRingHealthCounts(ctx, ring.Name, record.TargetVersion, record.TenantID)
		if err != nil {
			s.logger.Error("Ring health query failed, halting rollout",
				"rollout_id", logging.SanitizeLogValue(record.ID),
				"ring", ring.Name,
				"error", logging.SanitizeLogValue(err.Error()))
			s.persistRolloutHalt(ctx, record.ID, ring.Name, i,
				"ring health query failed: "+err.Error(),
				"Failed to persist halted rollout status after ring health query failure")
			s.emitSystemRolloutEvent(ctx, record, auditRolloutAutoHalted, markerKindRolloutAutoHalt,
				business.AuditSeverityHigh, map[string]interface{}{
					"halt_reason_class": haltClassRingHealthQueryFailed,
					"ring":              ring.Name,
					"rings_completed":   i,
				})
			s.notifyRolloutTerminal(record.ID)
			return
		}

		// Identify failed stewards and add them to the deferred-retry list.
		failedIDs := s.failedStewardIDs(ctx, ring.Name, record.TargetVersion, record.TenantID)
		if len(failedIDs) > 0 {
			if appendErr := s.rolloutStore.AppendDeferredStewards(ctx, record.ID, failedIDs); appendErr != nil {
				s.logger.Warn("Failed to append deferred stewards",
					"rollout_id", logging.SanitizeLogValue(record.ID), "ring", ring.Name, "error", logging.SanitizeLogValue(appendErr.Error()))
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
			haltMsg := fmt.Sprintf(
				"ring %q failure rate %.1f%% (failed=%d, on_version=%d) exceeds halt_threshold %.1f%%; pending=%d",
				ring.Name,
				float64(failed)/denominator*100,
				failed, onVersion,
				threshold*100,
				pending,
			)
			s.logger.Error("Rollout halted: failure rate exceeded threshold",
				"rollout_id", logging.SanitizeLogValue(record.ID),
				"ring", ring.Name,
				"failed", failed,
				"on_version", onVersion,
				"threshold", threshold)
			s.persistRolloutHalt(ctx, record.ID, ring.Name, i, haltMsg,
				"Failed to persist halted rollout status after failure-rate threshold exceeded")
			s.emitSystemRolloutEvent(ctx, record, auditRolloutAutoHalted, markerKindRolloutAutoHalt,
				business.AuditSeverityHigh, map[string]interface{}{
					"halt_reason_class": haltClassFailureRateExceeded,
					"ring":              ring.Name,
					"rings_completed":   i,
					"failed":            failed,
					"on_version":        onVersion,
					"pending":           pending,
					"halt_threshold":    threshold,
				})
			s.notifyRolloutTerminal(record.ID)
			return
		}

		// Ring cleared health gate. Mark it completed.
		if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
			business.RolloutStatusInProgress, "", i+1, nil, ""); updErr != nil {
			s.logger.Warn("Failed to advance rollout ring count",
				"rollout_id", logging.SanitizeLogValue(record.ID), "ring", ring.Name, "error", logging.SanitizeLogValue(updErr.Error()))
		}
		s.logger.Info("Ring advanced successfully",
			"rollout_id", logging.SanitizeLogValue(record.ID),
			"ring", ring.Name,
			"on_version", onVersion,
			"failed", failed,
			"pending", pending)
	}

	// All rings passed. Mark the rollout completed.
	if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, record.ID,
		business.RolloutStatusCompleted, "", len(rings), nil, ""); updErr != nil {
		s.logger.Error("Failed to persist completed rollout status",
			"rollout_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(updErr.Error()))
	}
	s.logger.Info("Rollout completed",
		"rollout_id", logging.SanitizeLogValue(record.ID),
		"target_version", logging.SanitizeLogValue(record.TargetVersion))
	s.emitSystemRolloutEvent(ctx, record, auditRolloutCompleted, markerKindRolloutCompleted,
		business.AuditSeverityHigh, map[string]interface{}{
			"rings_completed": len(rings),
		})
	s.notifyRolloutTerminal(record.ID)
}

// soakRing waits out a ring's configured soak duration and reports whether the rollout
// must stop (halted, or the context ended) while it waited. A zero duration returns false
// immediately.
func (s *Server) soakRing(ctx context.Context, haltCh <-chan struct{}, rolloutID string, soakDur time.Duration) bool {
	if soakDur <= 0 {
		return false
	}
	// Signal that this ring's in-progress state is committed and the goroutine is
	// about to block on the soak. Tests use this to synchronize an operator halt
	// deterministically; nil in production.
	if s.onRolloutSoak != nil {
		s.onRolloutSoak(rolloutID)
	}
	return s.waitOutSoak(ctx, haltCh, rolloutID, soakDur)
}

// persistRolloutHalt records an automatic halt in the rollout store. A write failure is
// logged with failMsg and dropped: the caller still notifies and stops.
func (s *Server) persistRolloutHalt(ctx context.Context, rolloutID, ringName string, ringsCompleted int, reason, failMsg string) {
	now := time.Now().UTC()
	if updErr := s.rolloutStore.UpdateRolloutProgress(ctx, rolloutID,
		business.RolloutStatusHalted, ringName, ringsCompleted, &now, reason); updErr != nil {
		s.logger.Error(failMsg,
			"rollout_id", logging.SanitizeLogValue(rolloutID), "ring", ringName, "error", logging.SanitizeLogValue(updErr.Error()))
	}
}

// rolloutShouldStop reports whether the runRollout goroutine for rolloutID must stop
// advancing: either this node served the halt (haltCh closed — the fast, same-node
// path), or a fresh read of the shared rolloutStore shows a terminal status persisted
// by a peer node's handleHaltRollout. An unreadable rollout record also stops the
// rollout — the same fail-closed direction the ring-health query already takes — since
// this goroutine must not keep advancing a fleet it can no longer confirm has not
// already been halted or completed by another node (Issue #3761 residual review).
func (s *Server) rolloutShouldStop(ctx context.Context, haltCh <-chan struct{}, rolloutID string) bool {
	select {
	case <-haltCh:
		return true
	default:
	}

	record, err := s.rolloutStore.GetRollout(ctx, rolloutID)
	if err != nil {
		s.logger.Error("Failed to re-read rollout record; stopping rollout goroutine fail-closed",
			"rollout_id", logging.SanitizeLogValue(rolloutID), "error", logging.SanitizeLogValue(err.Error()))
		return true
	}
	return record.Status == business.RolloutStatusHalted || record.Status == business.RolloutStatusCompleted
}

// waitOutSoak blocks for soakDur, re-checking rolloutShouldStop every
// s.rolloutHaltPollInterval so a halt persisted by a peer node during a long soak is
// noticed without waiting for the soak to fully elapse. Returns true if the wait was
// cut short by a stop condition.
func (s *Server) waitOutSoak(ctx context.Context, haltCh <-chan struct{}, rolloutID string, soakDur time.Duration) bool {
	pollInterval := s.rolloutHaltPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultRolloutHaltPollInterval
	}
	remaining := soakDur
	for remaining > 0 {
		wait := pollInterval
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-haltCh:
			return true
		case <-time.After(wait):
		}
		remaining -= wait
		if s.rolloutShouldStop(ctx, haltCh, rolloutID) {
			return true
		}
	}
	return false
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
