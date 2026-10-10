// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// maxTenantCrossingGrantDuration bounds how far into the future an MSP administrator
	// may time-box a client-granted support access record (ADR-025 Decision 2(a)).
	maxTenantCrossingGrantDuration = 24 * time.Hour

	// tenantCrossingBreakGlassDuration is the fixed elevation window for a tenant-crossing
	// break-glass invocation (ADR-025 Decision 2(b)). Shorter than emergency.break-glass's
	// 4h system-resource window (features/rbac/templates.go) because a tenant-crossing
	// elevation reaches a specific MSP client's own configuration and data, not shared
	// platform infrastructure — the tighter default narrows exposure if a token is stolen
	// mid-window. Not yet exposed as a per-invocation parameter; ADR-025's own "Remaining
	// Tunables" list carries the expiry default as still open (see Amendment 2).
	tenantCrossingBreakGlassDuration = 30 * time.Minute

	// Justification bounds mirror features/rbac.ValidateSensitiveOperation's M-AUTH-2
	// convention (10-1000 chars) — not reused directly because that helper's
	// SensitiveOperationType enum is scoped to RBAC role/permission CRUD, not tenant
	// crossing, but the same anti-abuse rationale applies verbatim here.
	tenantCrossingJustificationMinLen = 10
	tenantCrossingJustificationMaxLen = 1000

	// tenantCrossingMaxBodyBytes bounds the break-glass request body; the largest
	// legitimate body is a 1000-character justification plus a category.
	tenantCrossingMaxBodyBytes = 16 * 1024
)

// Derived crossing statuses reported by TenantCrossingResponse.Status.
const (
	tenantCrossingStatusActive  = "active"
	tenantCrossingStatusPending = "pending"
	tenantCrossingStatusExpired = "expired"
	tenantCrossingStatusRevoked = "revoked"
)

// TenantCrossingResponse is the snake_case wire shape of a grant or break-glass record.
type TenantCrossingResponse struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	PrincipalID    string     `json:"principal_id"`   // break-glass invoker; empty for a grant
	PrincipalName  string     `json:"principal_name"` // best effort; always empty for a grant
	Kind           string     `json:"kind"`
	GrantedBy      string     `json:"granted_by"`
	Justification  string     `json:"justification"`
	ReasonCategory string     `json:"reason_category"`
	ApprovalState  string     `json:"approval_state"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	// Status is derived: revoked, then expired, then pending (awaiting a second
	// approver), otherwise active.
	Status string `json:"status"`
}

// tenantCrossingStatus derives the status of c at now.
func tenantCrossingStatus(c *business.TenantCrossing, now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return tenantCrossingStatusRevoked
	case !c.ExpiresAt.After(now):
		return tenantCrossingStatusExpired
	case c.ApprovalState == business.TenantCrossingApprovalPending:
		return tenantCrossingStatusPending
	default:
		return tenantCrossingStatusActive
	}
}

// toTenantCrossingResponse converts a stored crossing to its wire shape. The principal
// name is a best-effort account lookup; a failure leaves it empty.
func (s *Server) toTenantCrossingResponse(ctx context.Context, c *business.TenantCrossing) TenantCrossingResponse {
	approval := string(c.ApprovalState)
	if approval == "" {
		approval = string(business.TenantCrossingApprovalApproved)
	}
	resp := TenantCrossingResponse{
		ID:             c.ID,
		TenantID:       c.TenantID,
		PrincipalID:    c.PrincipalID,
		Kind:           string(c.Kind),
		GrantedBy:      c.GrantedBy,
		Justification:  c.Justification,
		ReasonCategory: string(c.ReasonCategory),
		ApprovalState:  approval,
		CreatedAt:      c.CreatedAt,
		ExpiresAt:      c.ExpiresAt,
		RevokedAt:      c.RevokedAt,
		Status:         tenantCrossingStatus(c, time.Now()),
	}
	if c.Kind == business.TenantCrossingKindBreakGlass && c.PrincipalID != "" {
		if acct, err := s.getAccountByID(ctx, c.PrincipalID); err == nil && acct != nil {
			resp.PrincipalName = acct.Username
		}
	}
	return resp
}

// handleCreateTenantCrossingGrant implements POST /api/v1/tenants/{id}/access-grants.
// An MSP administrator (or unscoped admin) already authorized for tenantID explicitly
// grants a root-scoped support principal time-boxed, revocable access into their own
// tenant subtree (ADR-025 Decision 2(a)). No justification is required — this is
// opt-in, client-initiated trust, not an emergency override. Returns 404 for an unknown
// or out-of-scope target tenant (existence-oracle prevention, matching handleGetTenant).
func (s *Server) handleCreateTenantCrossingGrant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenant := callerTenantFilter(r.Context())

	// "root" is the SaaS operator's own scope, not an MSP that can consent to being
	// supported (ADR-025 Decision 1). A crossing recorded on "root" would sit on every
	// tenant's ancestry path (hasActiveTenantCrossing walks GetTenantPath, which starts
	// at "root") and act as a fleet-wide skeleton key, so it is never a legitimate grant
	// target — the per-MSP grant (Decision 2(a)) or the justified, 30-minute break-glass
	// (Decision 2(b)) are the only ways across the boundary.
	if s.isRootTenantForCrossing(r.Context(), tenantID) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"access grants cannot be created on the root tenant", "ROOT_TENANT_NOT_GRANTABLE")
		return
	}
	// A grant is client-initiated consent flowing from an MSP to a root-scoped support
	// principal. A root-scoped caller minting one would be consenting on the MSP's behalf
	// — self-dealing that bypasses Decision 2(b)'s justification, 30-minute cap, and
	// critical-severity audit trail. Break-glass is the root-scoped caller's only path.
	// "Root-scoped" is the tenant boundary's own predicate, so an account-bound
	// root-scope caller without the certificate/session marker is covered too.
	if subjectToTenantCrossingBoundary(principal) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"root-scoped callers cannot create access grants; use break-glass", "ROOT_SCOPED_CANNOT_GRANT")
		return
	}

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	// The granting caller must itself be authorized for tenantID — an MSP admin can only
	// grant access into a tenant it already controls, never into an arbitrary one. Reuses
	// the same decision as handleGetTenant; a root-scoped caller without its own crossing
	// gets the same step-up challenge here, since it cannot grant access it doesn't hold.
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant crossing-grant creation refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	// A grant names no person: it opens the MSP to all root support for a duration. A
	// body that carries principal_id (even an empty one) is refused rather than ignored,
	// so a client written for the old per-principal model fails loudly.
	var req struct {
		PrincipalID     *string `json:"principal_id"`
		DurationMinutes int     `json:"duration_minutes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, tenantCrossingMaxBodyBytes)).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.PrincipalID != nil {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"an access grant names no principal; send duration_minutes only", "GRANT_PRINCIPAL_NOT_ALLOWED")
		return
	}
	duration := time.Duration(req.DurationMinutes) * time.Minute
	if req.DurationMinutes <= 0 || duration > maxTenantCrossingGrantDuration {
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("duration_minutes must be between 1 and %d", int(maxTenantCrossingGrantDuration.Minutes())),
			"INVALID_DURATION")
		return
	}

	var callerID string
	if principal != nil {
		callerID = principal.ID
	}
	now := time.Now().UTC()
	crossing := &business.TenantCrossing{
		ID:       uuid.New().String(),
		TenantID: existing.ID,
		// A grant names no principal: it admits any root principal (ADR-025 Amendment 8).
		Kind:      business.TenantCrossingKindGrant,
		GrantedBy: callerID,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
	if err := s.tenantCrossingStore.CreateTenantCrossing(r.Context(), crossing); err != nil {
		s.logger.Error("Failed to create tenant crossing grant",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to create grant", "GRANT_FAILED")
		return
	}

	s.recordTenantCrossingAudit(r, existing.ID, callerID, crossing, business.AuditSeverityHigh,
		"tenant.crossing_grant_created", "")

	s.writeResponse(w, http.StatusCreated, s.toTenantCrossingResponse(r.Context(), crossing))
}

// handleTenantBreakGlass implements POST /api/v1/tenants/{id}/break-glass.
// A root-scoped SaaS-operator principal (ADR-025 Amendment 1 A1.3) invokes a
// justified, time-boxed, audited elevation into a tenant it does not otherwise have
// access to (ADR-025 Decision 2(b)) — distinct from, and never granted by, the
// system-resource-only emergency.break-glass RBAC template (features/rbac). Requires a
// reason_category and a justification (10-1000 chars, mirroring features/rbac's M-AUTH-2
// convention) in the JSON body; X-Justification is accepted as a justification fallback.
func (s *Server) handleTenantBreakGlass(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	// Same boundary as the grant path: a crossing recorded on "root" would cover every
	// tenant in the tree via the ancestry walk in hasActiveTenantCrossing. A root-scoped
	// caller already reaches "root" itself without any crossing (ADR-025 Decision 1), so
	// break-glass on "root" can only ever be an escalation attempt.
	if s.isRootTenantForCrossing(r.Context(), tenantID) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"break-glass cannot be invoked on the root tenant", "ROOT_TENANT_NOT_CROSSABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	// The same predicate authorizeTenantAccess uses to issue the crossing challenge:
	// every caller the boundary sends here must be able to complete break-glass.
	if !subjectToTenantCrossingBoundary(principal) {
		// Only a root-scoped caller can be denied purely by the ADR-025 boundary — anyone
		// else either already has ordinary ancestry-based access or is denied for a reason
		// break-glass cannot remedy (e.g. missing tenant:* permission entirely).
		s.writeErrorResponse(w, http.StatusForbidden, "break-glass is only available to root-scoped callers", "NOT_ROOT_SCOPED")
		return
	}

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	// The body carries the category and, preferably, the justification; the
	// X-Justification header is a fallback for the justification only. An empty or
	// absent body is not a decode error here: it must still reach the category check.
	var req struct {
		ReasonCategory string `json:"reason_category"`
		Justification  string `json:"justification"`
	}
	if body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, tenantCrossingMaxBodyBytes)); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	} else if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
			return
		}
	}

	category := business.TenantCrossingReasonCategory(strings.TrimSpace(req.ReasonCategory))
	if category == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "reason_category is required", "REASON_CATEGORY_REQUIRED")
		return
	}
	if !business.ValidTenantCrossingReasonCategory(category) {
		s.writeErrorResponse(w, http.StatusBadRequest, "reason_category is not a recognized category", "INVALID_REASON_CATEGORY")
		return
	}

	justification := strings.TrimSpace(req.Justification)
	if justification == "" {
		justification = strings.TrimSpace(r.Header.Get("X-Justification"))
	}
	if len(justification) < tenantCrossingJustificationMinLen || len(justification) > tenantCrossingJustificationMaxLen {
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("justification is required (%d-%d characters) in the request body or X-Justification header", tenantCrossingJustificationMinLen, tenantCrossingJustificationMaxLen),
			"JUSTIFICATION_REQUIRED")
		return
	}

	// With the second-approver setting on, the crossing is born pending and admits
	// nothing until a different root-scoped principal approves it; its unapproved
	// lifetime is the same window it would have had if active.
	approvalState := business.TenantCrossingApprovalApproved
	auditAction := "tenant.crossing_break_glass_invoked"
	if s.cfg.TenantAdmin.GetBreakGlassRequiresSecondApprover() {
		approvalState = business.TenantCrossingApprovalPending
		auditAction = "tenant.crossing_break_glass_requested"
	}

	now := time.Now().UTC()
	crossing := &business.TenantCrossing{
		ID:             uuid.New().String(),
		TenantID:       existing.ID,
		ApprovalState:  approvalState,
		PrincipalID:    principal.ID,
		Kind:           business.TenantCrossingKindBreakGlass,
		GrantedBy:      principal.ID,
		Justification:  justification,
		ReasonCategory: category,
		CreatedAt:      now,
		ExpiresAt:      now.Add(tenantCrossingBreakGlassDuration),
	}
	if err := s.tenantCrossingStore.CreateTenantCrossing(r.Context(), crossing); err != nil {
		s.logger.Error("Failed to create tenant crossing break-glass session",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to create break-glass session", "BREAK_GLASS_FAILED")
		return
	}

	s.recordTenantCrossingAudit(r, existing.ID, principal.ID, crossing, business.AuditSeverityCritical,
		auditAction, justification)

	s.writeResponse(w, http.StatusCreated, s.toTenantCrossingResponse(r.Context(), crossing))
}

// handleApproveTenantBreakGlass implements
// POST /api/v1/tenants/{id}/break-glass/{crossing_id}/approve. A root-scoped principal
// other than the invoker approves a pending break-glass crossing; the crossing becomes
// approved and its window restarts at approval time. The state transition is a single
// atomic store call, so a crossing that expired or was revoked while pending is never
// approvable.
func (s *Server) handleApproveTenantBreakGlass(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	crossingID := vars["crossing_id"]
	if tenantID == "" || crossingID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id and crossing id are required", "MISSING_PARAMETER")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if !subjectToTenantCrossingBoundary(principal) || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusForbidden, "break-glass approval is only available to root-scoped callers", "NOT_ROOT_SCOPED")
		return
	}

	crossing, err := s.tenantCrossingStore.GetTenantCrossing(r.Context(), crossingID)
	if err != nil && !errors.Is(err, business.ErrTenantCrossingNotFound) {
		s.logger.Error("Failed to get tenant crossing",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get crossing", "GET_FAILED")
		return
	}
	if err != nil || crossing == nil || crossing.TenantID != tenantID || crossing.Kind != business.TenantCrossingKindBreakGlass {
		s.writeErrorResponse(w, http.StatusNotFound, "crossing not found", "CROSSING_NOT_FOUND")
		return
	}
	if crossing.ApprovalState != business.TenantCrossingApprovalPending {
		s.writeErrorResponse(w, http.StatusConflict, "crossing is not pending approval", "NOT_PENDING")
		return
	}
	if crossing.GrantedBy == principal.ID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"approver must differ from the principal who invoked this break-glass", "SAME_APPROVER")
		return
	}

	now := time.Now().UTC()
	if err := s.tenantCrossingStore.ApproveTenantCrossing(r.Context(), crossing.ID, principal.ID, now, now.Add(tenantCrossingBreakGlassDuration)); err != nil {
		if errors.Is(err, business.ErrTenantCrossingNotPending) {
			s.writeErrorResponse(w, http.StatusConflict, "crossing is not pending approval", "NOT_PENDING")
			return
		}
		if errors.Is(err, business.ErrTenantCrossingNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "crossing not found", "CROSSING_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to approve tenant crossing",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to approve break-glass", "APPROVE_FAILED")
		return
	}
	if updated, gerr := s.tenantCrossingStore.GetTenantCrossing(r.Context(), crossing.ID); gerr == nil && updated != nil {
		crossing = updated
	}

	s.recordTenantCrossingAudit(r, crossing.TenantID, principal.ID, crossing, business.AuditSeverityCritical,
		"tenant.crossing_break_glass_approved", crossing.Justification)

	s.writeResponse(w, http.StatusOK, s.toTenantCrossingResponse(r.Context(), crossing))
}

// handleListTenantCrossings implements GET /api/v1/tenants/{id}/access-grants.
// Returns every grant and break-glass record (active, expired, and revoked) for
// tenantID — the MSP's own tenant-crossing activity view (ADR-025 Decision 2: both
// crossing kinds must be visible to the affected MSP, not hidden from it).
func (s *Server) handleListTenantCrossings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenant := callerTenantFilter(r.Context())

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant crossing-list refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	crossings, err := s.tenantCrossingStore.ListTenantCrossings(r.Context(), existing.ID)
	if err != nil {
		s.logger.Error("Failed to list tenant crossings",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to list tenant crossings", "LIST_FAILED")
		return
	}

	out := make([]TenantCrossingResponse, 0, len(crossings))
	for _, c := range crossings {
		out = append(out, s.toTenantCrossingResponse(r.Context(), c))
	}
	s.writeSuccessResponse(w, out)
}

// recordTenantCrossingAudit records a Decision 2 grant/break-glass event, tenant-scoped
// so it surfaces through the existing GET /api/v1/audit/entries endpoint — which always
// scopes to the caller's own context tenant — giving the affected MSP visibility into
// crossing activity on its tenant without a bespoke activity-view endpoint.
func (s *Server) recordTenantCrossingAudit(r *http.Request, tenantID, actorID string, crossing *business.TenantCrossing, severity business.AuditSeverity, action, detail string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant_crossing", crossing.ID, "").
		Result(business.AuditResultSuccess).
		Severity(severity).
		Detail("crossing_kind", string(crossing.Kind)).
		Detail("target_principal_id", logging.SanitizeLogValue(crossing.PrincipalID)).
		Detail("expires_at", crossing.ExpiresAt.Format(time.RFC3339)).
		Detail("reason_category", string(crossing.ReasonCategory)).
		Detail("detail", logging.SanitizeLogValue(detail))
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record tenant crossing audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleEndTenantCrossing implements DELETE /api/v1/tenants/{id}/access-grants/{crossing_id}.
// It ends an active grant or break-glass crossing early; the crossing stops granting
// access at once because HasActiveTenantCrossing excludes revoked records. A grant is
// ended by the MSP administrator of the granting tenant — a root-scoped caller never
// ends one (mirroring ROOT_SCOPED_CANNOT_GRANT on create). A break-glass crossing is
// ended by the root principal that invoked it or by an administrator of the owning
// tenant. A crossing that does not belong to {id} is a 404 with no disclosure, and
// ending an already revoked or expired crossing is an idempotent 200.
func (s *Server) handleEndTenantCrossing(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	crossingID := vars["crossing_id"]
	if tenantID == "" || crossingID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id and crossing id are required", "MISSING_PARAMETER")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenant := callerTenantFilter(r.Context())

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant crossing end refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	crossing, err := s.tenantCrossingStore.GetTenantCrossing(r.Context(), crossingID)
	if err != nil && !errors.Is(err, business.ErrTenantCrossingNotFound) {
		s.logger.Error("Failed to get tenant crossing",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get crossing", "GET_FAILED")
		return
	}
	if err != nil || crossing == nil || crossing.TenantID != existing.ID {
		s.writeErrorResponse(w, http.StatusNotFound, "crossing not found", "CROSSING_NOT_FOUND")
		return
	}

	var callerID string
	if principal != nil {
		callerID = principal.ID
	}
	rootScoped := subjectToTenantCrossingBoundary(principal)
	switch crossing.Kind {
	case business.TenantCrossingKindGrant:
		if rootScoped {
			s.writeErrorResponse(w, http.StatusForbidden,
				"root-scoped callers cannot end access grants", "ROOT_SCOPED_CANNOT_END_GRANT")
			return
		}
	default:
		// Break-glass: the invoker, or a caller not subject to the boundary (the owning
		// MSP's administrator, already authorized for this tenant above).
		if rootScoped && (callerID == "" || crossing.GrantedBy != callerID) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"only the invoker or an administrator of the owning tenant can end a break-glass crossing", "NOT_CROSSING_OWNER")
			return
		}
	}

	if crossing.RevokedAt != nil || !crossing.ExpiresAt.After(time.Now()) {
		s.writeResponse(w, http.StatusOK, s.toTenantCrossingResponse(r.Context(), crossing))
		return
	}

	if err := s.tenantCrossingStore.RevokeTenantCrossing(r.Context(), crossing.ID); err != nil {
		s.logger.Error("Failed to revoke tenant crossing",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to end crossing", "END_FAILED")
		return
	}
	if updated, gerr := s.tenantCrossingStore.GetTenantCrossing(r.Context(), crossing.ID); gerr == nil && updated != nil {
		crossing = updated
	}

	severity, action := business.AuditSeverityHigh, "tenant.crossing_grant_ended"
	if crossing.Kind == business.TenantCrossingKindBreakGlass {
		severity, action = business.AuditSeverityCritical, "tenant.crossing_break_glass_ended"
	}
	s.recordTenantCrossingAudit(r, existing.ID, callerID, crossing, severity, action, "ended early")

	s.writeResponse(w, http.StatusOK, s.toTenantCrossingResponse(r.Context(), crossing))
}
