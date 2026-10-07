// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Target kinds of the two action endpoints.
const (
	stewardActionKindService = "service"
	stewardActionKindProcess = "process"
)

const (
	// stewardActionMaxBodyBytes bounds an action or prepare request body.
	stewardActionMaxBodyBytes = 64 * 1024
	// stewardActionMaxJustification bounds the mandatory justification text.
	stewardActionMaxJustification = 1024

	// stewardActionBudgetKeyPrefix namespaces the per-principal action counter within
	// the shared s.rateCounterStore table.
	stewardActionBudgetKeyPrefix = "steward-action:"
	// stewardActionBudgetWindow is the fixed window the per-principal budget counts in.
	stewardActionBudgetWindow = time.Minute
)

// stewardActionVerbs maps a request's action word to the steward verb it signs, per
// target kind. The set is the steward's own closed allowlist; anything else is refused
// here so the operator is never asked to sign a verb the steward would reject.
var stewardActionVerbs = map[string]map[string]string{
	stewardActionKindService: {"start": "service.start", "stop": "service.stop", "restart": "service.restart"},
	stewardActionKindProcess: {"end": "process.end", "suspend": "process.suspend", "resume": "process.resume"},
}

var (
	// stewardActionNamePattern and stewardActionImagePattern mirror the bounds the
	// steward applies to a target name and a process image name.
	stewardActionNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,256}$`)
	stewardActionImagePattern = regexp.MustCompile(`^[^\x00-\x1f/\\]{1,256}$`)
)

// stewardActionRequest is the body of the two action endpoints. Nonce, ExpiresAt and
// Targets are copied from the sign/begin envelope; Signature (X.509) or WebAuthn is the
// sign/finish proof. The action content is rebuilt from Action, Image and the path,
// never taken from the client.
type stewardActionRequest struct {
	Action        string                 `json:"action"`
	Justification string                 `json:"justification"`
	Image         string                 `json:"image,omitempty"`
	Nonce         string                 `json:"nonce"`
	ExpiresAt     string                 `json:"expires_at"`
	Targets       []string               `json:"targets"`
	Signature     *OperatorX509Proof     `json:"signature,omitempty"`
	WebAuthn      *OperatorWebAuthnProof `json:"webauthn,omitempty"`
}

// stewardActionPrepareRequest is the body of POST /stewards/{id}/actions/prepare.
type stewardActionPrepareRequest struct {
	TargetKind string `json:"target_kind"`
	TargetName string `json:"target_name"`
	Action     string `json:"action"`
	Image      string `json:"image,omitempty"`
}

// stewardActionPrepareResponse carries only the canonical content and shell. Nonce,
// expiry and targets come from sign/begin, never from here.
type stewardActionPrepareResponse struct {
	Content string `json:"content"` // base64 of operatorpayload.ActionContent
	Shell   string `json:"shell"`
}

func peekStewardActionKind(raw []byte) (string, error) {
	var probe struct {
		TargetKind string `json:"target_kind"`
	}
	err := json.Unmarshal(raw, &probe)
	return probe.TargetKind, err
}

// buildStewardAction validates and assembles the action an operator signs. The target
// name is the service name, or the decimal PID for a process, whose single parameter is
// the image name the operator saw.
func buildStewardAction(kind, name, action, image string) (operatorpayload.Action, error) {
	verb, ok := stewardActionVerbs[kind][action]
	if !ok {
		return operatorpayload.Action{}, fmt.Errorf("unsupported %s action", kind)
	}
	if !stewardActionNamePattern.MatchString(name) {
		return operatorpayload.Action{}, errors.New("invalid target name")
	}
	a := operatorpayload.Action{Verb: verb, TargetKind: kind, TargetName: name}
	switch kind {
	case stewardActionKindService:
		if image != "" {
			return operatorpayload.Action{}, errors.New("image applies to process actions only")
		}
	case stewardActionKindProcess:
		if pid, err := strconv.ParseInt(name, 10, 32); err != nil || pid <= 0 {
			return operatorpayload.Action{}, errors.New("process target must be a decimal PID")
		}
		if !stewardActionImagePattern.MatchString(image) {
			return operatorpayload.Action{}, errors.New("a valid process image name is required")
		}
		a.Parameters = map[string]string{"image": image}
	}
	if _, err := operatorpayload.ActionContent(a); err != nil {
		return operatorpayload.Action{}, errors.New("invalid action")
	}
	return a, nil
}

// handlePrepareStewardAction handles POST /api/v1/stewards/{id}/actions/prepare. It
// returns the canonical content the operator signs and the shell, so the browser never
// re-implements canonicalization. Nothing is enqueued and nothing is signed here.
func (s *Server) handlePrepareStewardAction(w http.ResponseWriter, r *http.Request) {
	var req stewardActionPrepareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}
	action, err := buildStewardAction(req.TargetKind, req.TargetName, req.Action, req.Image)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ACTION")
		return
	}
	content, err := operatorpayload.ActionContent(action)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid action", "INVALID_ACTION")
		return
	}
	s.writeSuccessResponse(w, stewardActionPrepareResponse{
		Content: base64.StdEncoding.EncodeToString(content),
		Shell:   operatorpayload.ActionShell,
	})
}

// handlePostStewardAction handles the service and process action endpoints. The
// route wrapper has already authorized the permission, the caller's tenant scope and
// the ADR-025 crossing for the {id} steward. This handler validates the request,
// verifies the operator envelope before anything is queued, applies the per-principal
// budget, then creates the run and enqueues it through the shared stores. It never
// sends to the steward or waits for a result: the caller polls GET /runs/{run_id}.
func (s *Server) handlePostStewardAction(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.runManager == nil || s.runExecutionQueue == nil {
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Run service not available", "SERVICE_UNAVAILABLE")
			return
		}
		principal, _, ok := s.authRunAccess(w, r)
		if !ok {
			return
		}

		vars := mux.Vars(r)
		stewardID := vars["id"]
		name := vars["name"]
		if kind == stewardActionKindProcess {
			name = vars["pid"]
		}

		var req stewardActionRequest
		r.Body = http.MaxBytesReader(w, r.Body, stewardActionMaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
			return
		}
		action, err := buildStewardAction(kind, name, req.Action, req.Image)
		if err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ACTION")
			return
		}
		justification := strings.TrimSpace(req.Justification)
		if justification == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "justification is required", "MISSING_JUSTIFICATION")
			return
		}
		if len(justification) > stewardActionMaxJustification || strings.ContainsFunc(justification, unicode.IsControl) {
			s.writeErrorResponse(w, http.StatusBadRequest, "justification is too long or contains control characters", "INVALID_JUSTIFICATION")
			return
		}
		if req.Nonce == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "nonce is required", "MISSING_NONCE")
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "expires_at must be RFC3339", "INVALID_EXPIRES_AT")
			return
		}
		now := time.Now()
		if !expiresAt.After(now) {
			s.writeErrorResponse(w, http.StatusBadRequest, "operator envelope has expired", "ENVELOPE_EXPIRED")
			return
		}
		if expiresAt.After(now.Add(operatorpayload.ActionEnvelopeMaxTTL)) {
			s.writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("operator envelope expiry exceeds the %s maximum", operatorpayload.ActionEnvelopeMaxTTL), "ENVELOPE_TTL_EXCEEDED")
			return
		}
		if len(req.Targets) != 1 || req.Targets[0] != stewardID {
			s.writeErrorResponse(w, http.StatusBadRequest, "targets must be exactly the addressed steward", "INVALID_TARGETS")
			return
		}

		var proof OperatorProof
		var commandSignature *controllerrun.CommandSignature
		switch {
		case req.Signature != nil && req.WebAuthn != nil:
			s.writeErrorResponse(w, http.StatusBadRequest, "provide exactly one operator proof", "INVALID_SIGNATURE")
			return
		case req.Signature != nil:
			proof.X509 = req.Signature
			commandSignature = &controllerrun.CommandSignature{
				Algorithm: req.Signature.Algorithm, Value: req.Signature.Value, PublicKey: req.Signature.PublicKey,
			}
		case req.WebAuthn != nil:
			proof.WebAuthn = req.WebAuthn
			b64 := base64.StdEncoding.EncodeToString
			commandSignature = &controllerrun.CommandSignature{
				WebAuthnAuthenticatorData: b64(req.WebAuthn.AuthenticatorData),
				WebAuthnClientDataJSON:    b64(req.WebAuthn.ClientDataJSON),
				WebAuthnSignature:         b64(req.WebAuthn.Signature),
				WebAuthnCredentialID:      b64(req.WebAuthn.CredentialID),
			}
		default:
			s.writeErrorResponse(w, http.StatusForbidden, "operator signature is required", "OPERATOR_SIGNATURE_REQUIRED")
			return
		}

		info, known := s.controllerService.GetStewardInfo(stewardID)
		if !known {
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return
		}
		stewardTenant := info.TenantID

		credentialID, err := s.verifyOperatorActionEnvelope(r.Context(), stewardID, action, req.Targets, req.Nonce, expiresAt, proof)
		if err != nil {
			s.logger.Warn("Steward action refused: operator envelope not verified",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"principal_id", logging.SanitizeLogValue(principal.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.emitStewardActionAudit(r.Context(), stewardTenant, principal.ID, stewardID, action, justification, "", "",
				business.AuditResultDenied, "operator envelope not verified")
			s.writeErrorResponse(w, http.StatusForbidden, "invalid operator signature", "INVALID_SIGNATURE")
			return
		}

		// Fan-out bound (#3698): each request names one target, so the bound on signed
		// targets per request would not limit a burst of single-target requests. Count
		// accepted actions per principal instead; only a verified request counts.
		bound := s.resolveMaxTargetsForTenant(r.Context(), stewardTenant)
		if !s.admitStewardAction(r.Context(), principal.ID, bound) {
			s.emitStewardActionAudit(r.Context(), stewardTenant, principal.ID, stewardID, action, justification, credentialID, "",
				business.AuditResultDenied, fmt.Sprintf("action budget of %d per %s exceeded", bound, stewardActionBudgetWindow))
			s.writeErrorResponse(w, http.StatusTooManyRequests, "steward action budget exceeded", "ACTION_BUDGET_EXCEEDED")
			return
		}

		if proof.WebAuthn != nil {
			manifest, err := s.buildWebAuthnManifestForSteward(r.Context(), stewardID)
			if err != nil {
				s.logger.Error("Steward action not queued: WebAuthn manifest unavailable",
					"steward_id", logging.SanitizeLogValue(stewardID),
					"error", logging.SanitizeLogValue(err.Error()))
				s.emitStewardActionAudit(r.Context(), stewardTenant, principal.ID, stewardID, action, justification, credentialID, "",
					business.AuditResultError, "webauthn manifest unavailable")
				s.writeErrorResponse(w, http.StatusServiceUnavailable, "Operator credential manifest not available", "MANIFEST_UNAVAILABLE")
				return
			}
			commandSignature.WebAuthnManifest = manifest
		}

		runID, err := controllerrun.SynthesizeActionRunForDevices(
			r.Context(), s.runManager, s.runExecutionQueue,
			[]fleet.StewardResult{{ID: stewardID, TenantID: stewardTenant}},
			stewardTenant, principal.ID,
			fleet.Filter{IDs: []string{stewardID}},
			scriptmodule.StewardActionSpec{
				Verb: action.Verb, TargetKind: action.TargetKind, TargetName: action.TargetName, Parameters: action.Parameters,
			},
			commandSignature, req.Targets, req.Nonce, expiresAt,
		)
		if err != nil {
			s.logger.Error("Failed to synthesize steward action run",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.emitStewardActionAudit(r.Context(), stewardTenant, principal.ID, stewardID, action, justification, credentialID, "",
				business.AuditResultError, "failed to queue action")
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create run", "INTERNAL_ERROR")
			return
		}

		s.emitStewardActionAudit(r.Context(), stewardTenant, principal.ID, stewardID, action, justification, credentialID, runID,
			business.AuditResultSuccess, "")
		s.writeResponse(w, http.StatusAccepted, map[string]string{"run_id": runID})
	}
}

// emitStewardActionAudit records a steward action request or its refusal. The resource
// id is the cfg-declared steward id, never a live host name. The signing credential id is
// recorded as "signer_id": the audit manager redacts any key containing "credential". The completion of an
// accepted request is audited by the dispatcher when the steward reports.
func (s *Server) emitStewardActionAudit(ctx context.Context, tenantID, principalID, stewardID string, action operatorpayload.Action,
	justification, credentialID, runID string, result business.AuditResult, reason string) {
	if s.auditManager == nil {
		return
	}
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	severity := business.AuditSeverityHigh
	if result != business.AuditResultSuccess {
		severity = business.AuditSeverityCritical
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("steward_action.request").
		User(principalID, business.AuditUserTypeHuman).
		Resource("steward", stewardID, action.Verb).
		Result(result).
		Severity(severity).
		Detail("verb", action.Verb).
		Detail("target_kind", action.TargetKind).
		Detail("target_name", action.TargetName).
		Detail("justification", justification).
		Detail("signer_id", credentialID).
		Detail("run_id", runID)
	if image := action.Parameters["image"]; image != "" {
		b = b.Detail("image", image)
	}
	if reason != "" {
		b = b.Detail("rejection_reason", reason)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit steward action audit event",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// stewardActionBudgetRecord is the node-local fixed-window counter used when no
// cluster-visible RateCounterStore is wired.
type stewardActionBudgetRecord struct {
	mu    sync.Mutex
	start time.Time
	count int
}

// admitStewardAction counts one accepted action for principalID in the current fixed
// window and reports whether it is within bound. With a cluster-visible
// s.rateCounterStore the count is shared across nodes; ErrRateCounterCapacityExhausted
// denies (fail closed). Any other store error, or no store, falls back to a node-local
// counter, as the sign throttle does, so the bound still holds on a single node.
func (s *Server) admitStewardAction(ctx context.Context, principalID string, bound int) bool {
	if s.rateCounterStore != nil {
		count, _, err := s.rateCounterStore.Increment(ctx, stewardActionBudgetKeyPrefix+principalID, stewardActionBudgetWindow)
		if err == nil {
			return count <= bound
		}
		if errors.Is(err, business.ErrRateCounterCapacityExhausted) {
			return false
		}
		s.logger.Warn("Steward action budget: shared counter unavailable; using node-local counter",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	raw, _ := s.stewardActionBudget.LoadOrStore(principalID, &stewardActionBudgetRecord{})
	rec := raw.(*stewardActionBudgetRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	now := time.Now()
	if rec.start.IsZero() || now.Sub(rec.start) >= stewardActionBudgetWindow {
		rec.start, rec.count = now, 0
	}
	rec.count++
	return rec.count <= bound
}
