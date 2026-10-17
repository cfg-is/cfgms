// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

const terminalTicketMaxBodyBytes = 64 * 1024

// terminalPrepareRequest is the body of POST /terminal/prepare/{steward_id}.
type terminalPrepareRequest struct {
	TerminalShell string `json:"terminal_shell"`
}

// terminalPrepareResponse carries the content and envelope shell the browser feeds to
// operator-payload/sign/begin, and the terminal shell the content was built for.
type terminalPrepareResponse struct {
	Content       string `json:"content"` // base64 of operatorpayload.TerminalContent
	Shell         string `json:"shell"`   // envelope shell: operatorpayload.TerminalShell
	TerminalShell string `json:"terminal_shell"`
}

// terminalTicketRequest is the body of POST /terminal/tickets/{steward_id}. Nonce,
// ExpiresAt and Targets are copied from the sign/begin envelope; Signature (X.509) or
// WebAuthn is the sign/finish proof.
type terminalTicketRequest struct {
	TerminalShell string                 `json:"terminal_shell"`
	Nonce         string                 `json:"nonce"`
	ExpiresAt     string                 `json:"expires_at"`
	Targets       []string               `json:"targets"`
	Signature     *OperatorX509Proof     `json:"signature,omitempty"`
	WebAuthn      *OperatorWebAuthnProof `json:"webauthn,omitempty"`
}

type terminalTicketResponse struct {
	Ticket string `json:"ticket"`
}

// defaultTerminalShellForOS maps a steward's reported GOOS to its default terminal shell.
func defaultTerminalShellForOS(goos string) (string, bool) {
	switch strings.ToLower(goos) {
	case "":
		return "", false
	case "windows":
		return "powershell", true
	default:
		return "bash", true
	}
}

// handleTerminalPrepare handles POST /api/v1/terminal/prepare/{steward_id}. It returns the
// canonical content the operator signs. An empty terminal_shell resolves to the default
// for the target steward's platform (never the controller's); an unknown platform is 409.
func (s *Server) handleTerminalPrepare(w http.ResponseWriter, r *http.Request) {
	stewardID := mux.Vars(r)["steward_id"]
	var req terminalPrepareRequest
	r.Body = http.MaxBytesReader(w, r.Body, terminalTicketMaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}
	shell := req.TerminalShell
	if shell == "" {
		info, ok := s.controllerService.GetStewardInfo(stewardID)
		goos := ""
		if ok && info != nil && info.DNA != nil {
			goos = service.FlattenDNAFragments(info.DNA.Fragments)["os"]
		}
		resolved, known := defaultTerminalShellForOS(goos)
		if !known {
			s.writeErrorResponse(w, http.StatusConflict,
				"Steward platform is unknown; specify terminal_shell explicitly", "STEWARD_PLATFORM_UNKNOWN")
			return
		}
		shell = resolved
	} else if !terminal.ValidateShell(shell) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Unsupported terminal_shell", "INVALID_TERMINAL_SHELL")
		return
	}
	content, err := operatorpayload.TerminalContent(stewardID, shell)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid terminal request", "INVALID_REQUEST")
		return
	}
	s.writeSuccessResponse(w, terminalPrepareResponse{
		Content:       base64.StdEncoding.EncodeToString(content),
		Shell:         operatorpayload.TerminalShell,
		TerminalShell: shell,
	})
}

// handleTerminalTicket handles POST /api/v1/terminal/tickets/{steward_id}. It verifies the
// operator proof over the terminal-open envelope and mints a 30-second single-use ticket.
func (s *Server) handleTerminalTicket(w http.ResponseWriter, r *http.Request) {
	stewardID := mux.Vars(r)["steward_id"]
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "UNAUTHORIZED")
		return
	}

	var req terminalTicketRequest
	r.Body = http.MaxBytesReader(w, r.Body, terminalTicketMaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}
	if req.TerminalShell == "" || !terminal.ValidateShell(req.TerminalShell) {
		s.writeErrorResponse(w, http.StatusBadRequest, "A supported terminal_shell is required", "INVALID_TERMINAL_SHELL")
		return
	}

	refuse := func(reason string) {
		s.logger.Warn("Terminal ticket refused: operator envelope not verified",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(reason))
		s.writeErrorResponse(w, http.StatusForbidden, "invalid operator signature", "INVALID_SIGNATURE")
	}

	// A malformed or absent expiry cannot be a valid proof; it is reported like every
	// other proof failure.
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		refuse("expires_at must be RFC3339")
		return
	}
	var proof OperatorProof
	proof.X509, proof.WebAuthn = req.Signature, req.WebAuthn

	content, err := operatorpayload.TerminalContent(stewardID, req.TerminalShell)
	if err != nil {
		refuse(err.Error())
		return
	}
	if _, err := s.verifyOperatorEnvelope(r.Context(), stewardID, content, operatorpayload.TerminalShell,
		operatorpayload.TerminalEnvelopeMaxTTL, req.Targets, req.Nonce, expiresAt, proof); err != nil {
		refuse(err.Error())
		return
	}

	info, known := s.controllerService.GetStewardInfo(stewardID)
	if !known || info == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	rec := &terminalTicketRecord{
		principalID:   principal.ID,
		tenantID:      info.TenantID,
		webSessionID:  webSessionIDFromContext(r),
		stewardID:     stewardID,
		terminalShell: req.TerminalShell,
		expires:       time.Now().Add(terminalTicketTTL),
		targets:       req.Targets,
		nonce:         req.Nonce,
		expiresAt:     expiresAt,
		x509:          proof.X509,
		webAuthn:      proof.WebAuthn,
	}
	if proof.WebAuthn != nil {
		manifest, err := s.buildWebAuthnManifestForSteward(r.Context(), stewardID)
		if err != nil {
			s.logger.Error("Terminal ticket not minted: WebAuthn manifest unavailable",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "Operator credential manifest not available", "MANIFEST_UNAVAILABLE")
			return
		}
		rec.manifest = manifest
	}

	ticket, ticketHash, err := newTerminalTicket()
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to mint ticket", "INTERNAL_ERROR")
		return
	}
	if s.putTerminalTicket(r.Context(), ticketHash, rec) != ceremonyOK {
		s.writeCeremonyUnavailable(w)
		return
	}
	s.writeSuccessResponse(w, terminalTicketResponse{Ticket: ticket})
}

// webSessionIDFromContext returns the cookie session ID of the request, or "" for a
// non-cookie principal.
func webSessionIDFromContext(r *http.Request) string {
	id, _ := r.Context().Value(webSessionIDContextKey).(string)
	return id
}
