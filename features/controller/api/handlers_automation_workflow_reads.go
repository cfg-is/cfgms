// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/workflow"
)

// automationExecutionListScanLimit bounds how many of the run tenant's newest
// executions the list route checks against the run's artifacts.
const automationExecutionListScanLimit = 500

// The execution read routes let a grant read the workflow executions its own run
// started and nothing else. The existing execution handlers (handleGetExecution,
// handleGetWorkflowExecutions) scope a read to the caller's own workflow store, and they
// refuse a workflow that the run tenant inherits from an owner tenant, which is the
// ordinary case for a grant; so these handlers read the engine directly, through the same
// s.workflowHandler, in exactly the run tenant, and admit an execution only when the run
// recorded it (HasArtifact). Unknown, another run's and another tenant's executions all
// answer the same 404, so the response is no existence oracle.

// handleAutomationGetExecution serves GET .../executions/{exec_id}.
func (s *Server) handleAutomationGetExecution(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	runStore, h := s.automationRunStore(), s.workflowHandlerOrNil()
	if run == nil {
		s.writeErrorResponse(w, http.StatusForbidden, "The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	if runStore == nil || h == nil || h.engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Workflow service not available", "SERVICE_UNAVAILABLE")
		return
	}
	execID := mux.Vars(r)["exec_id"]
	started, err := runStore.HasArtifact(r.Context(), run.ID, automationArtifactKindExecution, execID)
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation artifact lookup failed", err)
		return
	}
	if !started {
		s.writeErrorResponse(w, http.StatusNotFound, "Execution not found", "NOT_FOUND")
		return
	}
	execution, err := h.engine.GetExecution(r.Context(), run.TenantID, execID)
	if errors.Is(err, workflow.ErrExecutionNotFound) {
		s.writeErrorResponse(w, http.StatusNotFound, "Execution not found", "NOT_FOUND")
		return
	}
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation execution read failed", err)
		return
	}
	s.writeSuccessResponse(w, execution)
}

// handleAutomationListExecutions serves GET .../executions: the executions of the run
// tenant that this run started, newest first.
func (s *Server) handleAutomationListExecutions(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	runStore, h := s.automationRunStore(), s.workflowHandlerOrNil()
	if run == nil {
		s.writeErrorResponse(w, http.StatusForbidden, "The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	if runStore == nil || h == nil || h.engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Workflow service not available", "SERVICE_UNAVAILABLE")
		return
	}
	all, err := h.engine.ListExecutions(r.Context(), run.TenantID)
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation execution list failed", err)
		return
	}
	if len(all) > automationExecutionListScanLimit {
		all = all[:automationExecutionListScanLimit]
	}
	started := make([]*workflow.WorkflowExecution, 0, len(all))
	for _, execution := range all {
		ok, err := runStore.HasArtifact(r.Context(), run.ID, automationArtifactKindExecution, execution.ID)
		if err != nil {
			s.writeAutomationUnavailable(w, "Automation artifact lookup failed", err)
			return
		}
		if ok {
			started = append(started, execution)
		}
	}
	s.writeSuccessResponse(w, started)
}
