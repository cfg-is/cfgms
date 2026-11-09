// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAutomationWorkflowRunRoutes) }

// registerAutomationWorkflowRunRoutes registers the three workflow routes of a run: start
// one pinned, approved workflow version, read one execution this run started, and list
// the executions this run started. All three go through registerAutomationRoute, so each
// sits behind requireAutomationRun and joins the automation route table; none is wrapped
// by requirePermission, because a grant principal holds no permissions and the run
// binding, the approval evaluator and the run tenant confine the call instead. The human
// execute route (POST /workflows/{id}/execute) is not in the table, so a grant principal
// is refused there by automationRouteGuard.
//
// Tenant-crossing classification: these routes are reachable only by an automation
// grant principal, whose tenant is fixed by its run binding, so no crossing applies.
func registerAutomationWorkflowRunRoutes(s *Server, api *mux.Router) {
	s.registerAutomationRoute(api, http.MethodPost, automationRunReadBase+"/workflows/{name}", s.handleAutomationPostWorkflowRun)
	s.registerAutomationRoute(api, http.MethodGet, automationRunReadBase+"/executions", s.handleAutomationListExecutions)
	s.registerAutomationRoute(api, http.MethodGet, automationRunReadBase+"/executions/{exec_id}", s.handleAutomationGetExecution)
}
