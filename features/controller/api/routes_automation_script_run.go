// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAutomationScriptRunRoutes) }

const (
	// automationScriptsPath is the route a grant starts and lists library scripts
	// through, under its run (ADR-036 sections 1 and 3), relative to the api router.
	automationScriptsPath = automationRunReadBase + "/scripts"
	// automationScriptsTemplate is the same route as it appears in the route table.
	automationScriptsTemplate = "/api/v1" + automationScriptsPath
)

// registerAutomationScriptRunRoutes registers the two script routes of a run. Both go
// through registerAutomationRoute, so each sits behind requireAutomationRun and its
// method and mux template join the automation route table; neither is wrapped by
// requirePermission, because a grant principal holds no permissions and the run
// binding, the approval evaluator and the run tenant confine the call instead. The
// human run routes under /runs are not in the table, so a grant principal is refused
// there by automationRouteGuard.
//
// Tenant-crossing classification: these routes are reachable only by an automation
// grant principal, whose tenant is fixed by its run binding, so no crossing applies.
func registerAutomationScriptRunRoutes(s *Server, api *mux.Router) {
	s.registerAutomationRoute(api, http.MethodPost, automationScriptsPath, s.handleAutomationPostScriptRun)
	s.registerAutomationRoute(api, http.MethodGet, automationScriptsPath, s.handleAutomationListScripts)
}
