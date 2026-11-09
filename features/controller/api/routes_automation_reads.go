// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAutomationReadRoutes) }

const automationRunReadBase = "/automation/runs/{run_id}"

// registerAutomationReadRoutes admits the closed set of read routes a grant may call
// within a run. Every route registers through registerAutomationRoute, so it sits
// behind requireAutomationRun and joins the route table; nothing else does. The
// handlers call the existing read handlers (handlers_automation_reads.go).
//
// Tenant-crossing classification: these routes are reachable only by an automation
// grant principal, whose tenant is fixed by its run binding, so no crossing applies.
func registerAutomationReadRoutes(s *Server, api *mux.Router) {
	for _, rt := range []struct {
		template string
		handler  http.HandlerFunc
	}{
		{"/stewards", s.handleAutomationListStewards},
		{"/stewards/{id}", s.handleAutomationGetSteward},
		{"/stewards/{id}/dna", s.handleAutomationGetStewardDNA},
		{"/results/{result_run_id}", s.handleAutomationGetResultRun},
		{"/results/{result_run_id}/jobs", s.handleAutomationGetResultRunJobs},
	} {
		s.registerAutomationRoute(api, http.MethodGet, automationRunReadBase+rt.template, rt.handler)
	}
}
