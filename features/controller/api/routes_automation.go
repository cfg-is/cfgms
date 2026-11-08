// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerAutomationRoutes) }

const (
	// automationBeginTemplate is the one automation route that has no run id.
	automationBeginTemplate = "/api/v1/automation/runs"
	automationEndTemplate   = "/api/v1/automation/runs/{run_id}/end"
)

// registerAutomationRoute is the only way a route joins the automation route table
// (ADR-036 section 3). It wraps the handler in requireAutomationRun, so the run
// binding is enforced before the handler runs, and admits the route's full mux path
// template, read back from the registered route, under its method. Every automation
// route registers through it; a route registered any other way is refused for a
// grant principal by automationRouteGuard.
func (s *Server) registerAutomationRoute(router *mux.Router, method, template string, handler http.HandlerFunc) *mux.Route {
	route := router.Handle(template, s.requireAutomationRun(handler)).Methods(method)
	if full, err := route.GetPathTemplate(); err == nil {
		addAutomationRoute(method, full)
	}
	return route
}

// Tenant-crossing classification: these routes are reachable only by an automation
// grant principal, whose tenant is fixed by its run binding, so no crossing applies.
func registerAutomationRoutes(s *Server, api *mux.Router) {
	s.registerAutomationRoute(api, http.MethodPost, "/automation/runs", s.handleAutomationRunBegin)
	s.registerAutomationRoute(api, http.MethodPost, "/automation/runs/{run_id}/end", s.handleAutomationRunEnd)
}
