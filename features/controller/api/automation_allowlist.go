// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"sync"

	"github.com/gorilla/mux"
)

// The automation route table is the one closed list of routes an automation-grant
// principal (ADR-036 section 3) may reach. It is keyed by HTTP method AND mux route
// template, so the same template under another method is refused.
//
// The table is filled only by registerAutomationRoute (routes_automation.go), which
// also wraps the handler in requireAutomationRun, so membership comes from a route
// opting in through that helper, never from a path prefix: a route that merely sits
// under /api/v1/automation/runs/{run_id}/ is not admitted.

type automationRoute struct {
	method   string
	template string
}

var (
	automationRoutesMu sync.RWMutex
	automationRoutes   []automationRoute
)

// addAutomationRoute admits method and template into the table. Admitting a pair
// twice (one registration per constructed Server) keeps a single entry.
func addAutomationRoute(method, template string) {
	automationRoutesMu.Lock()
	defer automationRoutesMu.Unlock()
	for _, rt := range automationRoutes {
		if rt.method == method && rt.template == template {
			return
		}
	}
	automationRoutes = append(automationRoutes, automationRoute{method: method, template: template})
}

// automationRouteTable returns a copy of the table, for tests that must exercise
// every admitted route.
func automationRouteTable() []automationRoute {
	automationRoutesMu.RLock()
	defer automationRoutesMu.RUnlock()
	return append([]automationRoute(nil), automationRoutes...)
}

// automationRouteAllowed reports whether a grant principal may reach the route with
// the given method and mux path template. An empty template (no matched route) is
// never allowed.
func automationRouteAllowed(method, template string) bool {
	if template == "" {
		return false
	}
	automationRoutesMu.RLock()
	defer automationRoutesMu.RUnlock()
	for _, rt := range automationRoutes {
		if rt.method == method && rt.template == template {
			return true
		}
	}
	return false
}

// automationRouteGuard is the router-level default deny for grant principals. It
// sits in the api subrouter chain straight after authenticationMiddleware: after
// gorilla/mux has matched the route (so the matched template is known) and before
// validation, CSRF, permission middleware and every handler. A request whose
// principal is not a grant passes through untouched. A grant request is refused with
// 403 unless its matched route template is in the table for its method, which also
// covers routes registered without requirePermission. A request mux cannot match
// (unknown path, method mismatch) never reaches this middleware: mux answers it from
// its NotFound/MethodNotAllowed handlers without running any route handler.
func (s *Server) automationRouteGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		if principal == nil || principal.Channel != AuthChannelAutomationGrant {
			next.ServeHTTP(w, r)
			return
		}
		template := ""
		if route := mux.CurrentRoute(r); route != nil {
			if tpl, err := route.GetPathTemplate(); err == nil {
				template = tpl
			}
		}
		if !automationRouteAllowed(r.Method, template) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Automation grant credentials cannot access this route", "AUTOMATION_ROUTE_DENIED")
			return
		}
		next.ServeHTTP(w, r)
	})
}
