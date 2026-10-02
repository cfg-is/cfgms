// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import "github.com/gorilla/mux"

// RouteRegistrarFunc is a function that registers feature routes on the /api/v1 subrouter.
// Each registrar creates its own named subrouter via api.PathPrefix(...).Subrouter() and
// registers routes on it, exactly mirroring the block it replaces in setupRouter.
type RouteRegistrarFunc func(s *Server, api *mux.Router)

var routeRegistrars []RouteRegistrarFunc

// RegisterRoutes appends fn to the slice of registrars run by setupRouter.
// Safe to call from package init() — all init() functions complete before New() is called.
func RegisterRoutes(fn RouteRegistrarFunc) {
	routeRegistrars = append(routeRegistrars, fn)
}
