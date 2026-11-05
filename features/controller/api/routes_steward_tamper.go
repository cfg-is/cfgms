// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerStewardTamperRoutes) }

// registerStewardTamperRoutes registers the operator verbs that end a tampered
// steward's state. All require AssuranceStrong via permissionAssurance.
func registerStewardTamperRoutes(s *Server, api *mux.Router) {
	api.Handle("/stewards/{id}/tamper/restore", s.requirePermission("steward", "tamper-restore")(http.HandlerFunc(s.handleRestoreTamperedSteward))).Methods("POST")
	api.Handle("/stewards/{id}/tamper/ban", s.requirePermission("steward", "tamper-ban")(http.HandlerFunc(s.handleBanTamperedSteward))).Methods("POST")
	api.Handle("/stewards/{id}/tamper/repair", s.requirePermission("steward", "tamper-repair")(http.HandlerFunc(s.handleRepairTamperedSteward))).Methods("POST")
	api.Handle("/stewards/{id}/tamper/repair", s.requirePermission("steward", "tamper-repair")(http.HandlerFunc(s.handleGetTamperRepair))).Methods("GET")
}
