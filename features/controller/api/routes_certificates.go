// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerCertificateRoutes) }

func registerCertificateRoutes(s *Server, api *mux.Router) {
	// Certificate management endpoints
	certs := api.PathPrefix("/certificates").Subrouter()
	certs.Handle("", s.requirePermission("certificate", "list")(http.HandlerFunc(s.handleListCertificates))).Methods("GET")
	certs.Handle("/provision", s.requirePermission("certificate", "provision")(http.HandlerFunc(s.handleProvisionCertificate))).Methods("POST")
	certs.Handle("/signing/rotate", s.requirePermission("certificate", "rotate")(http.HandlerFunc(s.handleRotateSigningCert))).Methods("POST")
}
