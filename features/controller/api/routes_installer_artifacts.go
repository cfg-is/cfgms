// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerInstallerArtifactRoutes) }

func registerInstallerArtifactRoutes(s *Server, api *mux.Router) {
	// Installer artifact management endpoints (Issue #1702).
	// Always registered — handlers return 503 when blobStore is nil (nil-safe by design).
	installer := api.PathPrefix("/installer/artifacts").Subrouter()
	installer.Handle("", s.requirePermission("installer", "read")(http.HandlerFunc(s.handleListInstallerArtifacts))).Methods("GET")
	installer.Handle("/{platform}/{arch}", s.requirePermission("installer", "upload")(http.HandlerFunc(s.handleUploadInstallerArtifact))).Methods("PUT")
	installer.Handle("/{platform}/{arch}", s.requirePermission("installer", "read")(http.HandlerFunc(s.handleGetInstallerArtifact))).Methods("GET")
	installer.Handle("/{platform}/{arch}", s.requirePermission("installer", "delete")(http.HandlerFunc(s.handleDeleteInstallerArtifact))).Methods("DELETE")
}
