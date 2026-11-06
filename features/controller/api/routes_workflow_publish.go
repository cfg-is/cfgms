// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerWorkflowPublishRoutes) }

// registerWorkflowPublishRoutes registers the publish ceremony for one stored workflow
// version. workflow:publish carries AssuranceStrong with no presence token: the
// passkey assertion collected by finish is itself the proof.
func registerWorkflowPublishRoutes(s *Server, api *mux.Router) {
	pub := api.PathPrefix("/workflows/{id}/versions/{version}/publish").Subrouter()
	pub.Handle("/begin", s.requirePermission("workflow", "publish")(http.HandlerFunc(s.handleWorkflowPublishBegin))).Methods("POST")
	pub.Handle("/finish", s.requirePermission("workflow", "publish")(http.HandlerFunc(s.handleWorkflowPublishFinish))).Methods("POST")
}
