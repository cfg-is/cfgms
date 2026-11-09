// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/pkg/logging"
)

// The automation read routes (ADR-036 section 3) let a grant read stewards, DNA and
// the runs and jobs its own run started. Each is a thin wrapper that runs behind
// requireAutomationRun, which has already fixed the tenant, and then calls the
// existing read handler, so no query logic is copied here.
//
// The existing handlers scope a read to the caller's tenant SUBTREE. A run is locked
// to exactly one tenant, so each wrapper adds the exact-tenant decision (runTenantOnly)
// around the handler: a device in a descendant tenant is refused before a by-ID read
// and dropped from a list. Nothing here widens what the handlers return.

// automationArtifactKindRun is the artifact kind under which a run records the runs
// it started.
const automationArtifactKindRun = "run"

// bufferedResponse captures what a handler writes so the wrapper can narrow it
// before it reaches the client.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: http.Header{}}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *bufferedResponse) ok() bool { return b.status == 0 || b.status == http.StatusOK }

// replay writes the captured response unchanged.
func (b *bufferedResponse) replay(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

// data decodes the "data" member of a captured success envelope into out.
func (b *bufferedResponse) data(out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b.body.Bytes(), &env); err != nil {
		return err
	}
	return json.Unmarshal(env.Data, out)
}

func (s *Server) writeAutomationReadFailure(w http.ResponseWriter, what string, err error) {
	s.logger.Error(what, "error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read result", "INTERNAL_ERROR")
}

// automationStewardTenant resolves the tenant that owns a steward the way the
// existing by-ID handlers do: the live registry first, the durable record second.
func (s *Server) automationStewardTenant(ctx context.Context, stewardID string) (string, bool) {
	if s.controllerService != nil {
		if info, ok := s.controllerService.GetStewardInfo(stewardID); ok {
			return info.TenantID, true
		}
	}
	if rec := s.durableStewardRecord(ctx, stewardID); rec != nil {
		return rec.TenantID, true
	}
	return "", false
}

// admitAutomationSteward refuses, with the handlers' own 404, a steward that does not
// exist or whose own tenant is not exactly the run tenant.
func (s *Server) admitAutomationSteward(w http.ResponseWriter, r *http.Request) bool {
	run := automationRunFromContext(r.Context())
	tenant, found := s.automationStewardTenant(r.Context(), mux.Vars(r)["id"])
	if run == nil || !found || !runTenantOnly(run.TenantID, tenant) {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return false
	}
	return true
}

// handleAutomationListStewards serves GET .../stewards: handleListStewards, with every
// steward outside the run tenant dropped. Pagination is applied after the drop so
// total counts only run-tenant stewards, never a descendant's.
func (s *Server) handleAutomationListStewards(w http.ResponseWriter, r *http.Request) {
	run := automationRunFromContext(r.Context())
	if run == nil {
		s.writeErrorResponse(w, http.StatusForbidden,
			"The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
		return
	}
	limit, offset, paginated, perr := parseStewardPagination(r.URL.Query())
	if perr != nil {
		// The handler answers a bad page request itself.
		s.handleListStewards(w, r)
		return
	}
	inner := r
	if paginated {
		inner = r.Clone(r.Context())
		u := *r.URL
		q := u.Query()
		q.Del("limit")
		q.Del("offset")
		u.RawQuery = q.Encode()
		inner.URL = &u
	}
	buf := newBufferedResponse()
	s.handleListStewards(buf, inner)
	if !buf.ok() {
		buf.replay(w)
		return
	}
	var all []StewardInfo
	if err := buf.data(&all); err != nil {
		s.writeAutomationReadFailure(w, "Automation steward list could not be decoded", err)
		return
	}
	kept := make([]StewardInfo, 0, len(all))
	for _, info := range all {
		if runTenantOnly(run.TenantID, info.TenantID) {
			kept = append(kept, info)
		}
	}
	if paginated {
		s.writeSuccessResponse(w, paginateStewards(kept, limit, offset))
		return
	}
	s.writeSuccessResponse(w, kept)
}

// handleAutomationGetSteward serves GET .../stewards/{id}: handleGetSteward for a
// steward whose own tenant is the run tenant.
func (s *Server) handleAutomationGetSteward(w http.ResponseWriter, r *http.Request) {
	if !s.admitAutomationSteward(w, r) {
		return
	}
	s.handleGetSteward(w, r)
}

// handleAutomationGetStewardDNA serves GET .../stewards/{id}/dna: handleGetStewardDNA
// for a steward whose own tenant is the run tenant.
func (s *Server) handleAutomationGetStewardDNA(w http.ResponseWriter, r *http.Request) {
	if !s.admitAutomationSteward(w, r) {
		return
	}
	s.handleGetStewardDNA(w, r)
}

// admitAutomationResultRun admits a read of the result run named in the path only when
// this run started it and the run record sits in exactly the run tenant. Unknown, other
// runs' and out-of-tenant runs all answer the same 404, so the response is no existence
// oracle. On success it returns the request with {run_id} set to the result run id, the
// variable the existing run handlers read.
func (s *Server) admitAutomationResultRun(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	run := automationRunFromContext(r.Context())
	runStore := s.automationRunStore()
	if run == nil || runStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	resultRunID := mux.Vars(r)["result_run_id"]
	notFound := func() { s.writeErrorResponse(w, http.StatusNotFound, "Run not found", "NOT_FOUND") }
	started, err := runStore.HasArtifact(r.Context(), run.ID, automationArtifactKindRun, resultRunID)
	if err != nil {
		s.writeAutomationUnavailable(w, "Automation artifact lookup failed", err)
		return nil, false
	}
	if !started {
		notFound()
		return nil, false
	}
	if s.runManager != nil {
		if rec, err := s.runManager.GetRun(r.Context(), resultRunID); err == nil && !runTenantOnly(run.TenantID, rec.TenantID) {
			notFound()
			return nil, false
		}
	}
	vars := map[string]string{}
	for k, v := range mux.Vars(r) {
		vars[k] = v
	}
	vars["run_id"] = resultRunID
	return mux.SetURLVars(r, vars), true
}

// handleAutomationGetResultRun serves GET .../results/{result_run_id}: handleGetRun
// for a run this run started.
func (s *Server) handleAutomationGetResultRun(w http.ResponseWriter, r *http.Request) {
	inner, ok := s.admitAutomationResultRun(w, r)
	if !ok {
		return
	}
	s.handleGetRun(w, inner)
}

// handleAutomationGetResultRunJobs serves GET .../results/{result_run_id}/jobs:
// handleGetRunJobs for a run this run started, with every job whose device is not in
// exactly the run tenant dropped (an unresolvable device is dropped too).
func (s *Server) handleAutomationGetResultRunJobs(w http.ResponseWriter, r *http.Request) {
	inner, ok := s.admitAutomationResultRun(w, r)
	if !ok {
		return
	}
	run := automationRunFromContext(r.Context())
	buf := newBufferedResponse()
	s.handleGetRunJobs(buf, inner)
	if !buf.ok() {
		buf.replay(w)
		return
	}
	var rows []json.RawMessage
	if err := buf.data(&rows); err != nil {
		s.writeAutomationReadFailure(w, "Automation job list could not be decoded", err)
		return
	}
	kept := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		var job controllerrun.JobRecord
		if json.Unmarshal(row, &job) != nil {
			continue
		}
		if tenant, found := s.automationStewardTenant(r.Context(), job.DeviceID); found && runTenantOnly(run.TenantID, tenant) {
			kept = append(kept, row)
		}
	}
	s.writeSuccessResponse(w, kept)
}
