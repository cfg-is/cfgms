// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// maxCustomBodyBytes bounds a custom report or template request body.
	maxCustomBodyBytes = 1 << 20

	msgCustomUnavailable = "custom reports not available"
	msgCustomForbidden   = "forbidden"
	msgTemplateNotFound  = "template not found"
	msgStreamNotFound    = "report data not found"
	msgInternal          = "internal error"
)

// SetCustomReports wires the custom template manager and custom report builder. When
// either is nil the custom routes answer 503.
func (h *Handler) SetCustomReports(templates interfaces.CustomTemplateManager, builder interfaces.CustomReportBuilder) {
	h.customTemplates = templates
	h.customBuilder = builder
}

// customCaller is the authenticated caller as the custom routes see it.
type customCaller struct {
	tenant string
	// root is true when the caller is root-scoped (its tenant is the deployment root).
	root bool
	user string
}

// customCallerFrom resolves the caller's own tenant from the authenticated request
// context. It never reads a request field. ok is false when the context carries no usable
// tenant.
func customCallerFrom(ctx context.Context) (customCaller, bool) {
	tenant, unrestricted, ok := ctxkeys.TenantRestriction(ctx)
	if !ok {
		return customCaller{}, false
	}
	if unrestricted {
		// A root caller has no filter tenant; its own tenant is the deployment root.
		tenant, _ = ctx.Value(ctxkeys.TenantID).(string)
		if tenant == "" {
			return customCaller{}, false
		}
	}
	user, _ := ctx.Value(ctxkeys.UserIDKey).(string)
	return customCaller{tenant: tenant, root: unrestricted, user: user}, true
}

func (h *Handler) writeCustomError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, map[string]interface{}{"error": message, "status": status})
}

// requireTemplates answers 503 or 403 and returns false unless the template routes can
// proceed; on success it returns the manager and the caller.
func (h *Handler) requireTemplates(w http.ResponseWriter, r *http.Request) (interfaces.CustomTemplateManager, customCaller, bool) {
	mgr := h.customTemplates
	if mgr == nil || h.customBuilder == nil {
		h.writeCustomError(w, http.StatusServiceUnavailable, msgCustomUnavailable)
		return nil, customCaller{}, false
	}
	caller, ok := customCallerFrom(r.Context())
	if !ok {
		h.writeCustomError(w, http.StatusForbidden, msgCustomForbidden)
		return nil, customCaller{}, false
	}
	return mgr, caller, true
}

// requireBuilder is requireTemplates for the report routes. Custom reports cover only the
// caller's own non-root tenant, so a root-scoped caller is refused before any builder call.
func (h *Handler) requireBuilder(w http.ResponseWriter, r *http.Request) (interfaces.CustomReportBuilder, customCaller, bool) {
	builder := h.customBuilder
	if builder == nil || h.customTemplates == nil {
		h.writeCustomError(w, http.StatusServiceUnavailable, msgCustomUnavailable)
		return nil, customCaller{}, false
	}
	caller, ok := customCallerFrom(r.Context())
	if !ok || caller.root {
		h.writeCustomError(w, http.StatusForbidden, msgCustomForbidden)
		return nil, customCaller{}, false
	}
	return builder, caller, true
}

func decodeCustomBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxCustomBodyBytes)
	return json.NewDecoder(r.Body).Decode(v) == nil
}

// writeCustomManagerError maps a manager or builder error to a response. Error text is
// logged sanitized and never returned to the caller.
func (h *Handler) writeCustomManagerError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, interfaces.ErrTemplateNotFound), errors.Is(err, interfaces.ErrTemplateAccessDenied):
		h.writeCustomError(w, http.StatusNotFound, msgTemplateNotFound)
	case errors.Is(err, interfaces.ErrStreamTokenInvalid):
		h.writeCustomError(w, http.StatusNotFound, msgStreamNotFound)
	case errors.Is(err, interfaces.ErrShareTargetInvalid):
		h.writeCustomError(w, http.StatusBadRequest, "invalid share target")
	case errors.Is(err, interfaces.ErrParameterValidationFailed),
		errors.Is(err, interfaces.ErrInvalidQuery),
		errors.Is(err, interfaces.ErrDataSourceNotSupported):
		h.writeCustomError(w, http.StatusBadRequest, "invalid request")
	default:
		h.logger.Error("custom report operation failed", "operation", op, "error", logging.SanitizeLogValue(err.Error()))
		h.writeCustomError(w, http.StatusInternalServerError, msgInternal)
	}
}

// generateCustomReport handles POST /custom/generate.
func (h *Handler) generateCustomReport(w http.ResponseWriter, r *http.Request) {
	builder, caller, ok := h.requireBuilder(w, r)
	if !ok {
		return
	}
	var req interfaces.CustomReportRequest
	if !decodeCustomBody(w, r, &req) {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// The tenant and author come from the session, never from the body.
	req.TenantID = caller.tenant
	req.CreatedBy = caller.user

	report, err := builder.GenerateReport(r.Context(), req)
	if err != nil {
		h.writeCustomManagerError(w, "generate", err)
		return
	}
	h.writeJSON(w, http.StatusOK, report)
}

// getCustomReportData handles GET /custom/data. The stream_token is a bearer for a cached
// page and is never logged or echoed.
func (h *Handler) getCustomReportData(w http.ResponseWriter, r *http.Request) {
	builder, caller, ok := h.requireBuilder(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page, err := parseCustomInt(q.Get("page"), 1)
	if err != nil {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request")
		return
	}
	pageSize, err := parseCustomInt(q.Get("page_size"), 0)
	if err != nil {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request")
		return
	}
	data, hasMore, err := builder.GetReportData(r.Context(), interfaces.PaginationRequest{
		TenantID:    caller.tenant,
		StreamToken: q.Get("stream_token"),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		h.writeCustomManagerError(w, "data", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if hasMore {
		w.Header().Set("X-Has-More", "true")
	} else {
		w.Header().Set("X-Has-More", "false")
	}
	// The page is json.Marshal output from the builder; writeJSON re-encodes it as a
	// validated JSON value with HTML-significant characters escaped, served as
	// application/json, so the body can never be interpreted as markup.
	h.writeJSON(w, http.StatusOK, json.RawMessage(data))
}

func parseCustomInt(raw string, def int) (int, error) {
	if raw == "" {
		return def, nil
	}
	return strconv.Atoi(raw)
}

// listCustomTemplates handles GET /custom-templates.
func (h *Handler) listCustomTemplates(w http.ResponseWriter, r *http.Request) {
	mgr, caller, ok := h.requireTemplates(w, r)
	if !ok {
		return
	}
	templates, err := mgr.GetAccessibleTemplates(r.Context(), caller.tenant)
	if err != nil {
		h.writeCustomManagerError(w, "list_templates", err)
		return
	}
	if templates == nil {
		templates = []*interfaces.CustomReportTemplate{}
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates, "count": len(templates)})
}

// getCustomTemplate handles GET /custom-templates/{id}.
func (h *Handler) getCustomTemplate(w http.ResponseWriter, r *http.Request) {
	mgr, caller, ok := h.requireTemplates(w, r)
	if !ok {
		return
	}
	tmpl, err := mgr.GetTemplate(r.Context(), mux.Vars(r)["id"], caller.tenant)
	if err != nil {
		h.writeCustomManagerError(w, "get_template", err)
		return
	}
	h.writeJSON(w, http.StatusOK, tmpl)
}

// createCustomTemplate handles POST /custom-templates.
func (h *Handler) createCustomTemplate(w http.ResponseWriter, r *http.Request) {
	mgr, caller, ok := h.requireTemplates(w, r)
	if !ok {
		return
	}
	var tmpl interfaces.CustomReportTemplate
	if !decodeCustomBody(w, r, &tmpl) {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(tmpl.Name) == "" || len(tmpl.Query.DataSources) == 0 ||
		len(tmpl.Parameters) > interfaces.DefaultCustomReportConfig().MaxParameters {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Ownership is the caller's; the body cannot name another tenant or author, and a
	// caller cannot plant sharing state through the create body.
	tmpl.TenantID = caller.tenant
	tmpl.CreatedBy = caller.user
	tmpl.IsShared = false
	tmpl.SharedWith = nil

	saved, err := mgr.SaveTemplate(r.Context(), &tmpl)
	if err != nil {
		h.writeCustomManagerError(w, "create_template", err)
		return
	}
	h.writeJSON(w, http.StatusCreated, saved)
}

// deleteCustomTemplate handles DELETE /custom-templates/{id}.
func (h *Handler) deleteCustomTemplate(w http.ResponseWriter, r *http.Request) {
	mgr, caller, ok := h.requireTemplates(w, r)
	if !ok {
		return
	}
	if err := mgr.DeleteTemplate(r.Context(), mux.Vars(r)["id"], caller.tenant); err != nil {
		h.writeCustomManagerError(w, "delete_template", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// shareCustomTemplate handles POST /custom-templates/{id}/share. Target reachability is
// decided by the template manager's share scope, so targets pass through unchanged.
func (h *Handler) shareCustomTemplate(w http.ResponseWriter, r *http.Request) {
	mgr, caller, ok := h.requireTemplates(w, r)
	if !ok {
		return
	}
	var req interfaces.ShareTemplateRequest
	if !decodeCustomBody(w, r, &req) {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TenantID = caller.tenant
	req.SharedBy = caller.user
	req.TemplateID = mux.Vars(r)["id"]
	if len(req.SharedWithTenants) == 0 || len(req.Permissions) == 0 {
		h.writeCustomError(w, http.StatusBadRequest, "invalid request")
		return
	}
	for _, p := range req.Permissions {
		if p != "read" && p != "execute" && p != "modify" {
			h.writeCustomError(w, http.StatusBadRequest, "invalid request")
			return
		}
	}
	if err := mgr.ShareTemplate(r.Context(), req); err != nil {
		h.writeCustomManagerError(w, "share_template", err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"status": "shared"})
}
