// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Billing reports (ADR-025 Amendment 6, A6.1-A6.3). Both endpoints are projections of
// the one aggregation, aggregateBilling; neither handler reads a store itself. Responses
// are built from dedicated structs so a field added to the aggregation cannot reach a
// response by accident.

// billingOwnCounts is an MSP's own (non-client) tech and endpoint counts.
type billingOwnCounts struct {
	TechCount     int `json:"tech_count"`
	EndpointCount int `json:"endpoint_count"`
}

// rootBillingClient is one client as root sees it: an opaque label and sizes. It has no
// name or ID field by construction.
type rootBillingClient struct {
	Label         string `json:"label"`
	EndpointCount int    `json:"endpoint_count"`
	TechCount     int    `json:"tech_count"`
}

// rootBillingMSP is one MSP row of the root billing report.
type rootBillingMSP struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	TechCount     int                 `json:"tech_count"`
	EndpointCount int                 `json:"endpoint_count"`
	ClientCount   int                 `json:"client_count"`
	Metrics       billingMetrics      `json:"metrics"`
	MSPOwn        billingOwnCounts    `json:"msp_own"`
	Clients       []rootBillingClient `json:"clients"`
}

// rootBillingReport is the GET /api/v1/billing/report response.
type rootBillingReport struct {
	MSPs []rootBillingMSP `json:"msps"`
}

// tenantBillingClient is one client as its own MSP sees it.
type tenantBillingClient struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	EndpointCount int    `json:"endpoint_count"`
	TechCount     int    `json:"tech_count"`
}

// tenantBillingReport is the GET /api/v1/tenants/{id}/billing-report response.
type tenantBillingReport struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	TechCount     int                   `json:"tech_count"`
	EndpointCount int                   `json:"endpoint_count"`
	ClientCount   int                   `json:"client_count"`
	Metrics       billingMetrics        `json:"metrics"`
	MSPOwn        billingOwnCounts      `json:"msp_own"`
	Clients       []tenantBillingClient `json:"clients"`
}

// canReadRootBilling reports whether principal may reach the root billing report: a
// root-scoped principal, a principal bound to the root tenant, or an unscoped
// certificate-authenticated principal. This is a gate only; tenant:billing-read is
// enforced separately by requirePermission, and a certificate authenticates without
// authorizing (ADR-025 Amendment 3).
func (s *Server) canReadRootBilling(r *http.Request, principal *Principal) bool {
	if principal == nil {
		return false
	}
	if subjectToTenantCrossingBoundary(principal) {
		return true
	}
	// A principal bound to the root tenant is already an ancestor of every tenant in
	// authorizeTenantAccess, so this admits no one that rule does not.
	if root := s.rootTenantID(r.Context()); root != "" && principal.TenantID == root {
		return true
	}
	return principal.TenantID == "" && principal.CertSerial != ""
}

// handleRootBillingReport implements GET /api/v1/billing/report. It lists every direct
// child of the root tenant (an MSP) with its sizes and metrics, and each MSP's clients
// under their stored opaque labels. Root's visibility is standing and disclosed (A6.3),
// so a read is not individually audited.
func (s *Server) handleRootBillingReport(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if !s.canReadRootBilling(r, principal) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"the cross-MSP billing report is available to the root operator only", "BILLING_ROOT_ONLY")
		return
	}
	rootID := s.rootTenantID(r.Context())
	if rootID == "" {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "root tenant unavailable", "ROOT_TENANT_UNAVAILABLE")
		return
	}
	top, err := s.aggregateBilling(r.Context(), rootID)
	if err != nil {
		s.writeBillingError(w, err)
		return
	}
	report := rootBillingReport{MSPs: make([]rootBillingMSP, 0, len(top.Clients))}
	for _, msp := range top.Clients {
		agg, err := s.aggregateBilling(r.Context(), msp.ID)
		if err != nil {
			s.writeBillingError(w, err)
			return
		}
		row := rootBillingMSP{
			ID: msp.ID, Name: msp.Name,
			TechCount: agg.TechCount, EndpointCount: agg.EndpointCount, ClientCount: agg.ClientCount,
			Metrics: agg.Metrics,
			MSPOwn:  billingOwnCounts{TechCount: agg.MSPOwn.Techs, EndpointCount: agg.MSPOwn.Endpoints},
			Clients: make([]rootBillingClient, 0, len(agg.Clients)),
		}
		for _, c := range agg.Clients {
			row.Clients = append(row.Clients, rootBillingClient{
				Label: c.BillingLabel, EndpointCount: c.Endpoints, TechCount: c.Techs,
			})
		}
		report.MSPs = append(report.MSPs, row)
	}
	s.writeSuccessResponse(w, report)
}

// handleTenantBillingReport implements GET /api/v1/tenants/{id}/billing-report: the same
// aggregation scoped to {id}'s subtree, with real client names and IDs.
func (s *Server) handleTenantBillingReport(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	switch s.authorizeTenantAccess(r.Context(), principal, tenantID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, tenantID)
		return
	default:
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}
	agg, err := s.aggregateBilling(r.Context(), tenantID)
	if err != nil {
		s.writeBillingError(w, err)
		return
	}
	name := ""
	if td, gerr := s.tenantManager.GetTenant(r.Context(), tenantID); gerr == nil {
		name = td.Name
	} else {
		s.logger.Warn("Billing report tenant name lookup failed",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(gerr.Error()))
	}
	report := tenantBillingReport{
		ID: tenantID, Name: name,
		TechCount: agg.TechCount, EndpointCount: agg.EndpointCount, ClientCount: agg.ClientCount,
		Metrics: agg.Metrics,
		MSPOwn:  billingOwnCounts{TechCount: agg.MSPOwn.Techs, EndpointCount: agg.MSPOwn.Endpoints},
		Clients: make([]tenantBillingClient, 0, len(agg.Clients)),
	}
	for _, c := range agg.Clients {
		report.Clients = append(report.Clients, tenantBillingClient{
			ID: c.ID, Name: c.Name, EndpointCount: c.Endpoints, TechCount: c.Techs,
		})
	}
	s.writeSuccessResponse(w, report)
}

// writeBillingError maps an aggregation error to a response. The cause is logged
// sanitized and never echoed.
func (s *Server) writeBillingError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBillingTenantNotFound) {
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}
	s.logger.Error("Billing aggregation failed", "error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, "failed to build billing report", "BILLING_REPORT_FAILED")
}
