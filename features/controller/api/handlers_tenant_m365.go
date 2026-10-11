// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// M365 connections (Issue #4551).
//
// An M365 connection is the auth.OAuth2Config stored for a CFGMS client tenant
// (SecretStoreCredentialStore.StoreConfig). The rule every handler here enforces:
// a connection exists only ON an existing client tenant, an existing tenant whose
// parent is an MSP tenant (a direct child of the deployment root). Nothing here
// creates a tenant, an account or any record keyed by anything else; the only
// writes are StoreConfig / DeleteConfig / DeleteToken on a client tenant's ID.

const (
	m365MaxBodyBytes  = 64 * 1024
	m365MaxLinks      = 200
	m365MaxIDLen      = 128
	m365MaxSecretLen  = 512
	m365MaxRoleLen    = 128
	m365MaxRoles      = 64
	m365ModeDirect    = "direct"
	m365ModePartner   = "partner"
	m365LinkUnlinked  = "unlinked"
	m365ActionSet     = "m365.connection.set"
	m365ActionDelete  = "m365.connection.delete"
	m365ActionGDAPLnk = "m365.gdap.link"
)

// m365PartnerEndpoints overrides the Partner Center and Microsoft login base URLs
// (sovereign clouds, tests). Empty values keep the resolver defaults.
var m365PartnerEndpoints = struct{ partnerCenterBaseURL, loginBaseURL string }{}

// m365WriteMu serializes connection writes within this process so the
// check-then-write validation of a request cannot interleave with another write.
var m365WriteMu sync.Mutex

var m365IDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// m365DirectRequest is the body of PUT /tenants/{id}/m365-connection.
type m365DirectRequest struct {
	AppID        string `json:"app_id"`
	M365TenantID string `json:"m365_tenant_id"`
	ClientSecret string `json:"client_secret"`
	Replace      bool   `json:"replace"`
}

// m365PartnerCreds are the Partner Center app credentials supplied on each GDAP call.
type m365PartnerCreds struct {
	PartnerTenantID string `json:"partner_tenant_id"`
	AppID           string `json:"app_id"`
	ClientSecret    string `json:"client_secret"`
}

type m365GDAPLink struct {
	CustomerTenantID string `json:"customer_tenant_id"`
	TenantID         string `json:"tenant_id"`
}

type m365GDAPLinkRequest struct {
	m365PartnerCreds
	Links     []m365GDAPLink `json:"links"`
	GDAPRoles []string       `json:"gdap_roles"`
	Replace   bool           `json:"replace"`
}

// m365ConnectionView is the secret-free description of a stored connection.
type m365ConnectionView struct {
	TenantID        string   `json:"tenant_id"`
	Mode            string   `json:"mode"`
	AppID           string   `json:"app_id"`
	M365TenantID    string   `json:"m365_tenant_id"`
	PartnerTenantID string   `json:"partner_tenant_id,omitempty"`
	GDAPRoles       []string `json:"gdap_roles,omitempty"`
	HasClientSecret bool     `json:"has_client_secret"`
}

type m365GDAPCustomerRow struct {
	CustomerTenantID string    `json:"customer_tenant_id"`
	Name             string    `json:"name"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at"`
	Roles            []string  `json:"roles"`
	LinkState        string    `json:"link_state"`
	LinkedTo         string    `json:"linked_to,omitempty"`
}

func m365View(tenantID string, cfg *auth.OAuth2Config) m365ConnectionView {
	v := m365ConnectionView{
		TenantID:        tenantID,
		Mode:            m365ModeDirect,
		AppID:           cfg.ClientID,
		M365TenantID:    cfg.TenantID,
		HasClientSecret: cfg.ClientSecret != "",
	}
	if cfg.PartnerDelegated {
		v.Mode = m365ModePartner
		v.M365TenantID = cfg.CustomerTenantID
		v.PartnerTenantID = cfg.PartnerTenantID
		v.GDAPRoles = cfg.GDAPRequiredRoles
	}
	return v
}

// m365LinkedCustomer returns the M365 tenant a stored config names: the customer for a
// partner config, the directory tenant for a direct one.
func m365LinkedCustomer(cfg *auth.OAuth2Config) string {
	if cfg.PartnerDelegated {
		return cfg.CustomerTenantID
	}
	return cfg.TenantID
}

func validM365ID(v string) bool {
	// An ID of only dots ("." / "..") would alter the Partner Center token URL path.
	return len(v) <= m365MaxIDLen && m365IDPattern.MatchString(v) && strings.Trim(v, ".") != ""
}

func validM365Secret(v string) bool {
	if v == "" || len(v) > m365MaxSecretLen {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func validM365Roles(roles []string) bool {
	if len(roles) > m365MaxRoles {
		return false
	}
	for _, r := range roles {
		if r == "" || len(r) > m365MaxRoleLen || !m365IDPattern.MatchString(r) {
			return false
		}
	}
	return true
}

// m365Store returns the credential store over the server's secret store, or writes 503
// and returns false when no secret store is configured. It is the first check of every
// M365 route.
func (s *Server) m365Store(w http.ResponseWriter) (*auth.SecretStoreCredentialStore, bool) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "secret store not available", "SECRET_STORE_UNAVAILABLE")
		return nil, false
	}
	return auth.NewSecretStoreCredentialStore(s.secretStore), true
}

func (s *Server) m365DecodeBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, m365MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return false
	}
	return true
}

// m365Tenant authorizes the caller for tenantID and loads it. It writes the response and
// returns nil when the tenant is missing, outside the caller's scope (404) or needs a
// crossing (the challenge).
func (s *Server) m365Tenant(w http.ResponseWriter, r *http.Request, tenantID string) *business.TenantData {
	td, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return nil
		}
		s.logger.Error("Failed to load tenant for M365 route",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return nil
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	switch s.authorizeTenantAccess(r.Context(), principal, td.ID) {
	case tenantAuthAllowed:
		return td
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, td.ID)
	default:
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
	}
	return nil
}

// m365IsMSP reports whether td is a direct child of the deployment root.
func (s *Server) m365IsMSP(ctx context.Context, td *business.TenantData) bool {
	root := s.rootTenantID(ctx)
	return root != "" && td.ID != root && td.ParentID == root
}

// m365ClientTenantMSP reports whether td is a client tenant, and returns its MSP.
func (s *Server) m365ClientTenantMSP(ctx context.Context, td *business.TenantData) (string, bool) {
	root := s.rootTenantID(ctx)
	if root == "" || td.ID == root || td.ParentID == "" || td.ParentID == root {
		return "", false
	}
	parent, err := s.tenantManager.GetTenant(ctx, td.ParentID)
	if err != nil || !s.m365IsMSP(ctx, parent) {
		return "", false
	}
	return parent.ID, true
}

// m365ClientTenant resolves the {id} tenant and requires it to be a client tenant.
func (s *Server) m365ClientTenant(w http.ResponseWriter, r *http.Request) *business.TenantData {
	td := s.m365Tenant(w, r, mux.Vars(r)["id"])
	if td == nil {
		return nil
	}
	if _, ok := s.m365ClientTenantMSP(r.Context(), td); !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"an M365 connection can only be set on a client tenant of an MSP", "M365_NOT_CLIENT_TENANT")
		return nil
	}
	return td
}

// m365MSPTenant resolves the {id} tenant and requires it to be an MSP tenant.
func (s *Server) m365MSPTenant(w http.ResponseWriter, r *http.Request) *business.TenantData {
	td := s.m365Tenant(w, r, mux.Vars(r)["id"])
	if td == nil {
		return nil
	}
	if !s.m365IsMSP(r.Context(), td) {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant is not an MSP tenant", "M365_NOT_MSP_TENANT")
		return nil
	}
	return td
}

func (s *Server) m365Audit(r *http.Request, tenantID, action string, details map[string]interface{}) {
	if s.auditManager == nil {
		return
	}
	var actorID string
	if p, _ := r.Context().Value(principalContextKey).(*Principal); p != nil {
		actorID = p.ID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant", tenantID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(details)
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record M365 audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"action", action,
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

func (s *Server) m365Internal(w http.ResponseWriter, msg, tenantID string, err error) {
	s.logger.Error(msg,
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, msg, "M365_STORE_FAILED")
}

// m365GetConfig reads a stored config; (nil, nil) means none.
func m365GetConfig(cs *auth.SecretStoreCredentialStore, tenantID string) (*auth.OAuth2Config, error) {
	cfg, err := cs.GetConfig(tenantID)
	if err != nil {
		if errors.Is(err, secretsif.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return cfg, nil
}

// handlePutTenantM365Connection implements PUT /api/v1/tenants/{id}/m365-connection.
func (s *Server) handlePutTenantM365Connection(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.m365Store(w)
	if !ok {
		return
	}
	td := s.m365ClientTenant(w, r)
	if td == nil {
		return
	}
	var req m365DirectRequest
	if !s.m365DecodeBody(w, r, &req) {
		return
	}
	switch {
	case !validM365ID(req.AppID):
		s.writeErrorResponse(w, http.StatusBadRequest, "app_id is required and must be a valid identifier", "INVALID_APP_ID")
		return
	case !validM365ID(req.M365TenantID):
		s.writeErrorResponse(w, http.StatusBadRequest, "m365_tenant_id is required and must be a valid identifier", "INVALID_M365_TENANT_ID")
		return
	case !validM365Secret(req.ClientSecret):
		s.writeErrorResponse(w, http.StatusBadRequest, "client_secret is required", "INVALID_CLIENT_SECRET")
		return
	}

	m365WriteMu.Lock()
	defer m365WriteMu.Unlock()
	existing, err := m365GetConfig(cs, td.ID)
	if err != nil {
		s.m365Internal(w, "failed to read existing connection", td.ID, err)
		return
	}
	if existing != nil && !req.Replace {
		s.writeErrorResponse(w, http.StatusConflict,
			"tenant already has an M365 connection; set replace to overwrite it", "M365_CONNECTION_EXISTS")
		return
	}
	cfg := &auth.OAuth2Config{
		ClientID:             req.AppID,
		ClientSecret:         req.ClientSecret,
		TenantID:             req.M365TenantID,
		UseClientCredentials: true,
	}
	if err := cs.StoreConfig(td.ID, cfg); err != nil {
		s.m365Internal(w, "failed to store connection", td.ID, err)
		return
	}
	if existing != nil {
		// A token minted from the replaced credentials must not be served.
		if err := cs.DeleteToken(td.ID); err != nil {
			s.logger.Warn("Failed to drop token after M365 connection replace",
				"tenant_id", logging.SanitizeLogValue(td.ID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
	s.m365Audit(r, td.ID, m365ActionSet, map[string]interface{}{
		"mode": m365ModeDirect, "app_id": req.AppID, "m365_tenant_id": req.M365TenantID, "replaced": existing != nil,
	})
	s.writeSuccessResponse(w, m365View(td.ID, cfg))
}

// handleGetTenantM365Connection implements GET /api/v1/tenants/{id}/m365-connection.
func (s *Server) handleGetTenantM365Connection(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.m365Store(w)
	if !ok {
		return
	}
	td := s.m365ClientTenant(w, r)
	if td == nil {
		return
	}
	cfg, err := m365GetConfig(cs, td.ID)
	if err != nil {
		s.m365Internal(w, "failed to read connection", td.ID, err)
		return
	}
	if cfg == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "tenant has no M365 connection", "M365_CONNECTION_NOT_FOUND")
		return
	}
	s.writeSuccessResponse(w, m365View(td.ID, cfg))
}

// handleDeleteTenantM365Connection implements DELETE /api/v1/tenants/{id}/m365-connection.
func (s *Server) handleDeleteTenantM365Connection(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.m365Store(w)
	if !ok {
		return
	}
	td := s.m365ClientTenant(w, r)
	if td == nil {
		return
	}
	m365WriteMu.Lock()
	defer m365WriteMu.Unlock()
	cfg, err := m365GetConfig(cs, td.ID)
	if err != nil {
		s.m365Internal(w, "failed to read connection", td.ID, err)
		return
	}
	if cfg == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "tenant has no M365 connection", "M365_CONNECTION_NOT_FOUND")
		return
	}
	if err := cs.DeleteConfig(td.ID); err != nil {
		s.m365Internal(w, "failed to delete connection", td.ID, err)
		return
	}
	view := m365View(td.ID, cfg)
	s.m365Audit(r, td.ID, m365ActionDelete, map[string]interface{}{
		"mode": view.Mode, "app_id": view.AppID, "m365_tenant_id": view.M365TenantID,
	})
	s.writeSuccessResponse(w, map[string]interface{}{"tenant_id": td.ID, "deleted": true})
}

// m365DiscoverCustomers lists the partner's active GDAP customers using only the
// supplied credentials; the Partner Center token is held in memory and nothing is
// persisted.
func (s *Server) m365DiscoverCustomers(ctx context.Context, c m365PartnerCreds) ([]auth.GDAPRelationship, error) {
	resolver := auth.NewGDAPRelationshipResolver(nil, c.PartnerTenantID)
	resolver.SetEndpoints(m365PartnerEndpoints.partnerCenterBaseURL, m365PartnerEndpoints.loginBaseURL)
	resolver.SetClientCredentials(c.AppID, c.ClientSecret)
	return resolver.DiscoverGDAPCustomers(ctx)
}

func (c m365PartnerCreds) validate() (field, code string) {
	switch {
	case !validM365ID(c.PartnerTenantID):
		return "partner_tenant_id", "INVALID_PARTNER_TENANT_ID"
	case !validM365ID(c.AppID):
		return "app_id", "INVALID_APP_ID"
	case !validM365Secret(c.ClientSecret):
		return "client_secret", "INVALID_CLIENT_SECRET"
	}
	return "", ""
}

// m365MSPClientConfigs returns the stored config of every direct child of the MSP that
// has one, keyed by client tenant ID.
func (s *Server) m365MSPClientConfigs(ctx context.Context, cs *auth.SecretStoreCredentialStore, mspID string) (map[string]*auth.OAuth2Config, error) {
	children, err := s.tenantManager.ListTenants(ctx, &business.TenantFilter{ParentID: mspID})
	if err != nil {
		return nil, err
	}
	out := make(map[string]*auth.OAuth2Config)
	for _, c := range children {
		if c.ParentID != mspID {
			continue
		}
		cfg, err := m365GetConfig(cs, c.ID)
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			out[c.ID] = cfg
		}
	}
	return out, nil
}

// handleM365GDAPCustomers implements POST /api/v1/tenants/{id}/m365-gdap-customers.
func (s *Server) handleM365GDAPCustomers(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.m365Store(w)
	if !ok {
		return
	}
	msp := s.m365MSPTenant(w, r)
	if msp == nil {
		return
	}
	var req m365PartnerCreds
	if !s.m365DecodeBody(w, r, &req) {
		return
	}
	if field, code := req.validate(); field != "" {
		s.writeErrorResponse(w, http.StatusBadRequest, field+" is missing or invalid", code)
		return
	}
	rels, err := s.m365DiscoverCustomers(r.Context(), req)
	if err != nil {
		s.logger.Warn("Partner Center customer discovery failed",
			"tenant_id", logging.SanitizeLogValue(msp.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadGateway, "failed to list GDAP customers from Partner Center", "M365_PARTNER_CENTER_FAILED")
		return
	}
	configs, err := s.m365MSPClientConfigs(r.Context(), cs, msp.ID)
	if err != nil {
		s.m365Internal(w, "failed to read client connections", msp.ID, err)
		return
	}
	linkedTo := make(map[string]string)
	for id, cfg := range configs {
		if cust := m365LinkedCustomer(cfg); cust != "" {
			if prev, dup := linkedTo[cust]; !dup || id < prev {
				linkedTo[cust] = id
			}
		}
	}
	rows := make([]m365GDAPCustomerRow, 0, len(rels))
	for _, rel := range rels {
		roles := make([]string, 0, len(rel.Roles))
		for _, role := range rel.Roles {
			roles = append(roles, role.RoleName)
		}
		row := m365GDAPCustomerRow{
			CustomerTenantID: rel.CustomerTenantID,
			Name:             rel.CustomerName,
			Status:           string(rel.Status),
			ExpiresAt:        rel.ExpiresAt,
			Roles:            roles,
			LinkState:        m365LinkUnlinked,
		}
		if id, linked := linkedTo[rel.CustomerTenantID]; linked {
			row.LinkState, row.LinkedTo = "linked", id
		}
		rows = append(rows, row)
	}
	s.writeSuccessResponse(w, map[string]interface{}{"msp_tenant_id": msp.ID, "customers": rows})
}

// m365LinkPlan is one validated link: the target's previous config (nil when none).
type m365LinkPlan struct {
	link m365GDAPLink
	prev *auth.OAuth2Config
}

// handleM365GDAPLinks implements POST /api/v1/tenants/{id}/m365-gdap-links. The request
// is validated as a whole before anything is written.
func (s *Server) handleM365GDAPLinks(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.m365Store(w)
	if !ok {
		return
	}
	msp := s.m365MSPTenant(w, r)
	if msp == nil {
		return
	}
	var req m365GDAPLinkRequest
	if !s.m365DecodeBody(w, r, &req) {
		return
	}
	if field, code := req.validate(); field != "" {
		s.writeErrorResponse(w, http.StatusBadRequest, field+" is missing or invalid", code)
		return
	}
	if len(req.Links) == 0 || len(req.Links) > m365MaxLinks {
		s.writeErrorResponse(w, http.StatusBadRequest, "links must hold between 1 and 200 entries", "INVALID_LINKS")
		return
	}
	if !validM365Roles(req.GDAPRoles) {
		s.writeErrorResponse(w, http.StatusBadRequest, "gdap_roles contains an invalid role", "INVALID_GDAP_ROLES")
		return
	}
	fail := func(status int, i int, msg, code string) {
		s.writeErrorResponse(w, status, fmt.Sprintf("links[%d]: %s", i, msg), code)
	}

	seenCust := map[string]bool{}
	seenTarget := map[string]bool{}
	for i, l := range req.Links {
		if !validM365ID(l.CustomerTenantID) || l.TenantID == "" {
			fail(http.StatusBadRequest, i, "customer_tenant_id and tenant_id are required", "INVALID_LINK")
			return
		}
		if seenCust[l.CustomerTenantID] {
			fail(http.StatusBadRequest, i, "duplicate customer_tenant_id", "M365_DUPLICATE_CUSTOMER")
			return
		}
		if seenTarget[l.TenantID] {
			fail(http.StatusBadRequest, i, "duplicate tenant_id", "M365_DUPLICATE_TARGET")
			return
		}
		seenCust[l.CustomerTenantID], seenTarget[l.TenantID] = true, true
	}

	// Every target must be an existing client tenant of this MSP that the caller may reach.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	for i, l := range req.Links {
		td, err := s.tenantManager.GetTenant(r.Context(), l.TenantID)
		if err != nil {
			if errors.Is(err, business.ErrTenantDoesNotExist) {
				fail(http.StatusNotFound, i, "tenant not found", "TENANT_NOT_FOUND")
				return
			}
			s.m365Internal(w, "failed to get tenant", msp.ID, err)
			return
		}
		switch s.authorizeTenantAccess(r.Context(), principal, td.ID) {
		case tenantAuthAllowed:
		case tenantAuthNeedsCrossing:
			s.writeTenantCrossingChallenge(w, td.ID)
			return
		default:
			fail(http.StatusNotFound, i, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		if mspID, isClient := s.m365ClientTenantMSP(r.Context(), td); !isClient || mspID != msp.ID {
			fail(http.StatusBadRequest, i, "tenant is not a client tenant of the named MSP", "M365_NOT_CLIENT_TENANT")
			return
		}
	}

	rels, err := s.m365DiscoverCustomers(r.Context(), req.m365PartnerCreds)
	if err != nil {
		s.logger.Warn("Partner Center customer discovery failed",
			"tenant_id", logging.SanitizeLogValue(msp.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadGateway, "failed to list GDAP customers from Partner Center", "M365_PARTNER_CENTER_FAILED")
		return
	}
	active := map[string]bool{}
	for _, rel := range rels {
		active[rel.CustomerTenantID] = true
	}
	for i, l := range req.Links {
		if !active[l.CustomerTenantID] {
			fail(http.StatusBadRequest, i, "customer is not in the partner's active GDAP list", "M365_CUSTOMER_NOT_IN_GDAP")
			return
		}
	}

	m365WriteMu.Lock()
	defer m365WriteMu.Unlock()
	configs, err := s.m365MSPClientConfigs(r.Context(), cs, msp.ID)
	if err != nil {
		s.m365Internal(w, "failed to read client connections", msp.ID, err)
		return
	}
	plans := make([]m365LinkPlan, 0, len(req.Links))
	for i, l := range req.Links {
		for id, cfg := range configs {
			if id != l.TenantID && m365LinkedCustomer(cfg) == l.CustomerTenantID {
				fail(http.StatusConflict, i, "customer is already linked to a different client tenant", "M365_CUSTOMER_ALREADY_LINKED")
				return
			}
		}
		prev := configs[l.TenantID]
		if prev != nil && !req.Replace {
			fail(http.StatusConflict, i, "tenant already has an M365 connection; set replace to overwrite it", "M365_CONNECTION_EXISTS")
			return
		}
		plans = append(plans, m365LinkPlan{link: l, prev: prev})
	}

	written := make([]m365LinkPlan, 0, len(plans))
	for _, p := range plans {
		cfg := &auth.OAuth2Config{
			ClientID:          req.AppID,
			ClientSecret:      req.ClientSecret,
			TenantID:          p.link.CustomerTenantID,
			PartnerDelegated:  true,
			PartnerTenantID:   req.PartnerTenantID,
			CustomerTenantID:  p.link.CustomerTenantID,
			GDAPRequiredRoles: req.GDAPRoles,
		}
		if err := cs.StoreConfig(p.link.TenantID, cfg); err != nil {
			s.m365Rollback(cs, written)
			s.m365Internal(w, "failed to store connection", p.link.TenantID, err)
			return
		}
		written = append(written, p)
		if p.prev != nil {
			if err := cs.DeleteToken(p.link.TenantID); err != nil {
				s.logger.Warn("Failed to drop token after M365 link replace",
					"tenant_id", logging.SanitizeLogValue(p.link.TenantID),
					"error", logging.SanitizeLogValue(err.Error()))
			}
		}
	}

	linked := make([]m365GDAPLink, 0, len(plans))
	for _, p := range plans {
		s.m365Audit(r, p.link.TenantID, m365ActionGDAPLnk, map[string]interface{}{
			"mode": m365ModePartner, "app_id": req.AppID, "partner_tenant_id": req.PartnerTenantID,
			"m365_tenant_id": p.link.CustomerTenantID, "msp_tenant_id": msp.ID, "replaced": p.prev != nil,
		})
		linked = append(linked, p.link)
	}
	sort.Slice(linked, func(i, j int) bool { return linked[i].TenantID < linked[j].TenantID })
	s.writeSuccessResponse(w, map[string]interface{}{"msp_tenant_id": msp.ID, "linked": linked})
}

// m365Rollback restores the previous state of configs written earlier in a failed batch.
func (s *Server) m365Rollback(cs *auth.SecretStoreCredentialStore, written []m365LinkPlan) {
	for _, p := range written {
		var err error
		if p.prev != nil {
			err = cs.StoreConfig(p.link.TenantID, p.prev)
		} else {
			err = cs.DeleteConfig(p.link.TenantID)
		}
		if err != nil {
			s.logger.Error("Failed to roll back M365 link",
				"tenant_id", logging.SanitizeLogValue(p.link.TenantID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
	}
}
