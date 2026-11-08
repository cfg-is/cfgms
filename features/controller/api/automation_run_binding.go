// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// A run binding (ADR-036 section 3) opens a window in which an automation grant acts
// on exactly one tenant, the tenant of one triggering event. The controller cannot
// verify the PSA event itself, so begin verifies that the declared tenant lies inside
// the grant tenant's subtree and then makes the declaration immutable: the binding is
// durable, the event is bound to its first tenant, and every later call in the run is
// confined to that one tenant by requireAutomationRun.

const (
	automationRunConfigNamespace      = "automation-runs"
	automationRunEventConfigNamespace = "automation-run-events"
	automationRunArtifactNamespace    = "automation-run-artifacts"
	automationRunIDBytes              = 16
	automationRunIDHexLen             = automationRunIDBytes * 2

	// MaxAutomationRunLifetime caps how long one run may stay open.
	MaxAutomationRunLifetime = time.Hour

	// maxOpenAutomationRunsPerGrant bounds the concurrently open runs of one grant.
	maxOpenAutomationRunsPerGrant = 5

	// automationBeginRateBound is how many begin attempts one grant may make per
	// automationBeginRateWindow. Every attempt counts, accepted or refused.
	automationBeginRateBound  = 20
	automationBeginRateWindow = time.Minute

	automationEventFieldMaxLen = 128
	automationArtifactMaxLen   = 256

	// automationRequestBodyPeekLimit bounds the body the wrapper inspects for a
	// tenant that differs from the run tenant.
	automationRequestBodyPeekLimit = 1 << 20

	// automationNoTenant is a tenant id no real tenant can have (tenant ids are DNS
	// label style), so a filter built on it matches nothing.
	automationNoTenant = "\x00"
)

var (
	// ErrAutomationRunNotFound is returned for an unknown or malformed run id.
	ErrAutomationRunNotFound = errors.New("automation run not found")
	// ErrAutomationEventBound is returned when an event is already bound to a
	// different tenant.
	ErrAutomationEventBound = errors.New("automation event is bound to a different tenant")
	// ErrAutomationRunCap is returned when a grant already has the maximum number of
	// open runs.
	ErrAutomationRunCap = errors.New("automation grant has the maximum number of open runs")

	// automationEventFieldPattern is the safe charset for event_ref and event_source.
	automationEventFieldPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/#-]*$`)
	automationRunIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// RunBinding is the durable record of one run.
type RunBinding struct {
	ID            string     `json:"id"`
	GrantID       string     `json:"grant_id"`
	GrantTenantID string     `json:"grant_tenant_id"`
	TenantID      string     `json:"tenant_id"`
	EventSource   string     `json:"event_source"`
	EventRef      string     `json:"event_ref"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Ended         bool       `json:"ended"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
}

// Open reports whether the run is neither ended nor expired at now.
func (b *RunBinding) Open(now time.Time) bool {
	return !b.Ended && now.Before(b.ExpiresAt)
}

type eventBinding struct {
	GrantID     string `json:"grant_id"`
	EventSource string `json:"event_source"`
	EventRef    string `json:"event_ref"`
	TenantID    string `json:"tenant_id"`
}

type artifactRecord struct {
	RunID string `json:"run_id"`
	Kind  string `json:"kind"`
	ID    string `json:"id"`
}

// automationRunWriteMu serialises the check-then-write sequences of the run store
// within one process. The event binding is additionally created with a conditional
// write when the backend offers one, so that guarantee holds across controller nodes;
// the open-run cap is a per-process serialised check.
var automationRunWriteMu sync.Mutex

// AutomationRunStore persists run bindings, event bindings and run artifacts in the
// config store. Nothing is cached: every call reads the store, so an end or a
// revocation is seen by every controller node on its next call.
type AutomationRunStore struct {
	configs cfgconfig.ConfigStore
	now     func() time.Time
}

// NewAutomationRunStore returns a run store over the given durable config store.
func NewAutomationRunStore(configs cfgconfig.ConfigStore, now func() time.Time) (*AutomationRunStore, error) {
	if configs == nil {
		return nil, errors.New("automation run store requires a config store")
	}
	if now == nil {
		now = time.Now
	}
	return &AutomationRunStore{configs: configs, now: now}, nil
}

// automationRunStore returns the run store over the grant store's durable config
// store, or nil while no grant store is wired.
func (s *Server) automationRunStore() *AutomationRunStore {
	s.mu.RLock()
	gs := s.automationGrantStore
	s.mu.RUnlock()
	if gs == nil {
		return nil
	}
	return &AutomationRunStore{configs: gs.configs, now: gs.now}
}

func runConfigKey(grantTenant, runID string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: grantTenant, Namespace: automationRunConfigNamespace, Name: runID}
}

func hashedName(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func configMissing(err error) bool {
	return errors.Is(err, cfgconfig.ErrConfigNotFound) || isConfigNotFound(err)
}

func (s *AutomationRunStore) put(ctx context.Context, key *cfgconfig.ConfigKey, v any, createdBy string) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to encode automation record: %w", err)
	}
	if err := s.configs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedBy: createdBy, UpdatedBy: createdBy,
		Tags: []string{"automation-run"}, Source: "automation-run-store",
	}); err != nil {
		return fmt.Errorf("failed to store automation record: %w", err)
	}
	return nil
}

func decodeRun(entry *cfgconfig.ConfigEntry) (*RunBinding, error) {
	var b RunBinding
	if err := json.Unmarshal(entry.Data, &b); err != nil {
		return nil, fmt.Errorf("failed to decode automation run: %w", err)
	}
	if entry.Key == nil || b.GrantTenantID != entry.Key.TenantID || b.ID != entry.Key.Name {
		return nil, errors.New("automation run record does not match its storage key")
	}
	return &b, nil
}

// Get returns the run with the given id under the given grant tenant.
func (s *AutomationRunStore) Get(ctx context.Context, grantTenant, runID string) (*RunBinding, error) {
	if !automationRunIDPattern.MatchString(runID) {
		return nil, ErrAutomationRunNotFound
	}
	entry, err := s.configs.GetConfig(ctx, runConfigKey(grantTenant, runID))
	if err != nil {
		if configMissing(err) {
			return nil, ErrAutomationRunNotFound
		}
		return nil, fmt.Errorf("failed to read automation run: %w", err)
	}
	if entry == nil {
		return nil, ErrAutomationRunNotFound
	}
	return decodeRun(entry)
}

// findByID locates a run whose grant tenant is not known.
func (s *AutomationRunStore) findByID(ctx context.Context, runID string) (*RunBinding, error) {
	if !automationRunIDPattern.MatchString(runID) {
		return nil, ErrAutomationRunNotFound
	}
	entries, err := s.configs.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		Namespace: automationRunConfigNamespace, Names: []string{runID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look up automation run: %w", err)
	}
	for _, e := range entries {
		b, err := decodeRun(e)
		if err != nil {
			return nil, err
		}
		if b.ID == runID {
			return b, nil
		}
	}
	return nil, ErrAutomationRunNotFound
}

// listForGrant returns every run of the grant, ended or not.
func (s *AutomationRunStore) listForGrant(ctx context.Context, grantTenant, grantID string) ([]*RunBinding, error) {
	entries, err := s.configs.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		TenantID: grantTenant, Namespace: automationRunConfigNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list automation runs: %w", err)
	}
	var out []*RunBinding
	for _, e := range entries {
		b, err := decodeRun(e)
		if err != nil {
			return nil, err
		}
		if b.GrantID == grantID {
			out = append(out, b)
		}
	}
	return out, nil
}

func validateEventField(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(v) > automationEventFieldMaxLen {
		return fmt.Errorf("%s exceeds %d characters", name, automationEventFieldMaxLen)
	}
	if !automationEventFieldPattern.MatchString(v) {
		return fmt.Errorf("%s contains characters outside the allowed set", name)
	}
	return nil
}

// Begin opens a run for the grant on tenantID. The caller has already verified that
// tenantID lies inside the grant tenant's subtree. The event (grant, source, ref) is
// bound to tenantID on its first begin; a later begin for the same event on another
// tenant is refused with ErrAutomationEventBound. At most
// maxOpenAutomationRunsPerGrant runs of a grant are open at once.
func (s *AutomationRunStore) Begin(ctx context.Context, grant *AutomationGrant, tenantID, eventSource, eventRef string) (*RunBinding, error) {
	automationRunWriteMu.Lock()
	defer automationRunWriteMu.Unlock()

	now := s.now().UTC()
	evKey := &cfgconfig.ConfigKey{
		TenantID: grant.TenantID, Namespace: automationRunEventConfigNamespace,
		Name: hashedName(grant.ID, eventSource, eventRef),
	}
	bound, err := s.eventTenant(ctx, evKey)
	if err != nil {
		return nil, err
	}
	if bound != "" && bound != tenantID {
		return nil, ErrAutomationEventBound
	}
	if err := s.checkOpenRunCap(ctx, grant, now); err != nil {
		return nil, err
	}
	if bound == "" {
		if err := s.claimEvent(ctx, grant, evKey, tenantID, eventSource, eventRef); err != nil {
			return nil, err
		}
	}

	id, err := randomToken(automationRunIDBytes, hex.EncodeToString)
	if err != nil {
		return nil, err
	}
	run := &RunBinding{
		ID: id, GrantID: grant.ID, GrantTenantID: grant.TenantID, TenantID: tenantID,
		EventSource: eventSource, EventRef: eventRef,
		CreatedAt: now, ExpiresAt: now.Add(MaxAutomationRunLifetime),
	}
	if err := s.put(ctx, runConfigKey(grant.TenantID, id), run, grant.ID); err != nil {
		return nil, err
	}
	return run, nil
}

// checkOpenRunCap refuses with ErrAutomationRunCap when the grant already has the
// maximum number of open runs.
func (s *AutomationRunStore) checkOpenRunCap(ctx context.Context, grant *AutomationGrant, now time.Time) error {
	runs, err := s.listForGrant(ctx, grant.TenantID, grant.ID)
	if err != nil {
		return err
	}
	open := 0
	for _, r := range runs {
		if r.Open(now) {
			open++
		}
	}
	if open >= maxOpenAutomationRunsPerGrant {
		return ErrAutomationRunCap
	}
	return nil
}

// claimEvent binds the event to tenantID, or refuses with ErrAutomationEventBound
// when a concurrent begin bound it to another tenant first.
func (s *AutomationRunStore) claimEvent(ctx context.Context, grant *AutomationGrant, key *cfgconfig.ConfigKey, tenantID, eventSource, eventRef string) error {
	raced, err := s.bindEvent(ctx, key, &eventBinding{
		GrantID: grant.ID, EventSource: eventSource, EventRef: eventRef, TenantID: tenantID,
	}, grant.ID)
	if err != nil {
		return err
	}
	if raced != "" && raced != tenantID {
		return ErrAutomationEventBound
	}
	return nil
}

// eventTenant returns the tenant an event is bound to, or "" when it is unbound.
func (s *AutomationRunStore) eventTenant(ctx context.Context, key *cfgconfig.ConfigKey) (string, error) {
	entry, err := s.configs.GetConfig(ctx, key)
	if err != nil {
		if configMissing(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read automation event binding: %w", err)
	}
	if entry == nil {
		return "", nil
	}
	var eb eventBinding
	if err := json.Unmarshal(entry.Data, &eb); err != nil {
		return "", fmt.Errorf("failed to decode automation event binding: %w", err)
	}
	if eb.TenantID == "" {
		return "", errors.New("automation event binding has no tenant")
	}
	return eb.TenantID, nil
}

// bindEvent records the event's tenant. When the backend offers a conditional write
// the record is created only if absent, and the tenant that won a lost race is
// returned; otherwise the process-wide write lock held by the caller serialises it.
func (s *AutomationRunStore) bindEvent(ctx context.Context, key *cfgconfig.ConfigKey, eb *eventBinding, createdBy string) (string, error) {
	cas, ok := s.configs.(cfgconfig.ConditionalConfigStore)
	if !ok {
		return "", s.put(ctx, key, eb, createdBy)
	}
	data, err := json.Marshal(eb)
	if err != nil {
		return "", fmt.Errorf("failed to encode automation event binding: %w", err)
	}
	_, created, err := cas.CompareAndSwapConfig(ctx, &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedBy: createdBy, UpdatedBy: createdBy,
		Tags: []string{"automation-run"}, Source: "automation-run-store",
	}, 0)
	if err != nil {
		return "", fmt.Errorf("failed to store automation event binding: %w", err)
	}
	if created {
		return "", nil
	}
	return s.eventTenant(ctx, key)
}

// End marks the run ended. Ending an ended run keeps the original end time.
func (s *AutomationRunStore) End(ctx context.Context, grantTenant, runID string) (*RunBinding, error) {
	automationRunWriteMu.Lock()
	defer automationRunWriteMu.Unlock()
	run, err := s.Get(ctx, grantTenant, runID)
	if err != nil {
		return nil, err
	}
	return run, s.endLocked(ctx, run)
}

func (s *AutomationRunStore) endLocked(ctx context.Context, run *RunBinding) error {
	if run.Ended {
		return nil
	}
	at := s.now().UTC()
	run.Ended, run.EndedAt = true, &at
	return s.put(ctx, runConfigKey(run.GrantTenantID, run.ID), run, run.GrantID)
}

// EndRunsForGrant ends every open run of the grant and returns how many it ended.
// The revoke handler calls it so a revoked grant leaves no usable run behind.
func (s *AutomationRunStore) EndRunsForGrant(ctx context.Context, grantID string) (int, error) {
	automationRunWriteMu.Lock()
	defer automationRunWriteMu.Unlock()
	entries, err := s.configs.ListConfigs(ctx, &cfgconfig.ConfigFilter{Namespace: automationRunConfigNamespace})
	if err != nil {
		return 0, fmt.Errorf("failed to list automation runs: %w", err)
	}
	ended := 0
	for _, e := range entries {
		run, err := decodeRun(e)
		if err != nil {
			return ended, err
		}
		if run.GrantID != grantID || run.Ended {
			continue
		}
		if err := s.endLocked(ctx, run); err != nil {
			return ended, err
		}
		ended++
	}
	return ended, nil
}

func validateArtifact(kind, id string) error {
	if kind == "" || id == "" || len(kind) > automationArtifactMaxLen || len(id) > automationArtifactMaxLen {
		return errors.New("artifact kind and id are required and bounded")
	}
	return nil
}

// RecordArtifact notes that the run started the artifact (kind, id), so a later read
// can be limited to what this run started.
func (s *AutomationRunStore) RecordArtifact(ctx context.Context, runID, kind, id string) error {
	if err := validateArtifact(kind, id); err != nil {
		return err
	}
	run, err := s.findByID(ctx, runID)
	if err != nil {
		return err
	}
	return s.put(ctx, &cfgconfig.ConfigKey{
		TenantID: run.GrantTenantID, Namespace: automationRunArtifactNamespace,
		Name: hashedName(runID, kind, id),
	}, &artifactRecord{RunID: runID, Kind: kind, ID: id}, run.GrantID)
}

// HasArtifact reports whether the run recorded the artifact (kind, id). An unknown
// run has no artifacts.
func (s *AutomationRunStore) HasArtifact(ctx context.Context, runID, kind, id string) (bool, error) {
	if err := validateArtifact(kind, id); err != nil {
		return false, nil
	}
	run, err := s.findByID(ctx, runID)
	if err != nil {
		if errors.Is(err, ErrAutomationRunNotFound) {
			return false, nil
		}
		return false, err
	}
	entry, err := s.configs.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID: run.GrantTenantID, Namespace: automationRunArtifactNamespace,
		Name: hashedName(runID, kind, id),
	})
	if err != nil {
		if configMissing(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read automation artifact: %w", err)
	}
	return entry != nil, nil
}

// runTenantOnly reports whether a device's own tenant is exactly the run tenant. The
// scope types and enforceExecTenantScope are subtree-shaped (a descendant passes);
// the run lock is exactly one tenant, so a device in a descendant, an ancestor or a
// sibling tenant is refused.
func runTenantOnly(runTenant, deviceTenantID string) bool {
	return runTenant != "" && deviceTenantID == runTenant
}

// runTenantOnlyFilter builds the fleet filter that returns only devices whose own
// tenant is the run tenant: an exact tenant match with no subtree. An empty run
// tenant yields a filter that matches nothing, never an unrestricted one.
func runTenantOnlyFilter(runTenant string) fleet.Filter {
	if runTenant == "" {
		return fleet.Filter{TenantID: automationNoTenant}
	}
	return fleet.Filter{TenantID: runTenant}
}

type automationRunCtxKey struct{}

// automationRunFromContext returns the run binding requireAutomationRun admitted the
// request under.
func automationRunFromContext(ctx context.Context) *RunBinding {
	b, _ := ctx.Value(automationRunCtxKey{}).(*RunBinding)
	return b
}

func matchedRouteTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if tpl, err := route.GetPathTemplate(); err == nil {
			return tpl
		}
	}
	return ""
}

// requireAutomationRun is the enforcement wrapper of every automation route. For a
// grant principal it takes the run id from the URL path only (never a header or the
// body), loads the binding and requires it to belong to the principal's grant and to
// be open, re-reads the grant (not revoked, not expired), refuses a request that
// names another tenant in its query or body, and then REPLACES the principal in the
// request context with a copy confined to the run tenant. Handlers read the
// principal's tenant and id directly as well as the context keys, so all three views
// (principal, context tenant id, context tenant scope) are set to the run tenant.
// The begin route is the one route with no run id: it is admitted after the grant
// re-read and keeps the grant tenant for the subtree check.
func (s *Server) requireAutomationRun(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := r.Context().Value(principalContextKey).(*Principal)
		template := matchedRouteTemplate(r)
		isBegin := template == automationBeginTemplate
		presentedRun := ""
		if !isBegin {
			presentedRun = mux.Vars(r)["run_id"]
		}

		grant, runStore, ok := s.admitAutomationGrant(w, r, principal, presentedRun)
		if !ok {
			return
		}
		if isBegin {
			next.ServeHTTP(w, r)
			return
		}
		run, ok := s.admitAutomationRunBinding(w, r, principal, presentedRun, runStore)
		if !ok {
			return
		}

		scoped := *principal
		scoped.TenantID = run.TenantID
		ctx := context.WithValue(r.Context(), principalContextKey, &scoped)
		ctx = context.WithValue(ctx, ctxkeys.TenantID, run.TenantID)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(run.TenantID))
		ctx = context.WithValue(ctx, automationRunCtxKey{}, run)
		s.emitAutomationAudit(ctx, grant.ID, run.ID, run.TenantID, grant.TenantID, run.EventRef,
			"automation.call", business.AuditResultSuccess,
			auditDetail{Key: "method", Value: r.Method}, auditDetail{Key: "route", Value: template})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeAutomationUnavailable answers a store failure without disclosing it.
func (s *Server) writeAutomationUnavailable(w http.ResponseWriter, what string, err error) {
	s.logger.Error(what, "error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusServiceUnavailable,
		"Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE")
}

// admitAutomationGrant requires a grant principal and re-reads its grant (present,
// not revoked, not expired) on every call. It writes the refusal itself and returns
// ok=false when the call is not admitted.
func (s *Server) admitAutomationGrant(w http.ResponseWriter, r *http.Request, principal *Principal, presentedRun string) (*AutomationGrant, *AutomationRunStore, bool) {
	if principal == nil || principal.Channel != AuthChannelAutomationGrant {
		s.refuseAutomationCall(w, r, principal, presentedRun, nil, "not_a_grant_principal")
		return nil, nil, false
	}
	grantStore, runStore := s.grantStoreOrNil(), s.automationRunStore()
	if grantStore == nil || runStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Authorization data is temporarily unavailable", "SERVICE_UNAVAILABLE")
		return nil, nil, false
	}
	grant, err := grantStore.Get(r.Context(), principal.TenantID, principal.ID)
	if err != nil {
		if !errors.Is(err, ErrGrantNotFound) {
			s.writeAutomationUnavailable(w, "Automation grant re-read failed", err)
			return nil, nil, false
		}
		s.refuseAutomationCall(w, r, principal, presentedRun, nil, "grant_not_found")
		return nil, nil, false
	}
	if reason := grantRefusalReason(grant, grantStore.now()); reason != "" {
		s.refuseAutomationCall(w, r, principal, presentedRun, nil, reason)
		return nil, nil, false
	}
	return grant, runStore, true
}

func grantRefusalReason(grant *AutomationGrant, now time.Time) string {
	switch {
	case grant.Revoked():
		return "grant_revoked"
	case !now.Before(grant.ExpiresAt):
		return "grant_expired"
	}
	return ""
}

// admitAutomationRunBinding loads the run named in the URL path and requires it to
// belong to the principal's grant, to be open, and not to be contradicted by a tenant
// named in the request. It writes the refusal itself and returns ok=false when the
// call is not admitted.
func (s *Server) admitAutomationRunBinding(w http.ResponseWriter, r *http.Request, principal *Principal, presentedRun string, runStore *AutomationRunStore) (*RunBinding, bool) {
	run, err := runStore.Get(r.Context(), principal.TenantID, presentedRun)
	if err != nil {
		if !errors.Is(err, ErrAutomationRunNotFound) {
			s.writeAutomationUnavailable(w, "Automation run lookup failed", err)
			return nil, false
		}
		s.refuseAutomationCall(w, r, principal, presentedRun, nil, "run_not_found")
		return nil, false
	}
	reason := ""
	switch {
	case run.GrantID != principal.ID:
		// The run is passed as nil so another grant's tenant and event ref stay out
		// of this grant's audit record.
		s.refuseAutomationCall(w, r, principal, presentedRun, nil, "run_belongs_to_another_grant")
		return nil, false
	case run.Ended:
		reason = "run_ended"
	case !runStore.now().Before(run.ExpiresAt):
		reason = "run_expired"
	default:
		reason = s.conflictingTenantReason(r, run.TenantID)
	}
	if reason != "" {
		s.refuseAutomationCall(w, r, principal, presentedRun, run, reason)
		return nil, false
	}
	return run, true
}

func (s *Server) grantStoreOrNil() *AutomationGrantStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.automationGrantStore
}

// refuseAutomationCall audits the refusal under the presented run id (never the
// credential) and answers one uniform 403 so the response does not say which check
// failed.
func (s *Server) refuseAutomationCall(w http.ResponseWriter, r *http.Request, principal *Principal, presentedRun string, run *RunBinding, reason string) {
	grantID, owner, tenant, eventRef, runID := "", "", "", "", presentedRun
	if principal != nil {
		grantID, owner, tenant = principal.ID, principal.TenantID, principal.TenantID
	}
	if run != nil {
		tenant, eventRef, runID = run.TenantID, run.EventRef, run.ID
	}
	s.emitAutomationAudit(r.Context(), grantID, runID, tenant, owner, eventRef,
		"automation.call", business.AuditResultDenied,
		auditDetail{Key: "reason", Value: reason},
		auditDetail{Key: "method", Value: r.Method},
		auditDetail{Key: "route", Value: matchedRouteTemplate(r)})
	s.writeErrorResponse(w, http.StatusForbidden,
		"The automation run does not permit this request", "AUTOMATION_RUN_DENIED")
}

// tenantNamingKeys are the request fields that name a tenant, in the query string
// and in a JSON object body.
var tenantNamingKeys = []string{"tenant_id", "tenant"}

// conflictingTenantReason returns a non-empty reason when the query or the JSON body
// names a tenant other than the run tenant.
func (s *Server) conflictingTenantReason(r *http.Request, runTenant string) string {
	q := r.URL.Query()
	for _, k := range tenantNamingKeys {
		for _, v := range q[k] {
			if v != runTenant {
				return "query_names_another_tenant"
			}
		}
	}
	return bodyTenantReason(r, runTenant)
}

// bodyTenantReason inspects a JSON object body for a tenant other than the run
// tenant. A body that cannot be read in full within the peek limit is refused; the
// body is restored for the handler otherwise.
func bodyTenantReason(r *http.Request, runTenant string) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, automationRequestBodyPeekLimit+1))
	_ = r.Body.Close()
	if err != nil || len(raw) > automationRequestBodyPeekLimit {
		return "body_unreadable"
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		// Empty or not a JSON object: nothing names a tenant here, and the
		// handler's own decoding refuses a malformed body.
		return ""
	}
	for k, v := range obj {
		var name string
		if isTenantNamingKey(k) && (json.Unmarshal(v, &name) != nil || name != runTenant) {
			return "body_names_another_tenant"
		}
	}
	return ""
}

// isTenantNamingKey matches the tenant keys case-insensitively, since the standard
// JSON decoder binds object keys to struct fields that way.
func isTenantNamingKey(k string) bool {
	for _, t := range tenantNamingKeys {
		if strings.EqualFold(k, t) {
			return true
		}
	}
	return false
}

// admitAutomationBegin counts one begin attempt for the grant in the current fixed
// window and reports whether it is within bound. With a cluster-visible
// rateCounterStore the count is shared across nodes and a capacity-exhausted store
// denies (fail closed); otherwise a node-local counter holds the bound.
func (s *Server) admitAutomationBegin(ctx context.Context, grantID string) bool {
	if s.rateCounterStore != nil {
		count, _, err := s.rateCounterStore.Increment(ctx, automationBeginRateKeyPrefix+grantID, automationBeginRateWindow)
		if err == nil {
			return count <= automationBeginRateBound
		}
		if errors.Is(err, business.ErrRateCounterCapacityExhausted) {
			return false
		}
		s.logger.Warn("Automation begin rate: shared counter unavailable; using node-local counter",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	raw, _ := automationBeginLocalCounters.LoadOrStore(grantID, &automationBeginRecord{})
	rec := raw.(*automationBeginRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	now := time.Now()
	if rec.start.IsZero() || now.Sub(rec.start) >= automationBeginRateWindow {
		rec.start, rec.count = now, 0
	}
	rec.count++
	return rec.count <= automationBeginRateBound
}

const automationBeginRateKeyPrefix = "automation-run-begin:grant:"

type automationBeginRecord struct {
	mu    sync.Mutex
	start time.Time
	count int
}

var automationBeginLocalCounters sync.Map
