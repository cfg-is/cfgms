// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/moduleset"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	dirif "github.com/cfgis/cfgms/pkg/directory/interfaces"
	egif "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// M365UserModule and M365GroupModule are the controller-kind modules the
	// convergence loop drives.
	M365UserModule  = "m365-entra-user"
	M365GroupModule = "m365-entra-group"

	m365BindingNamespace  = "m365-converge-bindings"
	m365ConvergeNamespace = "m365-converge-status"
	m365ConvergeCreatedBy = "m365-converge"
	m365ConvergeActor     = "controller"
	m365MaxOutcomes       = 1000
	m365MaxMessageLen     = 256

	// Resource outcome states recorded in ConvergeStatus.
	ConvergeStateConverged     = "converged"
	ConvergeStateDriftReported = "drift-reported"
	ConvergeStateReverted      = "drift-reverted"
	ConvergeStateCreated       = "created"
	ConvergeStateAbsent        = "absent"
	ConvergeStateRefused       = "refused"
	ConvergeStateError         = "error"
)

// ConvergeConfigSource returns the tenant's effective cfg (the controller's
// existing effective-config function, which cascades through the tenant tree).
type ConvergeConfigSource interface {
	EffectiveConfig(ctx context.Context, tenantID string) (*stewardtypes.StewardConfig, error)
}

// TenantModuleSource creates a module instance scoped to one execution tenant
// (workflow.TenantModuleLoader). It is the same call Engine.executeTaskStep makes,
// so credential issuance and the execution-tenant check apply per tenant.
type TenantModuleSource interface {
	CreateTenantModuleInstance(ctx context.Context, moduleName, tenantID string) (modules.Module, error)
}

// ConvergeAuditor records audit events (*audit.Manager).
type ConvergeAuditor interface {
	RecordEvent(ctx context.Context, event *audit.AuditEventBuilder) error
}

// CredentialIssuer issues the one-time password of a user the loop creates
// (*credentials.Service). Issue stores the password before it returns.
type CredentialIssuer interface {
	Issue(ctx context.Context, key credentials.Key) (string, error)
	Discard(ctx context.Context, key credentials.Key) error
}

// M365ConvergeConfig configures an M365Converge. Config, Modules, Providers,
// Writer and Store are required. Without Credentials a missing user is not
// created.
type M365ConvergeConfig struct {
	Config       ConvergeConfigSource
	Modules      TenantModuleSource
	Providers    ProviderOpRunner
	ProviderName string
	Writer       ObservationWriter
	Store        cfgconfig.ConfigStore
	Audit        ConvergeAuditor
	Credentials  CredentialIssuer
	Logger       logging.Logger
	Now          func() time.Time
}

// ResourceOutcome is the bounded, persisted result of one declared resource.
type ResourceOutcome struct {
	Module   string   `json:"module"`
	Resource string   `json:"resource"`
	Mode     string   `json:"mode"`
	State    string   `json:"state"`
	Fields   []string `json:"fields,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// ConvergeStatus is the persisted outcome of a tenant's latest convergence pass.
type ConvergeStatus struct {
	Tenant    string            `json:"tenant"`
	LastRun   time.Time         `json:"last_run"`
	Error     string            `json:"error,omitempty"`
	Resources []ResourceOutcome `json:"resources"`
}

type convergeBinding struct {
	ObjectID string    `json:"object_id"`
	Identity string    `json:"identity"`
	BoundAt  time.Time `json:"bound_at"`
}

type bindingDoc struct {
	Tenant   string                     `json:"tenant"`
	Bindings map[string]convergeBinding `json:"bindings"`
}

// M365Converge is the controller-run loop that brings declared m365-entra-user
// and m365-entra-group resources to their declared state. It never writes an
// object that is not declared and bound, never deletes, and never passes group
// membership to a user. It implements DeclaredSet: an object is managed when a
// declared resource is bound to it.
type M365Converge struct {
	cfg M365ConvergeConfig

	mu       sync.Mutex
	loaded   bool
	declared map[string]map[string]struct{} // tenant -> kind:objectID
}

// NewM365Converge validates cfg and returns the loop.
func NewM365Converge(cfg M365ConvergeConfig) (*M365Converge, error) {
	switch {
	case cfg.Config == nil:
		return nil, errors.New("m365 converge: config source is required")
	case cfg.Modules == nil:
		return nil, errors.New("m365 converge: module source is required")
	case cfg.Providers == nil:
		return nil, errors.New("m365 converge: provider runner is required")
	case cfg.Writer == nil:
		return nil, errors.New("m365 converge: entity graph writer is required")
	case cfg.Store == nil:
		return nil, errors.New("m365 converge: config store is required")
	}
	if cfg.ProviderName == "" {
		cfg.ProviderName = "entraid"
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.NewNoopLogger()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &M365Converge{cfg: cfg, declared: map[string]map[string]struct{}{}}, nil
}

var _ DeclaredSet = (*M365Converge)(nil)

// IsDeclared reports whether a declared resource is bound to the object.
func (c *M365Converge) IsDeclared(kind, id string) bool {
	c.loadBindings(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	key := kind + ":" + id
	for _, set := range c.declared {
		if _, ok := set[key]; ok {
			return true
		}
	}
	return false
}

// Status returns the persisted outcome of a tenant's latest pass.
func (c *M365Converge) Status(ctx context.Context, tenant string) (ConvergeStatus, bool, error) {
	var st ConvergeStatus
	entry, err := c.cfg.Store.GetConfig(ctx, convergeKey(m365ConvergeNamespace, tenant))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return st, false, nil
		}
		return st, false, err
	}
	if err := json.Unmarshal(entry.Data, &st); err != nil {
		return st, false, err
	}
	return st, true, nil
}

func convergeKey(namespace, tenant string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: m365ManifestTenant, Namespace: namespace, Name: hex32(tenant)}
}

// loadBindings reads every persisted binding document once, so the managed flag is
// right on the first inventory pass after a restart. A failed read is retried on
// the next call.
func (c *M365Converge) loadBindings(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return
	}
	entries, err := c.cfg.Store.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: m365ManifestTenant, Namespace: m365BindingNamespace})
	if err != nil {
		c.cfg.Logger.Warn("m365 converge: reading bindings failed", "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	for _, e := range entries {
		var doc bindingDoc
		if json.Unmarshal(e.Data, &doc) != nil || doc.Tenant == "" {
			continue
		}
		set := map[string]struct{}{}
		for key, b := range doc.Bindings {
			set[kindOfBinding(key)+":"+b.ObjectID] = struct{}{}
		}
		c.declared[doc.Tenant] = set
	}
	c.loaded = true
}

func kindOfBinding(key string) string {
	if strings.HasPrefix(key, M365GroupModule+"/") {
		return kindGroup
	}
	return kindUser
}

func (c *M365Converge) readBindings(ctx context.Context, tenant string) (bindingDoc, error) {
	doc := bindingDoc{Tenant: tenant, Bindings: map[string]convergeBinding{}}
	entry, err := c.cfg.Store.GetConfig(ctx, convergeKey(m365BindingNamespace, tenant))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return doc, nil
		}
		return doc, err
	}
	if err := json.Unmarshal(entry.Data, &doc); err != nil {
		return doc, err
	}
	if doc.Tenant != tenant {
		return doc, errors.New("binding document does not belong to this tenant")
	}
	if doc.Bindings == nil {
		doc.Bindings = map[string]convergeBinding{}
	}
	return doc, nil
}

func (c *M365Converge) writeJSON(ctx context.Context, key *cfgconfig.ConfigKey, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.cfg.Store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedBy: m365ConvergeCreatedBy, UpdatedBy: m365ConvergeCreatedBy,
	})
}

// converge is the per-tenant working state of one pass.
type converge struct {
	c     *M365Converge
	ctx   context.Context
	conn  M365Connection
	guid  string
	cfg   *stewardtypes.StewardConfig
	doc   bindingDoc
	dirty bool
	now   time.Time
	bound map[string]struct{}
	outs  []ResourceOutcome
	obs   []egtypes.Observation
}

// Converge runs one pass for a tenant: it reads the tenant's declared users and
// groups, compares each with the live object and applies or reports according to
// the module's drift mode. A failing resource is reported and skipped.
func (c *M365Converge) Converge(ctx context.Context, conn M365Connection) {
	c.loadBindings(ctx)
	guid, ok := normalizeEntraGUID(conn.EntraTenantID)
	if !ok {
		return
	}
	tctx := context.WithValue(ctx, ctxkeys.TenantID, conn.Tenant)
	st := ConvergeStatus{Tenant: conn.Tenant, LastRun: c.cfg.Now()}
	cfg, err := c.cfg.Config.EffectiveConfig(tctx, conn.Tenant)
	if err != nil {
		st.Error = boundedMessage(err)
		c.cfg.Logger.Warn("m365 converge: reading the declared configuration failed",
			"tenant", logging.SanitizeLogValue(conn.Tenant), "error", st.Error)
		c.saveStatus(ctx, st)
		return
	}
	if cfg == nil {
		cfg = &stewardtypes.StewardConfig{}
	}
	doc, err := c.readBindings(ctx, conn.Tenant)
	if err != nil {
		st.Error = boundedMessage(err)
		c.cfg.Logger.Warn("m365 converge: reading bindings failed",
			"tenant", logging.SanitizeLogValue(conn.Tenant), "error", st.Error)
		c.saveStatus(ctx, st)
		return
	}
	run := &converge{c: c, ctx: tctx, conn: conn, guid: guid, cfg: cfg, doc: doc,
		now: c.cfg.Now(), bound: map[string]struct{}{}}
	declaredKeys := map[string]struct{}{}
	for _, r := range cfg.Resources {
		if ctx.Err() != nil {
			return
		}
		if r.Module != M365UserModule && r.Module != M365GroupModule {
			continue
		}
		if !moduleset.Contains(r.Module) {
			continue
		}
		declaredKeys[bindingKey(r.Module, r.Name)] = struct{}{}
		run.resource(r)
	}
	// A resource no longer declared loses its binding, so redeclaring it later
	// is a fresh bind-or-adopt decision.
	for k := range run.doc.Bindings {
		if _, ok := declaredKeys[k]; !ok {
			delete(run.doc.Bindings, k)
			run.dirty = true
		}
	}
	if run.dirty {
		if err := c.writeJSON(ctx, convergeKey(m365BindingNamespace, conn.Tenant), run.doc); err != nil {
			c.cfg.Logger.Warn("m365 converge: recording bindings failed",
				"tenant", logging.SanitizeLogValue(conn.Tenant), "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	c.mu.Lock()
	set := map[string]struct{}{}
	for k, b := range run.doc.Bindings {
		set[kindOfBinding(k)+":"+b.ObjectID] = struct{}{}
	}
	c.declared[conn.Tenant] = set
	c.mu.Unlock()

	c.flushObservations(ctx, conn, guid, run.obs)
	if len(run.outs) > m365MaxOutcomes {
		run.outs = run.outs[:m365MaxOutcomes]
	}
	st.Resources = run.outs
	c.saveStatus(ctx, st)
}

func (c *M365Converge) saveStatus(ctx context.Context, st ConvergeStatus) {
	if err := c.writeJSON(ctx, convergeKey(m365ConvergeNamespace, st.Tenant), st); err != nil {
		c.cfg.Logger.Warn("m365 converge: recording status failed",
			"tenant", logging.SanitizeLogValue(st.Tenant), "error", logging.SanitizeLogValue(err.Error()))
	}
}

func (c *M365Converge) flushObservations(ctx context.Context, conn M365Connection, guid string, obs []egtypes.Observation) {
	if len(obs) == 0 {
		return
	}
	authority := m365Source + ":" + guid
	if err := c.cfg.Writer.ReportObservations(ctx, egif.ObservationBatch{Source: authority, Observations: obs}); err != nil {
		c.cfg.Logger.Warn("m365 converge: recording drift failed",
			"tenant", logging.SanitizeLogValue(conn.Tenant), "error", logging.SanitizeLogValue(err.Error()))
	}
}

func bindingKey(module, resource string) string { return module + "/" + resource }

func boundedMessage(err error) string {
	msg := logging.SanitizeLogValue(err.Error())
	if len(msg) > m365MaxMessageLen {
		msg = msg[:m365MaxMessageLen]
	}
	return msg
}

func (r *converge) outcome(res stewardtypes.ResourceConfig, mode stewardtypes.DriftMode, state, msg string, fields []string) {
	if len(msg) > m365MaxMessageLen {
		msg = msg[:m365MaxMessageLen]
	}
	r.outs = append(r.outs, ResourceOutcome{Module: res.Module, Resource: res.Name,
		Mode: string(mode), State: state, Fields: fields, Message: msg})
	if state == ConvergeStateRefused || state == ConvergeStateError {
		r.c.cfg.Logger.Warn("m365 converge: declared resource not converged",
			"tenant", logging.SanitizeLogValue(r.conn.Tenant),
			"module", logging.SanitizeLogValue(res.Module),
			"resource", logging.SanitizeLogValue(res.Name),
			"state", state, "reason", logging.SanitizeLogValue(msg))
	}
}

// resource converges one declared resource. Nothing here panics the pass: every
// failure becomes an outcome.
func (r *converge) resource(res stewardtypes.ResourceConfig) {
	mode := stewardtypes.EffectiveDriftMode(r.cfg.Steward, res.Module)
	spec, err := newResourceSpec(res, r.guid)
	if err != nil {
		r.outcome(res, mode, ConvergeStateRefused, err.Error(), nil)
		return
	}
	key := bindingKey(res.Module, res.Name)
	bind, isBound := r.doc.Bindings[key]

	live, found, err := r.lookup(spec)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "lookup failed: "+boundedMessage(err), nil)
		return
	}

	var ensureNew bool
	switch {
	case !found && isBound:
		r.outcome(res, mode, ConvergeStateAbsent, "the bound object no longer exists; it is not recreated", nil)
		return
	case !found && spec.kind == kindUser && (mode != stewardtypes.DriftModeApply || r.c.cfg.Credentials == nil):
		r.outcome(res, mode, ConvergeStateAbsent, "the user does not exist; it is created in apply mode", nil)
		return
	case !found:
		ensureNew = true
	case isBound && live.id != bind.ObjectID:
		r.outcome(res, mode, ConvergeStateRefused,
			"the declared "+spec.identityWord()+" now resolves to a different object than the one bound; not converged", nil)
		return
	case !isBound && !spec.adopt:
		r.outcome(res, mode, ConvergeStateRefused,
			"an existing "+spec.kind+" matches the declared "+spec.identityWord()+" but is not bound; set adopt: true to take it over", nil)
		return
	case !isBound:
		r.bindObject(key, live.id, spec.identity)
	}

	if ensureNew {
		if mode != stewardtypes.DriftModeApply {
			r.outcome(res, mode, ConvergeStateAbsent, "the group does not exist; it is created in apply mode", nil)
			return
		}
		if spec.kind == kindUser {
			r.createUser(res, spec, mode, key)
			return
		}
		r.create(res, spec, mode, key)
		return
	}
	r.compareAndApply(res, spec, mode, live)
}

func (r *converge) bindObject(key, objectID, identity string) {
	r.doc.Bindings[key] = convergeBinding{ObjectID: objectID, Identity: identity, BoundAt: r.now}
	r.dirty = true
}

// liveObject is the identity of an object found in Entra.
type liveObject struct {
	id   string
	name string
}

// lookup finds the live object a declaration names, through the directory
// provider. A user is found by UPN. A bound group is found by its object id (and
// refused if the declared name has moved to another object); an unbound group is
// found by exact display name.
func (r *converge) lookup(spec *resourceSpec) (liveObject, bool, error) {
	var out liveObject
	var found bool
	err := r.c.cfg.Providers.ExecuteProviderOp(r.ctx, r.c.cfg.ProviderName, func(p dirif.DirectoryProvider) error {
		switch spec.kind {
		case kindUser:
			u, err := p.GetUser(r.ctx, spec.identity)
			if err != nil {
				if graph.IsNotFoundError(err) {
					return nil
				}
				return err
			}
			out, found = liveObject{id: u.ID, name: u.UserPrincipalName}, validObjectID(u.ID)
			return nil
		default:
			named, err := groupsNamed(r.ctx, p, spec.identity)
			if err != nil {
				return err
			}
			bind, isBound := r.doc.Bindings[bindingKey(spec.module, spec.resource)]
			if isBound {
				g, err := p.GetGroup(r.ctx, bind.ObjectID)
				if err != nil {
					if graph.IsNotFoundError(err) {
						return nil
					}
					return err
				}
				for _, n := range named {
					if n.ID != g.ID {
						// The declared name belongs to another object now.
						out, found = liveObject{id: n.ID, name: n.DisplayName}, true
						return nil
					}
				}
				out, found = liveObject{id: g.ID, name: g.DisplayName}, true
				return nil
			}
			switch len(named) {
			case 0:
			case 1:
				out, found = liveObject{id: named[0].ID, name: named[0].DisplayName}, true
			default:
				return fmt.Errorf("%d groups share the declared display name; it cannot be told which to take", len(named))
			}
			return nil
		}
	})
	return out, found, err
}

func groupsNamed(ctx context.Context, p dirif.DirectoryProvider, name string) ([]dirif.DirectoryGroup, error) {
	list, err := p.ListGroups(ctx, &dirif.SearchFilters{Query: name, Limit: 999})
	if err != nil {
		return nil, err
	}
	var out []dirif.DirectoryGroup
	for _, g := range list.Groups {
		if g.DisplayName == name && validObjectID(g.ID) {
			out = append(out, g)
		}
	}
	return out, nil
}

// instance creates the tenant-scoped module instance and returns it with its stop.
func (r *converge) instance(module string) (modules.Module, func(), error) {
	m, err := r.c.cfg.Modules.CreateTenantModuleInstance(r.ctx, module, r.conn.Tenant)
	if err != nil {
		return nil, nil, err
	}
	stop := func() {}
	if s, ok := m.(interface{ Stop() error }); ok {
		stop = func() {
			if err := s.Stop(); err != nil {
				r.c.cfg.Logger.Warn("m365 converge: stopping module failed", "error", logging.SanitizeLogValue(err.Error()))
			}
		}
	}
	return m, stop, nil
}

func (r *converge) compareAndApply(res stewardtypes.ResourceConfig, spec *resourceSpec, mode stewardtypes.DriftMode, live liveObject) {
	mod, stop, err := r.instance(res.Module)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "module unavailable: "+boundedMessage(err), nil)
		return
	}
	defer stop()

	resourceID := r.guid + ":" + spec.moduleIdentity(live)
	state, err := mod.Get(r.ctx, resourceID)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "reading the live object failed: "+boundedMessage(err), nil)
		return
	}
	liveMap := state.AsMap()
	diffs := spec.compare(liveMap)
	r.recordDrift(res, spec, live.id, diffs)
	drifted := driftedFields(diffs)
	if len(drifted) == 0 {
		r.outcome(res, mode, ConvergeStateConverged, "", nil)
		return
	}
	if mode != stewardtypes.DriftModeApply {
		r.outcome(res, mode, ConvergeStateDriftReported, "differs from the declared state", drifted)
		return
	}

	setErr := mod.Set(r.ctx, resourceID, spec.state(liveMap))
	r.audit(res, "update", setErr, drifted)
	if setErr != nil {
		r.outcome(res, mode, ConvergeStateError, "applying failed: "+boundedMessage(setErr), drifted)
		return
	}
	after, err := mod.Get(r.ctx, resourceID)
	if err != nil {
		r.outcome(res, mode, ConvergeStateReverted, "applied; verifying failed: "+boundedMessage(err), drifted)
		return
	}
	still := spec.compare(after.AsMap())
	r.recordDrift(res, spec, live.id, still)
	if left := driftedFields(still); len(left) > 0 {
		r.outcome(res, mode, ConvergeStateError, "applied but the object still differs", left)
		return
	}
	r.outcome(res, mode, ConvergeStateReverted, "", drifted)
}

// create makes a declared group that does not exist (apply mode) and binds it.
func (r *converge) create(res stewardtypes.ResourceConfig, spec *resourceSpec, mode stewardtypes.DriftMode, key string) {
	mod, stop, err := r.instance(res.Module)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "module unavailable: "+boundedMessage(err), nil)
		return
	}
	defer stop()
	setErr := mod.Set(r.ctx, r.guid+":new", spec.state(nil))
	r.audit(res, "create", setErr, nil)
	if setErr != nil {
		r.outcome(res, mode, ConvergeStateError, "creating failed: "+boundedMessage(setErr), nil)
		return
	}
	live, found, err := r.lookup(spec)
	if err != nil || !found {
		r.outcome(res, mode, ConvergeStateError, "created; the new object could not be bound", nil)
		return
	}
	r.bindObject(key, live.id, spec.identity)
	r.outcome(res, mode, ConvergeStateCreated, "", nil)
}

// createUser makes a declared user that does not exist (apply mode). The one-time
// password is issued and stored by the credential service before the module is
// called, so a store failure creates no user. The password is passed only here,
// with force_change_password_next_signin, and never reaches a log, an outcome, an
// audit record or any store the loop writes.
func (r *converge) createUser(res stewardtypes.ResourceConfig, spec *resourceSpec, mode stewardtypes.DriftMode, key string) {
	ckey := credentials.Key{TenantID: r.conn.Tenant, StewardID: m365ConvergeActor, ResourceID: res.Name}
	password, err := r.c.cfg.Credentials.Issue(r.ctx, ckey)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "the initial password could not be stored; the user is not created", nil)
		return
	}
	mod, stop, err := r.instance(res.Module)
	if err != nil {
		r.outcome(res, mode, ConvergeStateError, "module unavailable: "+boundedMessage(err), nil)
		return
	}
	defer stop()

	state := spec.stateMap(nil)
	if _, declared := spec.bools["account_enabled"]; !declared {
		state["account_enabled"] = true
	}
	state["password_profile"] = map[string]interface{}{
		"password":                          password,
		"force_change_password_next_signin": true,
	}
	rawErr := mod.Set(r.ctx, r.guid+":new", fragState(state))
	var setErr error
	if rawErr != nil {
		setErr = errors.New(redactPassword(rawErr.Error(), password))
	}
	r.audit(res, "create", setErr, nil)
	if setErr != nil {
		// A retried create whose first attempt was lost comes back as a 4xx
		// ("already exists"), so a definite-looking failure is only trusted when
		// the user is confirmed not to exist.
		if _, exists, lerr := r.lookup(spec); definiteCreateFailure(rawErr) && lerr == nil && !exists {
			if err := r.c.cfg.Credentials.Discard(r.ctx, ckey); err != nil {
				r.c.cfg.Logger.Warn("m365 converge: discarding the initial password failed",
					"error", logging.SanitizeLogValue(err.Error()))
			}
		}
		r.outcome(res, mode, ConvergeStateError, "creating failed: "+boundedMessage(setErr), nil)
		return
	}
	live, found, err := r.lookup(spec)
	if err != nil || !found {
		r.outcome(res, mode, ConvergeStateError, "created; the new object could not be bound", nil)
		return
	}
	r.bindObject(key, live.id, spec.identity)
	// The credential service refuses a second issue once the account exists.
	if err := r.c.writeJSON(r.ctx, credentials.BindingConfigKey(ckey), convergeBinding{ObjectID: live.id, Identity: spec.identity, BoundAt: r.now}); err != nil {
		r.c.cfg.Logger.Warn("m365 converge: recording the credential binding failed",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	r.outcome(res, mode, ConvergeStateCreated, "", nil)
}

// redactPassword removes the password from msg, in its literal form and as a JSON
// encoder writes it (an error that echoes a request body escapes <, > and &).
func redactPassword(msg, password string) string {
	msg = strings.ReplaceAll(msg, password, "[redacted]")
	if enc, err := json.Marshal(password); err == nil && len(enc) > 2 {
		msg = strings.ReplaceAll(msg, string(enc[1:len(enc)-1]), "[redacted]")
	}
	return msg
}

// definiteCreateFailure reports whether Graph rejected a create outright (a 4xx
// other than a timeout), so no user exists. Anything else — a 5xx, a timeout, a
// lost response, an error from before the request — is ambiguous: the user may
// exist with the issued password.
func definiteCreateFailure(err error) bool {
	var ge *graph.GraphError
	if !errors.As(err, &ge) {
		return false
	}
	return ge.StatusCode >= 400 && ge.StatusCode < 500 && ge.StatusCode != http.StatusRequestTimeout
}

// audit records a write the controller made. The resource id is the cfg-declared
// resource id, never the Entra object id.
func (r *converge) audit(res stewardtypes.ResourceConfig, action string, setErr error, fields []string) {
	if r.c.cfg.Audit == nil {
		return
	}
	result := business.AuditResultSuccess
	severity := business.AuditSeverityMedium
	if setErr != nil {
		result = business.AuditResultFailure
		severity = business.AuditSeverityHigh
	}
	b := audit.NewEventBuilder().
		Tenant(r.conn.Tenant).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(m365ConvergeActor, business.AuditUserTypeSystem).
		Resource(res.Module, res.Name, "").
		Result(result).
		Severity(severity)
	if len(fields) > 0 {
		b = b.Detail("fields", fields)
	}
	if setErr != nil {
		b = b.Detail("error", boundedMessage(setErr))
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	defer cancel()
	if err := r.c.cfg.Audit.RecordEvent(actx, b); err != nil {
		r.c.cfg.Logger.Warn("m365 converge: recording audit event failed", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// recordDrift queues a drift-diff observation under the object's M365 entity id,
// carrying the cfg-declared resource id.
func (r *converge) recordDrift(res stewardtypes.ResourceConfig, spec *resourceSpec, objectID string, diffs []fieldDiff) {
	word := "user"
	if spec.kind == kindGroup {
		word = "group"
	}
	eid, err := egtypes.NewEID(m365Source, r.guid, word+":"+objectID)
	if err != nil {
		return
	}
	fields := make([]interface{}, 0, len(diffs))
	for _, d := range diffs {
		fields = append(fields, map[string]interface{}{
			"attribute": d.attr, "desired": d.desired, "actual": d.actual, "matching": d.matching,
		})
	}
	r.obs = append(r.obs, egtypes.Observation{
		Source: m365Source + ":" + r.guid, ObservedAt: r.now, RecordedAt: r.now,
		Subject: eid.String(), Kind: egtypes.ObservationKindDriftDiff, Confidence: egtypes.ConfidenceHigh,
		Payload: map[string]interface{}{
			"config_revision": "",
			"fields":          fields,
			"fragment_id":     spec.kind + ":" + objectID,
			"resource_id":     res.Name,
			"module":          res.Module,
			"owning_tenant":   r.conn.Tenant,
		},
	})
}

type fieldDiff struct {
	attr, desired, actual string
	matching              bool
}

func driftedFields(diffs []fieldDiff) []string {
	var out []string
	for _, d := range diffs {
		if !d.matching {
			out = append(out, d.attr)
		}
	}
	return out
}

// resourceSpec is a declaration reduced to what convergence may touch.
type resourceSpec struct {
	module   string
	resource string
	kind     string
	identity string // UPN or group display name
	adopt    bool
	guid     string
	strs     map[string]string
	bools    map[string]bool
	lists    map[string][]string
	managed  []string
}

var (
	userStringFields = []string{"display_name", "mail", "mobile_phone", "office_location", "job_title", "department", "company_name"}
	userBoolFields   = []string{"account_enabled"}
	groupStringField = []string{"display_name", "description"}
	groupListFields  = []string{"members_present", "members_absent"}
)

func (s *resourceSpec) identityWord() string {
	if s.kind == kindUser {
		return "UPN"
	}
	return "name"
}

// moduleIdentity is the second half of the module's resource id: a user's UPN, a
// group's object id.
func (s *resourceSpec) moduleIdentity(live liveObject) string {
	if s.kind == kindUser {
		return s.identity
	}
	return live.id
}

// newResourceSpec reads a declaration. Anything outside the managed attributes —
// groups on a user, passwords, licenses — is ignored, never forwarded.
func newResourceSpec(res stewardtypes.ResourceConfig, guid string) (*resourceSpec, error) {
	s := &resourceSpec{module: res.Module, resource: res.Name, guid: guid,
		strs: map[string]string{}, bools: map[string]bool{}, lists: map[string][]string{}}
	if v, ok := res.Config["adopt"].(bool); ok {
		s.adopt = v
	}
	strFields, boolFields, listFields := userStringFields, userBoolFields, []string(nil)
	if res.Module == M365GroupModule {
		s.kind = kindGroup
		strFields, boolFields, listFields = groupStringField, nil, groupListFields
		s.identity, _ = res.Config["display_name"].(string)
		if s.identity == "" {
			return nil, errors.New("display_name is required to identify a group")
		}
	} else {
		s.kind = kindUser
		s.identity, _ = res.Config["user_principal_name"].(string)
		if s.identity == "" {
			return nil, errors.New("user_principal_name is required to identify a user")
		}
	}
	// The connection's Entra tenant is authoritative; a declaration naming another
	// directory is refused rather than forwarded.
	if t, ok := res.Config["tenant_id"].(string); ok && t != "" {
		if g, valid := normalizeEntraGUID(t); !valid || g != guid {
			return nil, errors.New("tenant_id does not match the tenant's M365 connection")
		}
	}
	for _, f := range strFields {
		if v, ok := res.Config[f].(string); ok {
			s.strs[f] = v
			s.managed = append(s.managed, f)
		}
	}
	for _, f := range boolFields {
		if v, ok := res.Config[f].(bool); ok {
			s.bools[f] = v
			s.managed = append(s.managed, f)
		}
	}
	for _, f := range listFields {
		switch v := res.Config[f].(type) {
		case []string:
			s.lists[f] = v
			s.managed = append(s.managed, f)
		case []interface{}:
			var l []string
			for _, e := range v {
				str, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("%s entries must be strings", f)
				}
				l = append(l, str)
			}
			s.lists[f] = l
			s.managed = append(s.managed, f)
		}
	}
	return s, nil
}

// compare reports each managed attribute against the live state. A live attribute
// the module omits (an empty string, false) reads as its zero value.
func (s *resourceSpec) compare(live map[string]interface{}) []fieldDiff {
	var out []fieldDiff
	for _, f := range s.managed {
		d := fieldDiff{attr: f}
		switch {
		case isListField(f):
			// Membership is additive and subtractive: only the listed members are
			// compared, so a member nobody declared is never drift.
			want := normalizeList(s.lists[f])
			have := normalizeList(asStrings(live["members"]))
			inLive := map[string]struct{}{}
			for _, h := range have {
				inLive[h] = struct{}{}
			}
			var listed []string // the declared members that are in the group
			for _, w := range want {
				if _, ok := inLive[w]; ok {
					listed = append(listed, w)
				}
			}
			d.desired, d.actual = strings.Join(want, ","), strings.Join(listed, ",")
			if f == "members_absent" {
				d.desired = ""
			}
			d.matching = d.desired == d.actual
		case isBoolField(f):
			have, _ := live[f].(bool)
			d.desired, d.actual = fmt.Sprint(s.bools[f]), fmt.Sprint(have)
			d.matching = s.bools[f] == have
		default:
			have, _ := live[f].(string)
			d.desired, d.actual = s.strs[f], have
			d.matching = s.strs[f] == have
		}
		out = append(out, d)
	}
	return out
}

func isListField(f string) bool { return f == "members_present" || f == "members_absent" }
func isBoolField(f string) bool { return f == "account_enabled" }

func asStrings(v interface{}) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []interface{}:
		var out []string
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if _, dup := seen[s]; dup || s == "" {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// state builds the ConfigState handed to Set. managed_fields names exactly the
// declared attributes, so the module writes nothing else; the attributes the module
// requires but the declaration omits are filled from the live object and are not
// managed. groups is never set.
func (s *resourceSpec) state(live map[string]interface{}) modules.ConfigState {
	return fragState(s.stateMap(live))
}

// stateMap is state's map. It never carries a password: password_profile is not a
// managed field of an update, so the module cannot re-apply one.
func (s *resourceSpec) stateMap(live map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"tenant_id": s.guid}
	liveStr := func(k string) string { v, _ := live[k].(string); return v }
	for k, v := range s.strs {
		m[k] = v
	}
	for k, v := range s.bools {
		m[k] = v
	}
	for k, v := range s.lists {
		m[k] = append([]string(nil), v...)
	}
	if s.kind == kindUser {
		m["user_principal_name"] = s.identity
		if _, ok := m["display_name"]; !ok {
			m["display_name"] = liveStr("display_name")
		}
		if _, ok := m["account_enabled"]; !ok {
			enabled, _ := live["account_enabled"].(bool)
			m["account_enabled"] = enabled
		}
		nick := liveStr("mail_nickname")
		if nick == "" {
			nick, _, _ = strings.Cut(s.identity, "@")
		}
		m["mail_nickname"] = nick
	} else {
		if _, ok := m["display_name"]; !ok {
			m["display_name"] = s.identity
		}
		nick := liveStr("mail_nickname")
		if nick == "" {
			nick = strings.Map(func(r rune) rune {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, s.identity)
		}
		m["mail_nickname"] = nick
		if _, ok := m["security_enabled"]; !ok {
			if v, ok := live["security_enabled"].(bool); ok {
				m["security_enabled"] = v
			} else {
				m["security_enabled"] = true
			}
		}
	}
	m["managed_fields"] = append([]string(nil), s.managed...)
	delete(m, "password_profile")
	return m
}
