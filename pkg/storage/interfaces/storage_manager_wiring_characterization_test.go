// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Characterization tests for the wiring of CreateClusterStorageManager,
// CreateOSSStorageManager and CreateAllStoresFromConfig (Issue #5819). They pin
// the externally visible behavior — which StorageManager fields are set, the
// error text per store, which stores tolerate business.ErrNotSupported and the
// disarmed-defer cleanup — so the constructors can be restructured without a
// behavior change. They run against the real SQLite and flat-file providers; the
// cluster constructor, which hard-codes the provider name "database", is driven
// by a wrapper around the real SQLite provider registered under that name.
package interfaces_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// storagemanagerwiringCharProvider wraps a real provider, reports a chosen name,
// always passes its own cfg to the wrapped provider, injects a per-store error
// keyed by store name, and captures the routing store it hands out.
type storagemanagerwiringCharProvider struct {
	interfaces.StorageProvider
	name     string
	cfg      map[string]interface{}
	failures map[string]error
	routing  business.RoutingStore
}

func (p *storagemanagerwiringCharProvider) Name() string { return p.name }

func storagemanagerwiringCharCreate[T any](p *storagemanagerwiringCharProvider, key string, real func(map[string]interface{}) (T, error)) (T, error) {
	if err, ok := p.failures[key]; ok {
		var zero T
		return zero, err
	}
	return real(p.cfg)
}

func storagemanagerwiringCharOptional[C any, T any](p *storagemanagerwiringCharProvider, key string, call func(C, map[string]interface{}) (T, error)) (T, error) {
	var zero T
	if err, ok := p.failures[key]; ok {
		return zero, err
	}
	c, ok := p.StorageProvider.(C)
	if !ok {
		return zero, business.ErrNotSupported
	}
	return call(c, p.cfg)
}

func (p *storagemanagerwiringCharProvider) CreateConfigStore(_ map[string]interface{}) (cfgconfig.ConfigStore, error) {
	return storagemanagerwiringCharCreate(p, "config", p.StorageProvider.CreateConfigStore)
}

func (p *storagemanagerwiringCharProvider) CreateAuditStore(_ map[string]interface{}) (business.AuditStore, error) {
	return storagemanagerwiringCharCreate(p, "audit", p.StorageProvider.CreateAuditStore)
}

func (p *storagemanagerwiringCharProvider) CreateRBACStore(_ map[string]interface{}) (business.RBACStore, error) {
	return storagemanagerwiringCharCreate(p, "rbac", p.StorageProvider.CreateRBACStore)
}

func (p *storagemanagerwiringCharProvider) CreateTenantStore(_ map[string]interface{}) (business.TenantStore, error) {
	return storagemanagerwiringCharCreate(p, "tenant", p.StorageProvider.CreateTenantStore)
}

func (p *storagemanagerwiringCharProvider) CreateRegistrationTokenStore(_ map[string]interface{}) (business.RegistrationTokenStore, error) {
	return storagemanagerwiringCharCreate(p, "registrationtoken", p.StorageProvider.CreateRegistrationTokenStore)
}

func (p *storagemanagerwiringCharProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return storagemanagerwiringCharCreate(p, "session", p.StorageProvider.CreateSessionStore)
}

func (p *storagemanagerwiringCharProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return storagemanagerwiringCharCreate(p, "steward", p.StorageProvider.CreateStewardStore)
}

func (p *storagemanagerwiringCharProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return storagemanagerwiringCharCreate(p, "command", p.StorageProvider.CreateCommandStore)
}

func (p *storagemanagerwiringCharProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return storagemanagerwiringCharCreate(p, "trigger", p.StorageProvider.CreateTriggerStore)
}

func (p *storagemanagerwiringCharProvider) CreatePushStore(_ map[string]interface{}) (business.PushStore, error) {
	return storagemanagerwiringCharCreate(p, "push", p.StorageProvider.CreatePushStore)
}

func (p *storagemanagerwiringCharProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return storagemanagerwiringCharCreate(p, "pendingregistration", p.StorageProvider.CreatePendingRegistrationStore)
}

func (p *storagemanagerwiringCharProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return storagemanagerwiringCharCreate(p, "iptrust", p.StorageProvider.CreateIPTrustStore)
}

func (p *storagemanagerwiringCharProvider) CreateAlertStore(_ map[string]interface{}) (business.AlertStore, error) {
	return storagemanagerwiringCharCreate(p, "alert", p.StorageProvider.CreateAlertStore)
}

func (p *storagemanagerwiringCharProvider) CreateApprovalStore(_ map[string]interface{}) (business.ApprovalStore, error) {
	return storagemanagerwiringCharCreate(p, "approval", p.StorageProvider.CreateApprovalStore)
}

func (p *storagemanagerwiringCharProvider) CreateReportTemplateStore(_ map[string]interface{}) (business.ReportTemplateStore, error) {
	return storagemanagerwiringCharCreate(p, "reporttemplate", p.StorageProvider.CreateReportTemplateStore)
}

func (p *storagemanagerwiringCharProvider) CreateWorkflowExecutionStore(_ map[string]interface{}) (business.WorkflowExecutionStore, error) {
	return storagemanagerwiringCharCreate(p, "workflowexecution", p.StorageProvider.CreateWorkflowExecutionStore)
}

func (p *storagemanagerwiringCharProvider) CreateNonceStore(_ map[string]interface{}) (business.NonceStore, error) {
	return storagemanagerwiringCharOptional(p, "nonce", interfaces.NonceStoreCreator.CreateNonceStore)
}

func (p *storagemanagerwiringCharProvider) CreateLeaseStore(_ map[string]interface{}) (business.LeaseStore, error) {
	return storagemanagerwiringCharOptional(p, "lease", interfaces.LeaseStoreCreator.CreateLeaseStore)
}

func (p *storagemanagerwiringCharProvider) CreateRoutingStore(_ map[string]interface{}) (business.RoutingStore, error) {
	store, err := storagemanagerwiringCharOptional(p, "routing", interfaces.RoutingStoreCreator.CreateRoutingStore)
	if err == nil {
		p.routing = store
	}
	return store, err
}

func (p *storagemanagerwiringCharProvider) CreateNodeRegistryStore(_ map[string]interface{}) (business.NodeRegistryStore, error) {
	return storagemanagerwiringCharOptional(p, "noderegistry", interfaces.NodeRegistryStoreCreator.CreateNodeRegistryStore)
}

func (p *storagemanagerwiringCharProvider) CreateTenantCrossingStore(_ map[string]interface{}) (business.TenantCrossingStore, error) {
	return storagemanagerwiringCharOptional(p, "tenantcrossing", interfaces.TenantCrossingStoreCreator.CreateTenantCrossingStore)
}

func (p *storagemanagerwiringCharProvider) CreateCaseStore(_ map[string]interface{}) (business.CaseStore, error) {
	return storagemanagerwiringCharOptional(p, "case", interfaces.CaseStoreCreator.CreateCaseStore)
}

// storagemanagerwiringCharBundleFailProvider additionally exposes
// BusinessStoreOpener and fails it, so the OSS bundle path is reachable.
type storagemanagerwiringCharBundleFailProvider struct {
	*storagemanagerwiringCharProvider
}

func (p *storagemanagerwiringCharBundleFailProvider) OpenBusinessStores(_ string) (*interfaces.BusinessStoreBundle, error) {
	return nil, errors.New("injected: bundle open failed")
}

var errStoragemanagerwiringCharInjected = errors.New("injected: store creation failed")

func storagemanagerwiringCharSQLite(t *testing.T, name string, failures map[string]error) *storagemanagerwiringCharProvider {
	t.Helper()
	return &storagemanagerwiringCharProvider{
		StorageProvider: newSQLiteProvider(),
		name:            name,
		cfg:             map[string]interface{}{"path": filepath.Join(t.TempDir(), "test.db")},
		failures:        failures,
	}
}

func storagemanagerwiringCharFlatfile(t *testing.T, failures map[string]error) *storagemanagerwiringCharProvider {
	t.Helper()
	return &storagemanagerwiringCharProvider{
		StorageProvider: newFlatFileProvider(),
		name:            "flatfile",
		cfg:             map[string]interface{}{"root": t.TempDir()},
		failures:        failures,
	}
}

// storagemanagerwiringCharIsSet reports, per store key, whether the manager's
// field is populated.
var storagemanagerwiringCharIsSet = map[string]func(*interfaces.StorageManager) bool{
	"config":              func(sm *interfaces.StorageManager) bool { return sm.GetConfigStore() != nil },
	"audit":               func(sm *interfaces.StorageManager) bool { return sm.GetAuditStore() != nil },
	"rbac":                func(sm *interfaces.StorageManager) bool { return sm.GetRBACStore() != nil },
	"tenant":              func(sm *interfaces.StorageManager) bool { return sm.GetTenantStore() != nil },
	"registrationtoken":   func(sm *interfaces.StorageManager) bool { return sm.GetRegistrationTokenStore() != nil },
	"session":             func(sm *interfaces.StorageManager) bool { return sm.GetSessionStore() != nil },
	"steward":             func(sm *interfaces.StorageManager) bool { return sm.GetStewardStore() != nil },
	"command":             func(sm *interfaces.StorageManager) bool { return sm.GetCommandStore() != nil },
	"trigger":             func(sm *interfaces.StorageManager) bool { return sm.GetTriggerStore() != nil },
	"push":                func(sm *interfaces.StorageManager) bool { return sm.GetPushStore() != nil },
	"pendingregistration": func(sm *interfaces.StorageManager) bool { return sm.GetPendingRegistrationStore() != nil },
	"iptrust":             func(sm *interfaces.StorageManager) bool { return sm.GetIPTrustStore() != nil },
	"alert":               func(sm *interfaces.StorageManager) bool { return sm.GetAlertStore() != nil },
	"approval":            func(sm *interfaces.StorageManager) bool { return sm.GetApprovalStore() != nil },
	"reporttemplate":      func(sm *interfaces.StorageManager) bool { return sm.GetReportTemplateStore() != nil },
	"workflowexecution":   func(sm *interfaces.StorageManager) bool { return sm.GetWorkflowExecutionStore() != nil },
	"nonce":               func(sm *interfaces.StorageManager) bool { return sm.GetNonceStore() != nil },
	"lease":               func(sm *interfaces.StorageManager) bool { return sm.GetLeaseStore() != nil },
	"routing":             func(sm *interfaces.StorageManager) bool { return sm.GetRoutingStore() != nil },
	"noderegistry":        func(sm *interfaces.StorageManager) bool { return sm.GetNodeRegistryStore() != nil },
	"tenantcrossing":      func(sm *interfaces.StorageManager) bool { return sm.GetTenantCrossingStore() != nil },
	"case":                func(sm *interfaces.StorageManager) bool { return sm.GetCaseStore() != nil },
	"refreshpolicy":       func(sm *interfaces.StorageManager) bool { return sm.GetRefreshPolicyStore() != nil },
	"pendingrefresh":      func(sm *interfaces.StorageManager) bool { return sm.GetPendingRefreshStore() != nil },
	"assurancepolicy":     func(sm *interfaces.StorageManager) bool { return sm.GetAssurancePolicyStore() != nil },
	"blastradiuspolicy":   func(sm *interfaces.StorageManager) bool { return sm.GetBlastRadiusPolicyStore() != nil },
	"scriptrun":           func(sm *interfaces.StorageManager) bool { return sm.GetScriptRunStore() != nil },
	"executionqueue":      func(sm *interfaces.StorageManager) bool { return sm.GetExecutionQueueStore() != nil },
	"certrevocation":      func(sm *interfaces.StorageManager) bool { return sm.GetCertRevocationStore() != nil },
	"signingcursor":       func(sm *interfaces.StorageManager) bool { return sm.GetSigningCursorStore() != nil },
	"signingtrustack":     func(sm *interfaces.StorageManager) bool { return sm.GetSigningTrustAckStore() != nil },
	"moduleapproval":      func(sm *interfaces.StorageManager) bool { return sm.GetModuleApprovalStore() != nil },
	"ratecounter":         func(sm *interfaces.StorageManager) bool { return sm.GetRateCounterStore() != nil },
}

func storagemanagerwiringCharAssertSet(t *testing.T, sm *interfaces.StorageManager, set, unset []string) {
	t.Helper()
	for _, k := range set {
		assert.True(t, storagemanagerwiringCharIsSet[k](sm), "%s store must be set", k)
	}
	for _, k := range unset {
		assert.False(t, storagemanagerwiringCharIsSet[k](sm), "%s store must be nil", k)
	}
}

// storagemanagerwiringCharCase describes one store in a constructor: its key,
// the error-text fragment, whether business.ErrNotSupported is tolerated and
// which wrapped provider owns it (OSS only).
type storagemanagerwiringCharCase struct {
	key      string
	text     string
	tolerant bool
	flatfile bool
}

// storagemanagerwiringCharRunFailures drives the failure matrix: an
// ErrNotSupported injection and a generic-error injection per store.
func storagemanagerwiringCharRunFailures(t *testing.T, cases []storagemanagerwiringCharCase, build func(t *testing.T, c storagemanagerwiringCharCase, inject error) (*interfaces.StorageManager, error)) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.key+"/not-supported", func(t *testing.T) {
			sm, err := build(t, c, business.ErrNotSupported)
			if c.tolerant {
				require.NoError(t, err)
				require.NotNil(t, sm)
				t.Cleanup(func() { _ = sm.Close() })
				assert.False(t, storagemanagerwiringCharIsSet[c.key](sm), "declined store must leave the field nil")
				return
			}
			require.Error(t, err)
			assert.Nil(t, sm)
			assert.ErrorIs(t, err, business.ErrNotSupported)
			assert.Contains(t, err.Error(), c.text)
		})
		t.Run(c.key+"/error", func(t *testing.T) {
			sm, err := build(t, c, errStoragemanagerwiringCharInjected)
			require.Error(t, err)
			assert.Nil(t, sm)
			assert.ErrorIs(t, err, errStoragemanagerwiringCharInjected)
			assert.Contains(t, err.Error(), c.text)
		})
	}
}

func storagemanagerwiringCharAssertRoutingClosed(t *testing.T, p *storagemanagerwiringCharProvider) {
	t.Helper()
	require.NotNil(t, p.routing, "precondition: routing store must have been created before the injected failure")
	err := p.routing.RecordConnection(context.Background(), "steward-after-failed-construction", "node-1")
	assert.Error(t, err, "the routing store created before the failure must have been closed")
}

// ---- CreateClusterStorageManager ----

var storagemanagerwiringCharClusterCases = []storagemanagerwiringCharCase{
	{key: "config", text: "cluster storage: failed to create config store", tolerant: true},
	{key: "audit", text: "cluster storage: failed to create audit store"},
	{key: "rbac", text: "cluster storage: failed to create RBAC store"},
	{key: "tenant", text: "cluster storage: failed to create tenant store"},
	{key: "registrationtoken", text: "cluster storage: failed to create registration token store"},
	{key: "session", text: "cluster storage: failed to create session store", tolerant: true},
	{key: "steward", text: "cluster storage: failed to create steward store"},
	{key: "command", text: "cluster storage: failed to create command store", tolerant: true},
	{key: "trigger", text: "cluster storage: failed to create trigger store", tolerant: true},
	{key: "push", text: "cluster storage: failed to create push store", tolerant: true},
	{key: "iptrust", text: "cluster storage: failed to create IP trust store", tolerant: true},
	{key: "alert", text: "cluster storage: failed to create alert store", tolerant: true},
	{key: "approval", text: "cluster storage: failed to create approval store", tolerant: true},
	{key: "reporttemplate", text: "cluster storage: failed to create report template store", tolerant: true},
	{key: "workflowexecution", text: "cluster storage: failed to create workflow execution store", tolerant: true},
	{key: "pendingregistration", text: "cluster storage: failed to create pending registration store", tolerant: true},
	{key: "tenantcrossing", text: "cluster storage: failed to create tenant crossing store", tolerant: true},
	{key: "case", text: "cluster storage: failed to create case store", tolerant: true},
	{key: "nonce", text: "cluster storage: failed to create nonce store", tolerant: true},
	{key: "lease", text: "cluster storage: failed to create lease store", tolerant: true},
	{key: "routing", text: "cluster storage: failed to create routing store", tolerant: true},
	{key: "noderegistry", text: "cluster storage: failed to create node registry store", tolerant: true},
}

func storagemanagerwiringCharRegisterCluster(t *testing.T, failures map[string]error) *storagemanagerwiringCharProvider {
	t.Helper()
	withEmptyRegistry(t)
	p := storagemanagerwiringCharSQLite(t, "database", failures)
	interfaces.RegisterStorageProvider(p)
	return p
}

func TestStoragemanagerwiringChar_Cluster_HappyPathFieldWiring(t *testing.T) {
	p := storagemanagerwiringCharRegisterCluster(t, nil)

	sm, err := interfaces.CreateClusterStorageManager("postgres://unused", "hmac-key", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Equal(t, "database", sm.GetProviderName())
	assert.Same(t, interfaces.StorageProvider(p), sm.GetProvider())
	storagemanagerwiringCharAssertSet(t, sm,
		[]string{"audit", "rbac", "tenant", "registrationtoken", "session", "steward", "command",
			"trigger", "push", "pendingregistration", "approval", "reporttemplate",
			"workflowexecution", "tenantcrossing", "case", "nonce", "lease", "routing", "noderegistry"},
		// SQLite declines config, IP trust and alert stores, and does not implement
		// the remaining optional creators.
		[]string{"config", "iptrust", "alert", "refreshpolicy", "pendingrefresh", "assurancepolicy", "blastradiuspolicy", "scriptrun",
			"executionqueue", "certrevocation", "signingcursor", "signingtrustack", "moduleapproval", "ratecounter"})
}

func TestStoragemanagerwiringChar_Cluster_Preconditions(t *testing.T) {
	t.Run("empty connection string", func(t *testing.T) {
		sm, err := interfaces.CreateClusterStorageManager("", "hmac-key", nil)
		require.Error(t, err)
		assert.Nil(t, sm)
		assert.Contains(t, err.Error(), "cluster storage requires a Postgres connection string")
	})
	t.Run("database provider not registered", func(t *testing.T) {
		withEmptyRegistry(t)
		sm, err := interfaces.CreateClusterStorageManager("postgres://unused", "hmac-key", nil)
		require.Error(t, err)
		assert.Nil(t, sm)
		assert.Contains(t, err.Error(), "database provider not registered for cluster storage")
	})
}

func TestStoragemanagerwiringChar_Cluster_StoreFailures(t *testing.T) {
	storagemanagerwiringCharRunFailures(t, storagemanagerwiringCharClusterCases,
		func(t *testing.T, c storagemanagerwiringCharCase, inject error) (*interfaces.StorageManager, error) {
			storagemanagerwiringCharRegisterCluster(t, map[string]error{c.key: inject})
			return interfaces.CreateClusterStorageManager("postgres://unused", "hmac-key", nil)
		})
}

func TestStoragemanagerwiringChar_Cluster_ClosesEarlierStoresOnLaterFailure(t *testing.T) {
	p := storagemanagerwiringCharRegisterCluster(t, map[string]error{"noderegistry": errStoragemanagerwiringCharInjected})

	sm, err := interfaces.CreateClusterStorageManager("postgres://unused", "hmac-key", nil)
	require.Error(t, err)
	assert.Nil(t, sm)
	assert.Contains(t, err.Error(), "node registry store")
	storagemanagerwiringCharAssertRoutingClosed(t, p)
}

// ---- CreateOSSStorageManager ----

var storagemanagerwiringCharOSSCases = []storagemanagerwiringCharCase{
	{key: "config", text: "failed to create config store (flatfile)", flatfile: true},
	{key: "audit", text: "failed to create audit store (flatfile)", flatfile: true},
	{key: "steward", text: "failed to create steward store (flatfile)", flatfile: true},
	{key: "iptrust", text: "failed to create ip trust store (flatfile)", flatfile: true},
	{key: "alert", text: "failed to create alert store (flatfile)", flatfile: true},
	{key: "nonce", text: "failed to create nonce store (flatfile)", tolerant: true, flatfile: true},
	{key: "rbac", text: "failed to create RBAC store (sqlite)"},
	{key: "tenant", text: "failed to create tenant store (sqlite)"},
	{key: "registrationtoken", text: "failed to create registration token store (sqlite)"},
	{key: "session", text: "failed to create session store (sqlite)", tolerant: true},
	{key: "command", text: "failed to create command store (sqlite)", tolerant: true},
	{key: "trigger", text: "failed to create trigger store (sqlite)", tolerant: true},
	{key: "push", text: "failed to create push store (sqlite)", tolerant: true},
	{key: "pendingregistration", text: "failed to create pending registration store (sqlite)", tolerant: true},
	{key: "approval", text: "failed to create approval store (sqlite)", tolerant: true},
	{key: "workflowexecution", text: "failed to create workflow execution store (sqlite)", tolerant: true},
	{key: "reporttemplate", text: "failed to create report template store (sqlite)", tolerant: true},
	{key: "lease", text: "failed to create lease store (sqlite)", tolerant: true},
	{key: "routing", text: "failed to create routing store (sqlite)", tolerant: true},
	{key: "noderegistry", text: "failed to create node registry store (sqlite)", tolerant: true},
}

// storagemanagerwiringCharRegisterOSS registers a flat-file provider and a
// wrapped SQLite provider. The wrapper hides BusinessStoreOpener, so the OSS
// constructor takes its per-store fallback path.
func storagemanagerwiringCharRegisterOSS(t *testing.T, ffFailures, sqFailures map[string]error) (ff, sq *storagemanagerwiringCharProvider) {
	t.Helper()
	withEmptyRegistry(t)
	ff = storagemanagerwiringCharFlatfile(t, ffFailures)
	sq = storagemanagerwiringCharSQLite(t, "sqlite", sqFailures)
	interfaces.RegisterStorageProvider(ff)
	interfaces.RegisterStorageProvider(sq)
	return ff, sq
}

func TestStoragemanagerwiringChar_OSS_BundlePathFieldWiring(t *testing.T) {
	withEmptyRegistry(t)
	interfaces.RegisterStorageProvider(newFlatFileProvider())
	interfaces.RegisterStorageProvider(newSQLiteProvider())

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Equal(t, "composite", sm.GetProviderName())
	assert.Nil(t, sm.GetProvider())
	storagemanagerwiringCharAssertSet(t, sm,
		[]string{"config", "audit", "rbac", "tenant", "registrationtoken", "session", "steward", "command",
			"trigger", "push", "pendingregistration", "iptrust", "alert", "approval", "reporttemplate",
			"workflowexecution", "tenantcrossing", "case", "nonce", "lease", "refreshpolicy", "pendingrefresh",
			"assurancepolicy", "blastradiuspolicy"},
		[]string{"routing", "noderegistry", "scriptrun", "executionqueue", "certrevocation", "signingcursor",
			"signingtrustack", "moduleapproval", "ratecounter"})
}

func TestStoragemanagerwiringChar_OSS_FallbackPathFieldWiring(t *testing.T) {
	storagemanagerwiringCharRegisterOSS(t, nil, nil)

	sm, err := interfaces.CreateOSSStorageManager("unused", "unused")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Equal(t, "composite", sm.GetProviderName())
	storagemanagerwiringCharAssertSet(t, sm,
		[]string{"config", "audit", "rbac", "tenant", "registrationtoken", "session", "steward", "command",
			"trigger", "push", "pendingregistration", "iptrust", "alert", "approval", "reporttemplate",
			"workflowexecution", "nonce", "lease", "routing", "noderegistry"},
		// Only the bundle path wires these; the per-store fallback leaves them nil.
		[]string{"tenantcrossing", "case", "refreshpolicy", "pendingrefresh", "assurancepolicy",
			"blastradiuspolicy", "scriptrun", "executionqueue", "certrevocation", "signingcursor",
			"signingtrustack", "moduleapproval", "ratecounter"})
}

func TestStoragemanagerwiringChar_OSS_StoreFailures(t *testing.T) {
	storagemanagerwiringCharRunFailures(t, storagemanagerwiringCharOSSCases,
		func(t *testing.T, c storagemanagerwiringCharCase, inject error) (*interfaces.StorageManager, error) {
			failures := map[string]error{c.key: inject}
			if c.flatfile {
				storagemanagerwiringCharRegisterOSS(t, failures, nil)
			} else {
				storagemanagerwiringCharRegisterOSS(t, nil, failures)
			}
			return interfaces.CreateOSSStorageManager("unused", "unused")
		})
}

func TestStoragemanagerwiringChar_OSS_Preconditions(t *testing.T) {
	t.Run("flatfile provider not registered", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegisterStorageProvider(newSQLiteProvider())
		_, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "flatfile provider not registered")
	})
	t.Run("sqlite provider not registered", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegisterStorageProvider(newFlatFileProvider())
		_, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sqlite provider not registered")
	})
	t.Run("bundle open failure", func(t *testing.T) {
		withEmptyRegistry(t)
		interfaces.RegisterStorageProvider(newFlatFileProvider())
		interfaces.RegisterStorageProvider(&storagemanagerwiringCharBundleFailProvider{
			storagemanagerwiringCharSQLite(t, "sqlite", nil)})
		sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "test.db"))
		require.Error(t, err)
		assert.Nil(t, sm)
		assert.Contains(t, err.Error(), "failed to open SQLite business stores")
	})
}

func TestStoragemanagerwiringChar_OSS_ClosesEarlierStoresOnLaterFailure(t *testing.T) {
	_, sq := storagemanagerwiringCharRegisterOSS(t, nil, map[string]error{"noderegistry": errStoragemanagerwiringCharInjected})

	sm, err := interfaces.CreateOSSStorageManager("unused", "unused")
	require.Error(t, err)
	assert.Nil(t, sm)
	assert.Contains(t, err.Error(), "node registry store (sqlite)")
	storagemanagerwiringCharAssertRoutingClosed(t, sq)
}

// ---- CreateAllStoresFromConfig ----

var storagemanagerwiringCharAllCases = []storagemanagerwiringCharCase{
	{key: "config", text: "failed to create config store", tolerant: true},
	{key: "audit", text: "failed to create audit store", tolerant: true},
	{key: "rbac", text: "failed to create RBAC store", tolerant: true},
	{key: "tenant", text: "failed to create tenant store", tolerant: true},
	{key: "registrationtoken", text: "failed to create registration token store", tolerant: true},
	{key: "session", text: "failed to create session store", tolerant: true},
	{key: "steward", text: "failed to create steward store", tolerant: true},
	{key: "command", text: "failed to create command store", tolerant: true},
	{key: "trigger", text: "failed to create trigger store", tolerant: true},
	{key: "push", text: "failed to create push store", tolerant: true},
	{key: "iptrust", text: "failed to create IP trust store", tolerant: true},
	{key: "alert", text: "failed to create alert store", tolerant: true},
	{key: "approval", text: "failed to create approval store", tolerant: true},
	{key: "reporttemplate", text: "failed to create report template store", tolerant: true},
	{key: "workflowexecution", text: "failed to create workflow execution store", tolerant: true},
	{key: "nonce", text: "failed to create nonce store", tolerant: true},
	{key: "lease", text: "failed to create lease store", tolerant: true},
	{key: "routing", text: "failed to create routing store", tolerant: true},
	{key: "noderegistry", text: "failed to create node registry store", tolerant: true},
}

func storagemanagerwiringCharRegisterAll(t *testing.T, failures map[string]error) (*storagemanagerwiringCharProvider, map[string]interface{}) {
	t.Helper()
	withEmptyRegistry(t)
	p := storagemanagerwiringCharSQLite(t, "sqlite", failures)
	interfaces.RegisterStorageProvider(p)
	return p, p.cfg
}

func TestStoragemanagerwiringChar_All_HappyPathFieldWiring(t *testing.T) {
	p, cfg := storagemanagerwiringCharRegisterAll(t, nil)

	sm, err := interfaces.CreateAllStoresFromConfig("sqlite", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	assert.Equal(t, "sqlite", sm.GetProviderName())
	assert.Same(t, interfaces.StorageProvider(p), sm.GetProvider())
	storagemanagerwiringCharAssertSet(t, sm,
		[]string{"audit", "rbac", "tenant", "registrationtoken", "session", "steward", "command",
			"trigger", "push", "approval", "reporttemplate", "workflowexecution",
			"nonce", "lease", "routing", "noderegistry"},
		[]string{"config", "iptrust", "alert", "pendingregistration", "tenantcrossing", "case", "refreshpolicy", "pendingrefresh",
			"assurancepolicy", "blastradiuspolicy", "scriptrun", "executionqueue", "certrevocation",
			"signingcursor", "signingtrustack", "moduleapproval", "ratecounter"})
}

func TestStoragemanagerwiringChar_All_UnknownProvider(t *testing.T) {
	withEmptyRegistry(t)
	sm, err := interfaces.CreateAllStoresFromConfig("no-such-provider", nil)
	require.Error(t, err)
	assert.Nil(t, sm)
	assert.Contains(t, err.Error(), "storage provider 'no-such-provider' not available. Available providers:")
}

func TestStoragemanagerwiringChar_All_StoreFailures(t *testing.T) {
	storagemanagerwiringCharRunFailures(t, storagemanagerwiringCharAllCases,
		func(t *testing.T, c storagemanagerwiringCharCase, inject error) (*interfaces.StorageManager, error) {
			_, cfg := storagemanagerwiringCharRegisterAll(t, map[string]error{c.key: inject})
			return interfaces.CreateAllStoresFromConfig("sqlite", cfg)
		})
}
