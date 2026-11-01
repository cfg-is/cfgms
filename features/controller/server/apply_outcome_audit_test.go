// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// staticOutcomeSources is a fixed-fact implementation of applyOutcomeAuditSources:
// one registered steward with a declared cfg at one version, and the audit
// operations an approved manifest lists per bundle.
type staticOutcomeSources struct {
	stewardID string
	tenantID  string
	version   string
	resources []stewardtypes.ResourceConfig
	audited   map[string][]string
}

func (s staticOutcomeSources) DeclaredResources(_ context.Context, stewardID, version string) (string, []stewardtypes.ResourceConfig, error) {
	if stewardID != s.stewardID {
		return "", nil, fmt.Errorf("steward is not registered")
	}
	if version != s.version {
		return "", nil, fmt.Errorf("version %q is not served", version)
	}
	return s.tenantID, s.resources, nil
}

func (s staticOutcomeSources) AuditOperations(module string) ([]string, error) {
	return s.audited[module], nil
}

const (
	auditTestSteward = "steward-ad-1"
	auditTestTenant  = "root/acme-corp/hq"
	auditTestVersion = "v7"
)

func newOutcomeAuditServer(t *testing.T) (*Server, business.AuditStore, *audit.Manager) {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetAuditStore()
	mgr, err := audit.NewManager(store, "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	s := &Server{
		auditManager: mgr,
		logger:       logging.NewNoopLogger(),
		outcomeAuditSources: staticOutcomeSources{
			stewardID: auditTestSteward,
			tenantID:  auditTestTenant,
			version:   auditTestVersion,
			resources: []stewardtypes.ResourceConfig{
				{Name: "alice-user", Module: "activedirectory.user", Config: map[string]interface{}{"password": "p@ss"}},
				{Name: "ops-group", Module: "activedirectory.group"},
			},
			audited: map[string][]string{
				"activedirectory.user":  {"create_user", "set_user_enabled"},
				"activedirectory.group": {"add_group_member"},
			},
		},
	}
	return s, store, mgr
}

func outcomeDetails(t *testing.T, recs ...controlplaneTypes.ApplyOutcomeRecord) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"config_version": auditTestVersion, "apply_outcomes": recs})
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func auditedEntries(t *testing.T, store business.AuditStore, mgr *audit.Manager) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, mgr.Flush(context.Background()))
	entries, err := store.ListAuditEntries(context.Background(), &business.AuditFilter{TenantID: auditTestTenant})
	require.NoError(t, err)
	return entries
}

func TestAuditApplyOutcome_UsesDeclaredResourceID(t *testing.T) {
	s, store, mgr := newOutcomeAuditServer(t)
	details := outcomeDetails(t, controlplaneTypes.ApplyOutcomeRecord{
		ResourceID: "alice-user", ModuleName: "activedirectory.user", Status: "applied",
		Operation: "create_user", Changed: true,
	})

	require.NoError(t, s.ingestApplyOutcomes(context.Background(), auditTestSteward, auditTestVersion, details))

	entries := auditedEntries(t, store, mgr)
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, auditTestTenant, e.TenantID)
	assert.Equal(t, "activedirectory.user", e.ResourceType)
	assert.Equal(t, "alice-user", e.ResourceID)
	assert.Equal(t, "create_user", e.Action)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, auditTestSteward, e.UserID)
}

func TestAuditApplyOutcome_UnchangedOutcomeIsNotAudited(t *testing.T) {
	s, store, mgr := newOutcomeAuditServer(t)
	details := outcomeDetails(t,
		controlplaneTypes.ApplyOutcomeRecord{ResourceID: "alice-user", ModuleName: "activedirectory.user", Status: "applied"},
		controlplaneTypes.ApplyOutcomeRecord{ResourceID: "alice-user", ModuleName: "activedirectory.user", Status: "applied", Operation: "create_user"},
		// Changed, but not in the manifest's audit list.
		controlplaneTypes.ApplyOutcomeRecord{ResourceID: "alice-user", ModuleName: "activedirectory.user", Status: "applied", Operation: "read_user", Changed: true},
	)

	require.NoError(t, s.ingestApplyOutcomes(context.Background(), auditTestSteward, auditTestVersion, details))

	assert.Empty(t, auditedEntries(t, store, mgr))
}

func TestAuditApplyOutcome_ResourceNotInStewardsOwnCfgDropped(t *testing.T) {
	s, store, mgr := newOutcomeAuditServer(t)
	forged := func(id, module string) controlplaneTypes.ApplyOutcomeRecord {
		return controlplaneTypes.ApplyOutcomeRecord{
			ResourceID: id, ModuleName: module, Status: "applied", Operation: "create_user", Changed: true,
		}
	}

	// A resource id the steward never declared, and a declared id under another module.
	details := outcomeDetails(t, forged("someone-elses-user", "activedirectory.user"), forged("ops-group", "activedirectory.user"))
	require.NoError(t, s.ingestApplyOutcomes(context.Background(), auditTestSteward, auditTestVersion, details))
	assert.Empty(t, auditedEntries(t, store, mgr))

	// A cfg version the controller does not serve for this steward drops the report.
	details = outcomeDetails(t, forged("alice-user", "activedirectory.user"))
	require.NoError(t, s.ingestApplyOutcomes(context.Background(), auditTestSteward, "v1", details))
	assert.Empty(t, auditedEntries(t, store, mgr))

	// An unregistered steward cannot audit under anyone's cfg.
	require.NoError(t, s.ingestApplyOutcomes(context.Background(), "steward-unknown", auditTestVersion, details))
	assert.Empty(t, auditedEntries(t, store, mgr))
}

func TestAuditApplyOutcome_NoSecretInDetails(t *testing.T) {
	s, store, mgr := newOutcomeAuditServer(t)
	details := outcomeDetails(t, controlplaneTypes.ApplyOutcomeRecord{
		ResourceID: "alice-user", ModuleName: "activedirectory.user", Status: "failed",
		Error: "password p@ss rejected", Operation: "create_user", Changed: true,
	})

	require.NoError(t, s.ingestApplyOutcomes(context.Background(), auditTestSteward, auditTestVersion, details))

	entries := auditedEntries(t, store, mgr)
	require.Len(t, entries, 1)
	assert.Equal(t, business.AuditResultFailure, entries[0].Result)
	raw, err := json.Marshal(entries[0])
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "p@ss")
	assert.NotContains(t, string(raw), "password")
	assert.ElementsMatch(t, []string{"module", "config_version", "status"}, keysOf(entries[0].Details))
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
