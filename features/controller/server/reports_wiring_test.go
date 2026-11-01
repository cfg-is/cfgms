// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	reportinterfaces "github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const reportsTestRoot = "root"

// newReportsTenantTree builds a real tenant hierarchy in real storage:
//
//	root ─┬─ msp-a ─┬─ client-1
//	      │         └─ client-2
//	      └─ msp-b ─── client-3
func newReportsTenantTree(t *testing.T) (context.Context, *interfaces.StorageManager) {
	t.Helper()
	ctx := ctxkeys.WithSystem(context.Background())
	sm := pkgtesting.SetupTestStorage(t)
	for _, tn := range []struct{ id, parent string }{
		{reportsTestRoot, ""},
		{"msp-a", reportsTestRoot},
		{"msp-b", reportsTestRoot},
		{"client-1", "msp-a"},
		{"client-2", "msp-a"},
		{"client-3", "msp-b"},
	} {
		require.NoError(t, sm.GetTenantStore().CreateTenant(ctx, &business.TenantData{
			ID: tn.id, Name: tn.id, ParentID: tn.parent, Status: business.TenantStatusActive,
		}))
	}
	return ctx, sm
}

func TestReportShareScope(t *testing.T) {
	ctx, sm := newReportsTenantTree(t)
	tenantPath := sm.GetTenantStore().GetTenantPath
	scope := reportShareScope(tenantPath, reportsTestRoot)

	cases := []struct {
		name          string
		owner, target string
		want          bool
	}{
		{"siblings under the same MSP are allowed", "client-1", "client-2", true},
		{"MSP to its own client is allowed", "msp-a", "client-1", true},
		{"client to its own MSP is allowed", "client-1", "msp-a", true},
		{"clients under different MSPs are denied", "client-1", "client-3", false},
		{"MSP to another MSP's client is denied", "msp-a", "client-3", false},
		{"MSP to another MSP is denied", "msp-a", "msp-b", false},
		{"root owner is denied", reportsTestRoot, "client-1", false},
		{"sharing to the root is denied (target path too short)", "client-1", reportsTestRoot, false},
		{"owner equal to target is denied", "client-1", "client-1", false},
		{"empty owner is denied", "", "client-1", false},
		{"empty target is denied", "client-1", "", false},
		{"unknown owner fails closed", "ghost", "client-1", false},
		{"unknown target fails closed", "client-1", "ghost", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scope(ctx, tc.owner, tc.target)
			require.NoError(t, err, "the scope reports denial, never an error")
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReportShareScope_FailsClosedWithoutRootOrResolver(t *testing.T) {
	ctx, sm := newReportsTenantTree(t)

	got, err := reportShareScope(sm.GetTenantStore().GetTenantPath, "")(ctx, "client-1", "client-2")
	require.NoError(t, err)
	assert.False(t, got, "an empty root tenant must deny every share")

	got, err = reportShareScope(nil, reportsTestRoot)(ctx, "client-1", "client-2")
	require.NoError(t, err)
	assert.False(t, got, "a nil tenant path resolver must deny every share")
}

// reportsWiringFixture holds the real components initializeReportsHandler consumes.
type reportsWiringFixture struct {
	ctx  context.Context
	sm   *interfaces.StorageManager
	eg   *egsqlite.SQLiteEntityGraphProvider
	ctrl *service.ControllerService
}

func newReportsWiringFixture(t *testing.T) *reportsWiringFixture {
	t.Helper()
	ctx, sm := newReportsTenantTree(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	eg, err := egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"), egsqlite.WithTenantResolver(ctrl))
	require.NoError(t, err)
	t.Cleanup(func() { _ = eg.Close() })
	return &reportsWiringFixture{ctx: ctx, sm: sm, eg: eg, ctrl: ctrl}
}

func (f *reportsWiringFixture) init(templateStore business.ReportTemplateStore, root string) (handlerNil bool, dp reportinterfaces.DataProvider, mgr reportinterfaces.CustomTemplateManager, builder reportinterfaces.CustomReportBuilder) {
	ts := f.sm.GetTenantStore()
	h, dp, mgr, builder := initializeReportsHandler(f.eg, f.ctrl, ts.IsTenantAncestor, f.sm.GetAlertStore(), templateStore, ts.GetTenantPath, root, logging.NewNoopLogger())
	return h == nil, dp, mgr, builder
}

func saveReportsTestTemplate(t *testing.T, ctx context.Context, mgr reportinterfaces.CustomTemplateManager, tenant string) string {
	t.Helper()
	saved, err := mgr.SaveTemplate(ctx, &reportinterfaces.CustomReportTemplate{
		TenantID: tenant,
		Name:     "wiring",
		Query:    reportinterfaces.CustomQuery{DataSources: []string{"dna"}},
	})
	require.NoError(t, err)
	return saved.ID
}

func TestInitializeReportsHandler_NilEntityGraphReturnsNothing(t *testing.T) {
	f := newReportsWiringFixture(t)
	h, dp, mgr, builder := initializeReportsHandler(nil, f.ctrl, f.sm.GetTenantStore().IsTenantAncestor, nil, f.sm.GetReportTemplateStore(), f.sm.GetTenantStore().GetTenantPath, reportsTestRoot, logging.NewNoopLogger())
	assert.Nil(t, h)
	assert.Nil(t, dp)
	assert.Nil(t, mgr)
	assert.Nil(t, builder)
}

func TestInitializeReportsHandler_FullWiringEnforcesShareScope(t *testing.T) {
	f := newReportsWiringFixture(t)
	store := f.sm.GetReportTemplateStore()
	require.NotNil(t, store)

	handlerNil, dp, mgr, builder := f.init(store, reportsTestRoot)
	require.False(t, handlerNil)
	require.NotNil(t, dp)
	require.NotNil(t, mgr, "a template store must yield a template manager")
	require.NotNil(t, builder, "a non-empty root must yield a report builder")

	id := saveReportsTestTemplate(t, f.ctx, mgr, "client-1")

	// The manager is wired with reportShareScope over the real tenant tree: a share
	// across MSPs is rejected, a share within the MSP is accepted and visible.
	err := mgr.ShareTemplate(f.ctx, reportinterfaces.ShareTemplateRequest{
		TenantID: "client-1", TemplateID: id, SharedWithTenants: []string{"client-3"}, Permissions: []string{"read"},
	})
	require.ErrorIs(t, err, reportinterfaces.ErrShareTargetInvalid)

	require.NoError(t, mgr.ShareTemplate(f.ctx, reportinterfaces.ShareTemplateRequest{
		TenantID: "client-1", TemplateID: id, SharedWithTenants: []string{"client-2"}, Permissions: []string{"read"},
	}))
	got, err := mgr.GetTemplate(f.ctx, id, "client-2")
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)

	_, err = mgr.GetTemplate(f.ctx, id, "client-3")
	require.Error(t, err, "a tenant outside the share must not see the template")
}

func TestInitializeReportsHandler_NilTemplateStoreGivesNilManager(t *testing.T) {
	f := newReportsWiringFixture(t)

	handlerNil, dp, mgr, builder := f.init(nil, reportsTestRoot)
	require.False(t, handlerNil, "the reports handler must still be built without a template store")
	assert.NotNil(t, dp)
	assert.Nil(t, mgr, "no template store means no template manager")
	assert.NotNil(t, builder, "the builder does not depend on the template store")
}

func TestInitializeReportsHandler_EmptyRootFailsClosed(t *testing.T) {
	f := newReportsWiringFixture(t)

	handlerNil, dp, mgr, builder := f.init(f.sm.GetReportTemplateStore(), "")
	require.False(t, handlerNil)
	assert.NotNil(t, dp)
	assert.Nil(t, builder, "builder construction must fail without a root tenant")
	require.NotNil(t, mgr)

	id := saveReportsTestTemplate(t, f.ctx, mgr, "client-1")
	err := mgr.ShareTemplate(f.ctx, reportinterfaces.ShareTemplateRequest{
		TenantID: "client-1", TemplateID: id, SharedWithTenants: []string{"client-2"}, Permissions: []string{"read"},
	})
	require.ErrorIs(t, err, reportinterfaces.ErrShareTargetInvalid, "an empty root must deny every share")
}
