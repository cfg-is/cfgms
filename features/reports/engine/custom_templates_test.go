// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenant tree: root -> msp-a (a1, a2), msp-b (b1)
var testParents = map[string]string{
	"msp-a": "root", "msp-b": "root",
	"a1": "msp-a", "a2": "msp-a", "b1": "msp-b",
}

func testScope(_ context.Context, owner, target string) (bool, error) {
	if target == "" || target == owner {
		return false, nil
	}
	if _, ok := testParents[target]; !ok {
		return false, nil
	}
	msp := func(t string) string {
		for testParents[t] != "root" && testParents[t] != "" {
			t = testParents[t]
		}
		return t
	}
	if _, ok := testParents[owner]; !ok {
		return false, nil // root owner cannot share into an MSP
	}
	return msp(owner) == msp(target), nil
}

type fixture struct {
	m     *CustomTemplateManager
	store business.ReportTemplateStore
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := newTestReportTemplateStore(t)
	f := &fixture{store: store, now: time.Now().UTC().Truncate(time.Second)}
	var err error
	f.m, err = NewCustomTemplateManager(store, func() time.Time { return f.now }, testScope)
	require.NoError(t, err)
	return f
}

func tmpl(tenant string) *interfaces.CustomReportTemplate {
	return &interfaces.CustomReportTemplate{
		Name: "t", TenantID: tenant, CreatedBy: "u",
		Query:      interfaces.CustomQuery{DataSources: []string{"dna"}},
		Parameters: []interfaces.CustomParameter{{Name: "p", Type: "string"}},
	}
}

func (f *fixture) save(t *testing.T, tenant string) *interfaces.CustomReportTemplate {
	t.Helper()
	saved, err := f.m.SaveTemplate(context.Background(), tmpl(tenant))
	require.NoError(t, err)
	return saved
}

func TestNewCustomTemplateManager_RequiresDependencies(t *testing.T) {
	f := newFixture(t)
	clock := func() time.Time { return f.now }
	_, err := NewCustomTemplateManager(nil, clock, testScope)
	assert.Error(t, err)
	_, err = NewCustomTemplateManager(f.store, nil, testScope)
	assert.Error(t, err)
	_, err = NewCustomTemplateManager(f.store, clock, nil)
	assert.Error(t, err)
}

func TestCustomTemplateManager_EmptyTenantRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	_, err := f.m.SaveTemplate(ctx, tmpl(""))
	assert.Error(t, err)
	_, err = f.m.GetTemplate(ctx, saved.ID, "")
	assert.Error(t, err)
	_, err = f.m.GetAccessibleTemplates(ctx, "")
	assert.Error(t, err)
	assert.Error(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read"}}))
	assert.Error(t, f.m.DeleteTemplate(ctx, saved.ID, ""))
}

func TestCustomTemplateManager_SaveTemplate_ValidTemplate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	assert.NotEmpty(t, saved.ID)
	assert.Equal(t, "a1", saved.TenantID)
	assert.Equal(t, f.now, saved.CreatedAt)
	assert.Equal(t, f.now, saved.UpdatedAt)

	got, err := f.m.GetTemplate(ctx, saved.ID, "a1")
	require.NoError(t, err)
	assert.Equal(t, []string{"dna"}, got.Query.DataSources)
	require.Len(t, got.Parameters, 1)
	assert.Equal(t, "p", got.Parameters[0].Name)

	// Owner update preserves creation time.
	f.now = f.now.Add(time.Hour)
	got.Name = "renamed"
	updated, err := f.m.SaveTemplate(ctx, got)
	require.NoError(t, err)
	assert.Equal(t, saved.CreatedAt, updated.CreatedAt)
	assert.Equal(t, f.now, updated.UpdatedAt)
	assert.Equal(t, "renamed", updated.Name)
}

func TestCustomTemplateManager_SaveTemplate_Validation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	bad := tmpl("a1")
	bad.Name = ""
	_, err := f.m.SaveTemplate(ctx, bad)
	assert.Error(t, err)

	bad = tmpl("a1")
	bad.Query.DataSources = nil
	_, err = f.m.SaveTemplate(ctx, bad)
	assert.Error(t, err)

	bad = tmpl("a1")
	bad.Parameters = make([]interfaces.CustomParameter, interfaces.DefaultCustomReportConfig().MaxParameters+1)
	_, err = f.m.SaveTemplate(ctx, bad)
	assert.Error(t, err)
}

func TestCustomTemplateManager_NonOwnerCannotOverwriteOrDelete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read", "modify"},
	}))

	over := tmpl("a2")
	over.ID = saved.ID
	over.Name = "hijack"
	_, err := f.m.SaveTemplate(ctx, over)
	assert.ErrorIs(t, err, interfaces.ErrTemplateAccessDenied)

	assert.ErrorIs(t, f.m.DeleteTemplate(ctx, saved.ID, "a2"), interfaces.ErrTemplateAccessDenied)
	got, err := f.m.GetTemplate(ctx, saved.ID, "a1")
	require.NoError(t, err)
	assert.Equal(t, "t", got.Name)

	// Unrelated tenant gets not found, not a hint the template exists.
	_, err = f.m.GetTemplate(ctx, saved.ID, "b1")
	assert.ErrorIs(t, err, interfaces.ErrTemplateNotFound)
	_, err = f.m.GetTemplate(ctx, "missing", "a1")
	assert.ErrorIs(t, err, interfaces.ErrTemplateNotFound)

	require.NoError(t, f.m.DeleteTemplate(ctx, saved.ID, "a1"))
	_, err = f.m.GetTemplate(ctx, saved.ID, "a1")
	assert.ErrorIs(t, err, interfaces.ErrTemplateNotFound)
}

func TestCustomTemplateManager_GetAccessibleTemplates_RespectsTenantIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")

	list, err := f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	assert.Empty(t, list)

	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read"},
	}))
	list, err = f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, saved.ID, list[0].ID)

	owned, err := f.m.GetAccessibleTemplates(ctx, "a1")
	require.NoError(t, err)
	assert.Len(t, owned, 1)

	_, err = f.m.GetAccessibleTemplates(ctx, "")
	assert.Error(t, err)
}

func TestCustomTemplateManager_ShareTemplate_ValidPermissions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	exp := f.now.Add(time.Hour)
	req := interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"},
		Permissions: []string{"read", "execute", "modify"}, SharedBy: "alice", ExpiresAt: &exp,
	}
	require.NoError(t, f.m.ShareTemplate(ctx, req))
	got, err := f.m.GetTemplate(ctx, saved.ID, "a1")
	require.NoError(t, err)
	require.Len(t, got.SharedWith, 1)
	assert.Equal(t, "alice", got.SharedWith[0].SharedBy)
	assert.Equal(t, exp, *got.SharedWith[0].ExpiresAt)

	bad := req
	bad.Permissions = []string{"admin"}
	assert.Error(t, f.m.ShareTemplate(ctx, bad))

	nonOwner := req
	nonOwner.TenantID = "a2"
	nonOwner.SharedWithTenants = []string{"a1"}
	assert.ErrorIs(t, f.m.ShareTemplate(ctx, nonOwner), interfaces.ErrTemplateAccessDenied)
}

func TestCustomTemplateManager_ShareWithoutReadDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"execute"},
	}))
	_, err := f.m.GetTemplate(ctx, saved.ID, "a2")
	assert.ErrorIs(t, err, interfaces.ErrTemplateAccessDenied)
}

func TestCustomTemplateManager_ShareWithoutReadNotListed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"execute", "modify"},
	}))
	list, err := f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	assert.Empty(t, list, "a share without read must not expose the template through the list")

	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read"},
	}))
	list, err = f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, saved.ID, list[0].ID)
}

func TestCustomTemplateManager_ExpiredShareGrantsNothing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	exp := f.now.Add(time.Hour)
	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read"}, ExpiresAt: &exp,
	}))
	_, err := f.m.GetTemplate(ctx, saved.ID, "a2")
	require.NoError(t, err)

	f.now = exp.Add(time.Second)
	_, err = f.m.GetTemplate(ctx, saved.ID, "a2")
	assert.Error(t, err)
	list, err := f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestCustomTemplateManager_SharedWithRedactedForNonOwner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	// a2 and a3 are both in msp-a's subtree for this test.
	testParents["a3"] = "msp-a"
	t.Cleanup(func() { delete(testParents, "a3") })
	require.NoError(t, f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2", "a3"}, Permissions: []string{"read"},
	}))

	got, err := f.m.GetTemplate(ctx, saved.ID, "a2")
	require.NoError(t, err)
	require.Len(t, got.SharedWith, 1)
	assert.Equal(t, "a2", got.SharedWith[0].TenantID)

	list, err := f.m.GetAccessibleTemplates(ctx, "a2")
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Len(t, list[0].SharedWith, 1)
	assert.Equal(t, "a2", list[0].SharedWith[0].TenantID)

	owner, err := f.m.GetTemplate(ctx, saved.ID, "a1")
	require.NoError(t, err)
	assert.Len(t, owner.SharedWith, 2)

	// Stored record is untouched by redaction.
	rec, err := f.store.GetByID(ctx, "a1", saved.ID)
	require.NoError(t, err)
	assert.Len(t, rec.SharedWith, 2)
}

func TestCustomTemplateManager_ShareTargetScope(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	saved := f.save(t, "a1")
	share := func(targets ...string) error {
		return f.m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
			TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: targets, Permissions: []string{"read"},
		})
	}
	otherMSP := share("b1")
	missing := share("ghost")
	require.ErrorIs(t, otherMSP, interfaces.ErrShareTargetInvalid)
	require.ErrorIs(t, missing, interfaces.ErrShareTargetInvalid)
	assert.Equal(t, otherMSP.Error(), missing.Error())
	assert.NotContains(t, otherMSP.Error(), "b1")
	assert.ErrorIs(t, share(""), interfaces.ErrShareTargetInvalid)
	assert.ErrorIs(t, share("a1"), interfaces.ErrShareTargetInvalid)
	// One bad target refuses the whole request.
	assert.ErrorIs(t, share("a2", "b1"), interfaces.ErrShareTargetInvalid)

	rec, err := f.store.GetByID(ctx, "a1", saved.ID)
	require.NoError(t, err)
	assert.Empty(t, rec.SharedWith, "refused targets write no share")

	// A scope function that errors denies.
	m, err := NewCustomTemplateManager(f.store, func() time.Time { return f.now },
		func(context.Context, string, string) (bool, error) { return true, errors.New("boom") })
	require.NoError(t, err)
	err = m.ShareTemplate(ctx, interfaces.ShareTemplateRequest{
		TenantID: "a1", TemplateID: saved.ID, SharedWithTenants: []string{"a2"}, Permissions: []string{"read"},
	})
	assert.ErrorIs(t, err, interfaces.ErrShareTargetInvalid)
	rec, err = f.store.GetByID(ctx, "a1", saved.ID)
	require.NoError(t, err)
	assert.Empty(t, rec.SharedWith)
}

func TestCustomTemplateManager_RootOwnerCannotShareIntoMSP(t *testing.T) {
	f := newFixture(t)
	saved := f.save(t, "root")
	err := f.m.ShareTemplate(context.Background(), interfaces.ShareTemplateRequest{
		TenantID: "root", TemplateID: saved.ID, SharedWithTenants: []string{"msp-a"}, Permissions: []string{"read"},
	})
	assert.ErrorIs(t, err, interfaces.ErrShareTargetInvalid)
}
