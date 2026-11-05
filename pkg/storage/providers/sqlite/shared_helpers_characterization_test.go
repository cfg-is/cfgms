// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for logic shared with the database provider (Issue #5794).
// They pin the observable behaviour so moving the code into providers/internal does not
// change it.

func TestTicketMarshal_RoundTrip(t *testing.T) {
	in := makeCase("c", "t").Ticket
	s, err := marshalTicket(in)
	require.NoError(t, err)
	out, err := unmarshalTicket(s)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestTicketUnmarshal_EmptyAndInvalid(t *testing.T) {
	for _, s := range []string{"", "{}"} {
		out, err := unmarshalTicket(s)
		require.NoError(t, err)
		assert.Equal(t, business.Ticket{}, out)
	}
	_, err := unmarshalTicket("{not json")
	assert.Error(t, err)
}

func TestAssurancePolicy_GetPolicy_TenantScoping(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	ctx := context.Background()
	min := 3
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{TenantID: "a",
		Overrides: []business.AssurancePolicyOverride{{PermissionID: "p1", MinOverride: &min, RequireUserPresence: true}}}))
	require.NoError(t, store.SetPolicy(ctx, &business.AssurancePolicy{TenantID: "b",
		Overrides: []business.AssurancePolicyOverride{{PermissionID: "p2"}}}))

	a, err := store.GetPolicy(ctx, "a")
	require.NoError(t, err)
	require.Len(t, a.Overrides, 1)
	assert.Equal(t, "p1", a.Overrides[0].PermissionID)
	require.NotNil(t, a.Overrides[0].MinOverride)
	assert.Equal(t, 3, *a.Overrides[0].MinOverride)
	assert.True(t, a.Overrides[0].RequireUserPresence)

	b, err := store.GetPolicy(ctx, "b")
	require.NoError(t, err)
	require.Len(t, b.Overrides, 1)
	assert.Nil(t, b.Overrides[0].MinOverride)

	none, err := store.GetPolicy(ctx, "c")
	require.NoError(t, err)
	assert.Equal(t, "c", none.TenantID)
	assert.Nil(t, none.Overrides)
}

func TestAssurancePolicy_GetPolicy_ErrorString(t *testing.T) {
	store := newTestAssurancePolicyStore(t)
	require.NoError(t, store.db.Close())
	_, err := store.GetPolicy(context.Background(), "a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sqlite: failed to get assurance policy for tenant a: ")
}

func TestReportTemplate_Query_Visibility(t *testing.T) {
	st := newTestReportTemplateStoreAt(t, t.TempDir()+"/cfgms.db")
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	save := func(tenant, id string, shares ...business.ReportTemplateShare) {
		require.NoError(t, st.Save(ctx, tenant, &business.ReportTemplate{ID: id, TenantID: tenant, Name: id,
			CreatedAt: time.Now(), UpdatedAt: time.Now(), IsShared: len(shares) > 0, SharedWith: shares}))
	}
	save("owner", "z")
	save("owner", "a", business.ReportTemplateShare{TenantID: "rcpt", SharedAt: time.Now()})
	save("owner", "expired", business.ReportTemplateShare{TenantID: "rcpt", SharedAt: time.Now(), ExpiresAt: &past})

	owned, err := st.ListOwned(ctx, "owner")
	require.NoError(t, err)
	require.Len(t, owned, 3)
	assert.Equal(t, "a", owned[0].ID, "sorted by name")

	shared, err := st.ListSharedWith(ctx, "rcpt")
	require.NoError(t, err)
	require.Len(t, shared, 1, "expired share is hidden")
	assert.Equal(t, "a", shared[0].ID)
	assert.Len(t, shared[0].SharedWith, 1)

	empty, err := st.ListOwned(ctx, "nobody")
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty)
}

func TestReportTemplate_Query_ErrorString(t *testing.T) {
	st := newTestReportTemplateStoreAt(t, t.TempDir()+"/cfgms.db").(*SQLiteReportTemplateStore)
	require.NoError(t, st.db.Close())
	_, err := st.ListOwned(context.Background(), "owner")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sqlite: failed to list report templates: ")
}
