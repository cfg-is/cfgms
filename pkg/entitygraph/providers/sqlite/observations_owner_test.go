// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func reportAs(t *testing.T, p *SQLiteEntityGraphProvider, peer, subject string, payload map[string]interface{}) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source:            peer,
		AuthenticatedPeer: peer,
		Observations: []types.Observation{{
			Source: peer, ObservedAt: now, RecordedAt: now, Subject: subject,
			Kind: types.ObservationKindState, Confidence: types.ConfidenceHigh, Payload: payload,
		}},
	}))
}

func TestDirectoryEntity_ExistingSubjectOtherTenant_WriteRejected(t *testing.T) {
	p := newTestProviderWithResolver(t, staticTenantResolver{"dc-a": "root/tenant-a", "dc-b": "root/tenant-b"})
	var got []interfaces.OwnerConflict
	p.SetOwnerConflictObserver(func(_ context.Context, c interfaces.OwnerConflict) { got = append(got, c) })

	for _, subject := range []string{"directory:corp.example.com/user:u1", "m365:tenant-x/user:u1"} {
		reportAs(t, p, "dc-a", subject, map[string]interface{}{"marker": "original"})
		reportAs(t, p, "dc-b", subject, map[string]interface{}{"marker": "hijack"})

		view, err := p.GetEntity(context.Background(), mustEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/tenant-a"})
		require.NoError(t, err)
		assert.Equal(t, "root/tenant-a", view.Entity.OwningTenant)
		assert.Equal(t, "original", view.Entity.Attributes["marker"])
	}

	require.Len(t, got, 2)
	assert.Equal(t, "root/tenant-a", got[0].ExistingTenant)
	assert.Equal(t, "root/tenant-b", got[0].AttemptedTenant)

	// An unresolvable peer (empty tenant) cannot take over an owned subject either.
	reportAs(t, p, "dc-unknown", "directory:corp.example.com/user:u1", map[string]interface{}{"marker": "anon"})
	view, err := p.GetEntity(context.Background(), mustEID(t, "directory:corp.example.com/user:u1"), interfaces.GetEntityOpts{TenantFilter: "root/tenant-a"})
	require.NoError(t, err)
	assert.Equal(t, "original", view.Entity.Attributes["marker"])
}

func TestDirectoryEntity_NotVisibleToOtherTenant(t *testing.T) {
	p := newTestProviderWithResolver(t, staticTenantResolver{"dc-a": "root/tenant-a", "dc-b": "root/tenant-b"})
	const subject = "directory:corp.example.com/group:g1"
	reportAs(t, p, "dc-a", subject, map[string]interface{}{"marker": "secret"})
	reportAs(t, p, "dc-b", subject, map[string]interface{}{"marker": "hijack"})

	if v, err := p.GetEntity(context.Background(), mustEID(t, subject), interfaces.GetEntityOpts{TenantFilter: "root/tenant-b"}); err == nil {
		assert.Nil(t, v, "another tenant must not see the directory entity")
	}
	page, err := p.QueryEntities(context.Background(), interfaces.EntityFilter{TenantFilter: "root/tenant-b"}, interfaces.PageToken{})
	require.NoError(t, err)
	assert.Empty(t, page.Entities)
}

func TestDirectoryEntity_HostOwnershipStillMoves(t *testing.T) {
	p := newTestProviderWithResolver(t, staticTenantResolver{"s": "root/tenant-a"})
	reportAs(t, p, "s", "host:s/file:x", map[string]interface{}{"marker": "1"})
	p.tenantResolver = staticTenantResolver{"s": "root/tenant-b"} // steward moved
	reportAs(t, p, "s", "host:s/file:x", map[string]interface{}{"marker": "2"})
	view, err := p.GetEntity(context.Background(), mustEID(t, "host:s/file:x"), interfaces.GetEntityOpts{TenantFilter: "root/tenant-b"})
	require.NoError(t, err)
	assert.Equal(t, "root/tenant-b", view.Entity.OwningTenant)
}
