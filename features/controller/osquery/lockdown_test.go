// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/osquery"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestQuerySteward_TamperedStewardIsOperatorOnly: OsqueryQuery is a request the
// controller originates, so for a tampered steward it runs only when ctx carries
// the operator-origin marker (Issue #5666).
func TestQuerySteward_TamperedStewardIsOperatorOnly(t *testing.T) {
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	for id, st := range map[string]business.StewardStatus{
		"steward-tampered": business.StewardStatusTampered,
		"steward-normal":   business.StewardStatusActive,
	} {
		require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
			ID: id, TenantID: "tenant-a", Hostname: id, Platform: "linux", Status: st,
			RegisteredAt: time.Now(), LastSeen: time.Now(),
		}))
	}
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null").
		WithLockdown(fleet.NewLockdown(store, logging.NewNoopLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	params := map[string]string{"path": "/etc/os-release"}

	tampered, stopTampered := startStewardStream(t, h, "steward-tampered")
	defer stopTampered()

	// Without the marker: refused, nothing reaches the endpoint.
	_, err := h.QuerySteward(ctx, "steward-tampered", "file_info", params)
	require.ErrorIs(t, err, controlplaneInterfaces.ErrStewardLockedDown)
	select {
	case <-tampered.sent:
		t.Fatal("a refused query must not reach the steward")
	default:
	}

	// With the marker: allowed.
	go func() {
		req := <-tampered.sent
		tampered.incoming <- &transportpb.OsqueryQueryResponse{StewardId: req.GetStewardId(), CatalogId: req.GetCatalogId()}
	}()
	opCtx := controlplaneInterfaces.WithOperatorOrigin(ctx, "operator-1")
	_, err = h.QuerySteward(opCtx, "steward-tampered", "file_info", params)
	require.NoError(t, err)

	// A normal steward needs no marker.
	normal, stopNormal := startStewardStream(t, h, "steward-normal")
	defer stopNormal()
	go func() {
		req := <-normal.sent
		normal.incoming <- &transportpb.OsqueryQueryResponse{StewardId: req.GetStewardId(), CatalogId: req.GetCatalogId()}
	}()
	_, err = h.QuerySteward(ctx, "steward-normal", "file_info", params)
	assert.NoError(t, err)
}
