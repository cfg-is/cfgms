// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
	migratestorage "github.com/cfgis/cfgms/pkg/storage/interfaces"

	storagepkg "github.com/cfgis/cfgms/pkg/migrate/storage"
)

// idsByKind groups exported record IDs per kind, preserving export order.
func idsByKind(recs []migrate.Record) map[string][]string {
	out := map[string][]string{}
	for _, r := range recs {
		out[r.Kind] = append(out[r.Kind], r.ID)
	}
	return out
}

// TestCharacterization_ExportImportRoundTripEveryType exports every kind from a
// populated manager, imports the records into an empty one and re-exports,
// asserting per-kind record counts and ordering are preserved.
func TestCharacterization_ExportImportRoundTripEveryType(t *testing.T) {
	ctx := context.Background()
	src := newOSSManager(t)
	seedOSSManager(t, src)
	dst := newOSSManager(t)

	srcRecs, err := storagepkg.ExportAllForTest(ctx, src)
	require.NoError(t, err)
	srcIDs := idsByKind(srcRecs)

	allKinds := []string{
		"tenant", "config", "audit",
		"rbac_permission", "rbac_role", "rbac_subject", "rbac_role_assignment",
		"registration_token", "session", "steward", "command", "trigger", "push",
		"ip_trust", "refresh_policy", "pending_refresh", "pending_registration",
	}
	for _, kind := range allKinds {
		assert.NotEmpty(t, srcIDs[kind], "seeded source must export kind %q", kind)
	}

	// A second export of the same source yields identical ordering.
	again, err := storagepkg.ExportAllForTest(ctx, src)
	require.NoError(t, err)
	assert.Equal(t, srcIDs, idsByKind(again), "export order must be deterministic")

	for _, rec := range srcRecs {
		require.NoError(t, storagepkg.ImportRecordForTest(ctx, dst, rec), "import %s/%s", rec.Kind, rec.ID)
	}

	dstRecs, err := storagepkg.ExportAllForTest(ctx, dst)
	require.NoError(t, err)
	dstIDs := idsByKind(dstRecs)
	for _, kind := range allKinds {
		assert.ElementsMatch(t, srcIDs[kind], dstIDs[kind], "kind %q IDs after round trip", kind)
		assert.Len(t, dstIDs[kind], len(srcIDs[kind]), "kind %q count after round trip", kind)
	}
}

// TestCharacterization_ImportStoreUnavailableText pins the per-kind error text
// returned when the destination lacks the store.
func TestCharacterization_ImportStoreUnavailableText(t *testing.T) {
	ctx := context.Background()
	mgr := migratestorage.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	cases := map[string]string{
		"rbac_permission":      "RBAC store not available",
		"rbac_role":            "RBAC store not available",
		"rbac_subject":         "RBAC store not available",
		"rbac_role_assignment": "RBAC store not available",
		"registration_token":   "registration token store not available",
		"session":              "session store not available",
		"steward":              "steward store not available",
		"command":              "command store not available",
		"trigger":              "trigger store not available in destination",
		"push":                 "push store not available in destination",
	}
	for kind, want := range cases {
		t.Run(kind, func(t *testing.T) {
			err := storagepkg.ImportRecordForTest(ctx, mgr, migrate.Record{Kind: kind, ID: "x", Data: []byte(`{}`)})
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

// TestCharacterization_ImportMalformedText pins the per-kind decode error text.
func TestCharacterization_ImportMalformedText(t *testing.T) {
	ctx := context.Background()
	mgr := newOSSManager(t)
	cases := map[string]string{
		"rbac_permission":      "unmarshal permission",
		"rbac_role":            "unmarshal role",
		"rbac_subject":         "unmarshal subject",
		"rbac_role_assignment": "unmarshal role assignment",
		"registration_token":   "unmarshal registration token",
		"session":              "unmarshal session",
		"steward":              "unmarshal steward",
		"command":              "unmarshal command",
		"trigger":              "unmarshal trigger",
		"push":                 "unmarshal push",
	}
	for kind, want := range cases {
		t.Run(kind, func(t *testing.T) {
			err := storagepkg.ImportRecordForTest(ctx, mgr, migrate.Record{Kind: kind, ID: "x", Data: []byte("{not json")})
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}
