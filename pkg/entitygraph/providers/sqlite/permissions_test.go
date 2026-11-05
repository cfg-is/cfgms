// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

func TestEntityGraphSQLite_CreatesOwnerOnly(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "eg.db")
	p, err := NewSQLiteEntityGraphProvider(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	eid := mustEID(t, "host:perm01")
	require.NoError(t, p.ReportObservations(context.Background(), interfaces.ObservationBatch{
		Source: "enforcing-module:file",
		Observations: []types.Observation{
			obs(eid.String(), "enforcing-module:file", types.ObservationKindState, time.Now().UTC(), map[string]interface{}{
				"entity_kind": "host", "owning_tenant": "root/msp-a/client-1", "hostname": "web01",
			}),
		},
	}))

	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(dbPath + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err, suffix)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "eg.db%s", suffix)
	}
}
