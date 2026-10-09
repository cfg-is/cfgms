// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
)

func TestFileSigningTrustAckStore_SurvivesReconstruction(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	first, err := cert.NewFileSigningTrustAckStore(dir)
	require.NoError(t, err)
	require.NoError(t, first.RecordAck(ctx, "steward-1", "serial-a"))
	recorded, err := first.GetAck(ctx, "steward-1", "serial-a")
	require.NoError(t, err)

	second, err := cert.NewFileSigningTrustAckStore(dir)
	require.NoError(t, err)
	got, err := second.GetAck(ctx, "steward-1", "serial-a")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, recorded.AcknowledgedAt.Equal(got.AcknowledgedAt))

	info, err := os.Stat(filepath.Join(dir, "signing-trust-acks.json"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		// Windows does not report Unix permission bits.
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestFileSigningTrustAckStore_RejectsEmptyBasePath(t *testing.T) {
	_, err := cert.NewFileSigningTrustAckStore("")
	assert.Error(t, err)
}

func TestFileSigningTrustAckStore_CorruptFileSurfacesError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "signing-trust-acks.json"), []byte("{not json"), 0600))
	store, err := cert.NewFileSigningTrustAckStore(dir)
	require.NoError(t, err)
	assert.Error(t, store.RecordAck(context.Background(), "steward-1", "serial-a"))
	_, err = store.ListAcked(context.Background(), "serial-a")
	assert.Error(t, err)
}
