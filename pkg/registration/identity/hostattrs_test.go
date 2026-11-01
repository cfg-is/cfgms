// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/registration"
)

func TestCollectHostAttributes_NoDNAKeys_StableAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	first := CollectHostAttributes(dir)
	second := CollectHostAttributes(dir)
	assert.Equal(t, first, second)

	allowed := map[string]bool{HostAttrMachineID: true, HostAttrNICMACs: true, HostAttrDiskSerials: true, HostAttrInstallDate: true}
	for k := range first {
		assert.False(t, registration.DNAFieldKeys[k], "DNA key %q must never be collected", k)
		assert.True(t, allowed[k], "unexpected key %q", k)
	}
}

func TestCollectHostAttributes_InstallDateFromIdentityFile(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	attrs := CollectHostAttributes(dir)
	d, ok := attrs[HostAttrInstallDate]
	require.True(t, ok)
	_, err = time.Parse(time.DateOnly, d)
	require.NoError(t, err)
}

func TestCollectHostAttributes_NoIdentityFile_OmitsInstallDate(t *testing.T) {
	attrs := CollectHostAttributes(t.TempDir())
	_, ok := attrs[HostAttrInstallDate]
	assert.False(t, ok, "an unreadable attribute is omitted, never fabricated")
}

func TestCollectHostAttributes_ListsSortedAndCommaJoined(t *testing.T) {
	attrs := CollectHostAttributes(t.TempDir())
	for _, key := range []string{HostAttrNICMACs, HostAttrDiskSerials} {
		v, ok := attrs[key]
		if !ok {
			continue
		}
		parts := strings.Split(v, ",")
		assert.True(t, sort.StringsAreSorted(parts), "%s must be sorted: %q", key, v)
	}
}

func TestNormalizeList(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, normalizeList([]string{" b", "a", "b", "", "x,y"}))
}
