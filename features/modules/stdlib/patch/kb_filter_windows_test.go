// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package patch

import (
	"testing"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kbStringCollection returns a Windows Update string collection, the type of
// an update's KBArticleIDs property, holding ids.
func kbStringCollection(t *testing.T, ids ...string) *ole.IDispatch {
	t.Helper()
	unknown, err := oleutil.CreateObject("Microsoft.Update.StringColl")
	require.NoError(t, err)
	coll, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	require.NoError(t, err)
	t.Cleanup(func() { coll.Release() })
	for _, id := range ids {
		_, err := oleutil.CallMethod(coll, "Add", id)
		require.NoError(t, err)
	}
	return coll
}

func TestReadKBArticleIDs_ReadsEveryStringEntry(t *testing.T) {
	w, err := NewWindowsUpdateManager() // initialises COM on this thread
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })

	ids, err := readKBArticleIDs(kbStringCollection(t, "5000001", "5000002", "5000003"))
	require.NoError(t, err)
	assert.Equal(t, []string{"KB5000001", "KB5000002", "KB5000003"}, ids)
}

func TestShouldIncludeUpdate_ExcludedKBInLaterPositionOfRealCollection(t *testing.T) {
	w, err := NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	coll := kbStringCollection(t, "5000001", "5000002")

	assert.False(t, w.shouldIncludeUpdate(coll, &Config{ExcludePatches: []string{"KB5000002"}}))
	assert.True(t, w.shouldIncludeUpdate(coll, &Config{IncludePatches: []string{"KB5000002"}}))
	assert.False(t, w.shouldIncludeUpdate(kbStringCollection(t), &Config{IncludePatches: []string{"KB5000002"}}))
	assert.True(t, w.shouldIncludeUpdate(kbStringCollection(t), &Config{}))
}
