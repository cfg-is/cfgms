// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

func newUnattendedRolloutStore(t *testing.T) (*UnattendedRolloutStore, cfgconfig.ConfigStore) {
	t.Helper()
	_, cs := newApprovalStore(t)
	st, err := NewUnattendedRolloutStore(cs)
	require.NoError(t, err)
	return st, cs
}

func TestUnattendedRolloutDefaultOff(t *testing.T) {
	st, _ := newUnattendedRolloutStore(t)

	got, err := st.Get(context.Background())
	require.NoError(t, err)
	assert.False(t, got.Enabled, "a cell with no stored record is off")
	assert.Empty(t, got.ChangedBy)
	assert.Nil(t, got.ChangedAt)

	_, err = NewUnattendedRolloutStore(nil)
	assert.Error(t, err, "a store needs a config store")
	_, err = st.Set(context.Background(), true, "")
	assert.Error(t, err, "a change needs an actor")
	got, err = st.Get(context.Background())
	require.NoError(t, err)
	assert.False(t, got.Enabled, "a rejected change stores nothing")
}

func TestUnattendedRolloutSetPersistsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	_, cs, closeFn := openApprovalStore(t, root)
	st, err := NewUnattendedRolloutStore(cs)
	require.NoError(t, err)
	set, err := st.Set(ctx, true, "alice")
	require.NoError(t, err)
	assert.True(t, set.Enabled)
	closeFn()

	_, cs2, closeFn2 := openApprovalStore(t, root)
	defer closeFn2()
	st2, err := NewUnattendedRolloutStore(cs2)
	require.NoError(t, err)
	got, err := st2.Get(ctx)
	require.NoError(t, err)
	assert.True(t, got.Enabled)
	assert.Equal(t, "alice", got.ChangedBy)
	require.NotNil(t, got.ChangedAt)
	assert.WithinDuration(t, time.Now(), *got.ChangedAt, time.Minute)

	// Turning it off is stored too, and replaces the actor.
	_, err = st2.Set(ctx, false, "bob")
	require.NoError(t, err)
	got, err = st2.Get(ctx)
	require.NoError(t, err)
	assert.False(t, got.Enabled)
	assert.Equal(t, "bob", got.ChangedBy)
}

type unattendedReadFailStore struct{ cfgconfig.ConfigStore }

func (unattendedReadFailStore) GetConfig(context.Context, *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, errors.New("read failed")
}

// TestUnattendedRolloutUnreadableSettingIsErrorNotDefault: a failing or corrupt
// store must never read as off (or on).
func TestUnattendedRolloutUnreadableSettingIsErrorNotDefault(t *testing.T) {
	_, cs := newApprovalStore(t)
	failing, err := NewUnattendedRolloutStore(unattendedReadFailStore{cs})
	require.NoError(t, err)
	_, err = failing.Get(context.Background())
	assert.Error(t, err)

	st, err := NewUnattendedRolloutStore(cs)
	require.NoError(t, err)
	require.NoError(t, cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key: unattendedRolloutKey(), Data: []byte("not json"), Format: cfgconfig.ConfigFormatJSON,
		Checksum: "x", UpdatedAt: time.Now().UTC(), UpdatedBy: "test", Source: "test",
	}))
	_, err = st.Get(context.Background())
	assert.Error(t, err)
}

// TestUnattendedRolloutNamespaceOnlyStoreWrites names the writers of the
// unattended rollout namespace: unattended_rollout_store.go is the only one, and
// no registered route addresses it.
func TestUnattendedRolloutNamespaceOnlyStoreWrites(t *testing.T) {
	srv := setupTestServer(t)
	var routes []string
	require.NoError(t, srv.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if p, err := r.GetPathTemplate(); err == nil {
			routes = append(routes, p)
		}
		return nil
	}))
	require.NotEmpty(t, routes)
	for _, p := range routes {
		assert.NotContains(t, p, unattendedRolloutNamespace, "route %s must not address the namespace", p)
	}

	root := filepath.Join("..", "..", "..")
	writers := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"features", "pkg", "cmd"} {
		require.NoError(t, filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil && v == unattendedRolloutNamespace {
						writers[filepath.ToSlash(rel)] = true
					}
				}
				return true
			})
			return nil
		}))
	}
	var names []string
	for w := range writers {
		names = append(names, w)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"features/controller/api/unattended_rollout_store.go"}, names)

	// The constant is the namespace the store writes to.
	st, cs := newUnattendedRolloutStore(t)
	_, err := st.Set(context.Background(), true, "alice")
	require.NoError(t, err)
	entries, err := cs.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: unattendedRolloutTenant, Namespace: unattendedRolloutNamespace})
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
