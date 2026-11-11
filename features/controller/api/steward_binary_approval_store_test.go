// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// newTestStewardBinaryApprovalStore opens a durable flatfile-backed approval store
// rooted at a per-test temporary directory.
func newTestStewardBinaryApprovalStore(t *testing.T) (*StewardBinaryApprovalStore, cfgconfig.ConfigStore) {
	t.Helper()
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), "file:binary-approval-"+strconv.FormatInt(time.Now().UnixNano(), 10)+"?mode=memory")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	st, err := NewStewardBinaryApprovalStore(sm.GetConfigStore())
	require.NoError(t, err)
	return st, sm.GetConfigStore()
}

// wireTestStewardBinaryApprovalStore gives srv a durable approval store.
func wireTestStewardBinaryApprovalStore(t *testing.T, srv *Server) *StewardBinaryApprovalStore {
	t.Helper()
	st, _ := newTestStewardBinaryApprovalStore(t)
	srv.SetStewardBinaryApprovalStore(st)
	return st
}

func hexSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestNewStewardBinaryApprovalStoreRequiresConfigStore(t *testing.T) {
	_, err := NewStewardBinaryApprovalStore(nil)
	assert.Error(t, err)
}

// TestApprovalStoreKeepsFirstRecord: approving the same bytes again keeps the first
// record, including under concurrent writers; a different hash is a separate record.
func TestApprovalStoreKeepsFirstRecord(t *testing.T) {
	st, cs := newTestStewardBinaryApprovalStore(t)
	ctx := context.Background()
	sha := hexSHA256([]byte("binary"))
	first := StewardBinaryApproval{
		TenantID: "default", Version: "v1.0.0", Platform: "linux", Arch: "amd64",
		SHA256: sha, ApprovedBy: "alice", ApprovedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	got, created, err := st.Put(ctx, first)
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, "alice", got.ApprovedBy)

	second := first
	second.ApprovedBy = "bob"
	second.ApprovedAt = first.ApprovedAt.Add(time.Hour)
	got, created, err = st.Put(ctx, second)
	require.NoError(t, err)
	assert.False(t, created, "the same key is not created twice")
	assert.Equal(t, "alice", got.ApprovedBy)
	assert.True(t, first.ApprovedAt.Equal(got.ApprovedAt))

	stored, err := st.Get(ctx, "default", "v1.0.0", "linux", "amd64", sha)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "alice", stored.ApprovedBy)

	// Each coordinate is part of the key.
	for name, miss := range map[string][5]string{
		"tenant":   {"other", "v1.0.0", "linux", "amd64", sha},
		"version":  {"default", "v1.0.1", "linux", "amd64", sha},
		"platform": {"default", "v1.0.0", "darwin", "amd64", sha},
		"arch":     {"default", "v1.0.0", "linux", "arm64", sha},
		"sha":      {"default", "v1.0.0", "linux", "amd64", hexSHA256([]byte("other"))},
	} {
		rec, err := st.Get(ctx, miss[0], miss[1], miss[2], miss[3], miss[4])
		require.NoError(t, err, name)
		assert.Nil(t, rec, "a record for another %s must not match", name)
	}
	entries, err := cs.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: "default", Namespace: stewardBinaryApprovalNamespace})
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	// Concurrent first approvals leave exactly one winner and every caller sees it.
	concurrent := first
	concurrent.SHA256 = hexSHA256([]byte("concurrent"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := map[string]int{}
	createdCount := 0
	for _, who := range []string{"a", "b", "c", "d", "e", "f"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			rec := concurrent
			rec.ApprovedBy = who
			got, created, err := st.Put(ctx, rec)
			mu.Lock()
			defer mu.Unlock()
			if assert.NoError(t, err) {
				winners[got.ApprovedBy]++
				if created {
					createdCount++
				}
			}
		}(who)
	}
	wg.Wait()
	assert.Equal(t, 1, createdCount, "exactly one writer creates the record")
	assert.Len(t, winners, 1, "every caller reads back the same first approver")
}

func TestApprovalStorePutValidation(t *testing.T) {
	st, _ := newTestStewardBinaryApprovalStore(t)
	ctx := context.Background()
	ok := StewardBinaryApproval{TenantID: "default", Version: "v1.0.0", Platform: "linux", Arch: "amd64", SHA256: hexSHA256([]byte("x")), ApprovedBy: "alice"}
	for name, mutate := range map[string]func(*StewardBinaryApproval){
		"tenant":   func(a *StewardBinaryApproval) { a.TenantID = "" },
		"version":  func(a *StewardBinaryApproval) { a.Version = "" },
		"platform": func(a *StewardBinaryApproval) { a.Platform = "" },
		"arch":     func(a *StewardBinaryApproval) { a.Arch = "" },
		"sha":      func(a *StewardBinaryApproval) { a.SHA256 = "" },
		"approver": func(a *StewardBinaryApproval) { a.ApprovedBy = "" },
	} {
		bad := ok
		mutate(&bad)
		_, _, err := st.Put(ctx, bad)
		assert.Error(t, err, "missing %s must be refused", name)
	}
	rec, err := st.Get(ctx, "default", "v1.0.0", "linux", "", ok.SHA256)
	require.NoError(t, err)
	assert.Nil(t, rec, "an incomplete lookup matches nothing")
}

// TestApprovalStoreRejectsMisfiledRecord: a record stored under another binary's key
// never satisfies a lookup, because the decoded tuple is re-checked.
func TestApprovalStoreRejectsMisfiledRecord(t *testing.T) {
	st, cs := newTestStewardBinaryApprovalStore(t)
	ctx := context.Background()
	l := stewardBinaryApprovalLookup{tenant: "default", version: "v1.0.0", platform: "linux", arch: "amd64", sha256: hexSHA256([]byte("x"))}
	forged := `{"tenant_id":"default","version":"v9.9.9","platform":"linux","arch":"amd64","sha256":"` + l.sha256 + `","approved_by":"mallory"}`
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: stewardBinaryApprovalKey(l), Data: []byte(forged), Format: cfgconfig.ConfigFormatJSON,
		Checksum: hexSHA256([]byte(forged)), UpdatedAt: time.Now().UTC(), UpdatedBy: "mallory", Source: "test",
	}))
	rec, err := st.Get(ctx, l.tenant, l.version, l.platform, l.arch, l.sha256)
	require.NoError(t, err)
	assert.Nil(t, rec)

	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: stewardBinaryApprovalKey(l), Data: []byte("not json"), Format: cfgconfig.ConfigFormatJSON,
		Checksum: hexSHA256([]byte("not json")), UpdatedAt: time.Now().UTC(), UpdatedBy: "x", Source: "test",
	}))
	_, err = st.Get(ctx, l.tenant, l.version, l.platform, l.arch, l.sha256)
	assert.Error(t, err, "an undecodable record is an error, never approved")
}

// TestApprovalStoreFailsClosedWhenUnset: with no store wired, the read and the write
// helpers return an error and never report approved.
func TestApprovalStoreFailsClosedWhenUnset(t *testing.T) {
	srv := setupTestServer(t)
	require.Nil(t, srv.StewardBinaryApprovalStore())
	sha := hexSHA256([]byte("x"))
	approved, err := srv.stewardBinaryApproved(context.Background(), "default", "v1.0.0", "linux", "amd64", sha)
	assert.ErrorIs(t, err, errStewardBinaryApprovalUnavailable)
	assert.False(t, approved)
	created, err := srv.approveStewardBinary(context.Background(), "default", "v1.0.0", "linux", "amd64", sha, "alice")
	assert.ErrorIs(t, err, errStewardBinaryApprovalUnavailable)
	assert.False(t, created)
}

// TestStewardBinaryApprovalNamespace_OnlyStoreWrites names the writers of the
// approval namespace: steward_binary_approval_store.go is the only file that names
// it, no registered route addresses it, and the store writes to it.
func TestStewardBinaryApprovalNamespace_OnlyStoreWrites(t *testing.T) {
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
		assert.NotContains(t, p, stewardBinaryApprovalNamespace, "route %s must not address the namespace", p)
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
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil && v == stewardBinaryApprovalNamespace {
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
	assert.Equal(t, []string{"features/controller/api/steward_binary_approval_store.go"}, names)

	// Every non-test caller of the store's writer is the one server helper.
	callers := map[string]bool{}
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
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewStewardBinaryApprovalStore" {
						callers[filepath.ToSlash(rel)] = true
					}
				}
				return true
			})
			return nil
		}))
	}
	assert.Equal(t, map[string]bool{"features/controller/server/server.go": true}, callers,
		"only controller startup constructs the store")

	st, cs := newTestStewardBinaryApprovalStore(t)
	_, _, err := st.Put(context.Background(), StewardBinaryApproval{
		TenantID: "default", Version: "v1.0.0", Platform: "linux", Arch: "amd64", SHA256: hexSHA256([]byte("x")), ApprovedBy: "alice",
	})
	require.NoError(t, err)
	entries, err := cs.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "default", Namespace: stewardBinaryApprovalNamespace})
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// casConfigStore is a real flatfile store that also offers CompareAndSwapConfig, so
// the store takes its conditional create path. When rival is set the call loses to a
// rival approval committed first, as a second controller node would.
type casConfigStore struct {
	cfgconfig.ConfigStore
	rival *StewardBinaryApproval
	calls int
	gotV  int64
}

func (c *casConfigStore) CompareAndSwapConfig(ctx context.Context, e *cfgconfig.ConfigEntry, expected int64) (int64, bool, error) {
	c.calls++
	c.gotV = expected
	if c.rival != nil {
		data, err := json.Marshal(c.rival)
		if err != nil {
			return 0, false, err
		}
		if err := c.StoreConfig(ctx, &cfgconfig.ConfigEntry{Key: e.Key, Data: data, Format: cfgconfig.ConfigFormatJSON, Checksum: hexSHA256(data), UpdatedAt: time.Now().UTC(), UpdatedBy: c.rival.ApprovedBy, Source: "rival"}); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	return 1, true, c.StoreConfig(ctx, e)
}

// TestApprovalStoreUsesConditionalCreate: with a ConditionalConfigStore the record is
// created with expected version 0, and losing that create leaves the rival's record.
func TestApprovalStoreUsesConditionalCreate(t *testing.T) {
	_, base := newTestStewardBinaryApprovalStore(t)
	ctx := context.Background()
	sha := hexSHA256([]byte("cas"))
	mine := StewardBinaryApproval{TenantID: "default", Version: "v1.0.0", Platform: "linux", Arch: "amd64", SHA256: sha, ApprovedBy: "mine"}

	winning := &casConfigStore{ConfigStore: base}
	st, err := NewStewardBinaryApprovalStore(winning)
	require.NoError(t, err)
	got, created, err := st.Put(ctx, mine)
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, "mine", got.ApprovedBy)
	assert.Equal(t, 1, winning.calls)
	assert.EqualValues(t, 0, winning.gotV, "create-if-absent means expected version 0")

	rival := mine
	rival.Version = "v1.0.1"
	rivalRec := rival
	rivalRec.ApprovedBy = "rival"
	losing := &casConfigStore{ConfigStore: base, rival: &rivalRec}
	st, err = NewStewardBinaryApprovalStore(losing)
	require.NoError(t, err)
	got, created, err = st.Put(ctx, rival)
	require.NoError(t, err)
	assert.False(t, created, "losing the conditional create is not a creation")
	assert.Equal(t, "rival", got.ApprovedBy, "the record that won stays")
}
