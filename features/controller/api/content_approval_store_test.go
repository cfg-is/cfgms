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

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// openApprovalStore opens a durable flatfile-backed store rooted at root.
func openApprovalStore(t *testing.T, root string) (*ContentApprovalStore, cfgconfig.ConfigStore, func()) {
	t.Helper()
	sm, err := interfaces.CreateOSSStorageManager(root, "file:approval-"+strconv.FormatInt(time.Now().UnixNano(), 10)+"?mode=memory")
	require.NoError(t, err)
	st, err := NewContentApprovalStore(sm.GetConfigStore())
	require.NoError(t, err)
	return st, sm.GetConfigStore(), func() { _ = sm.Close() }
}

func newApprovalStore(t *testing.T) (*ContentApprovalStore, cfgconfig.ConfigStore) {
	t.Helper()
	st, cs, closeFn := openApprovalStore(t, t.TempDir())
	t.Cleanup(closeFn)
	return st, cs
}

func scriptFixture() *script.VersionedScript {
	return &script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID: "s1", Version: &script.Version{Major: 1}, Shell: script.ShellBash,
			Timeout:    time.Minute,
			Parameters: []script.ScriptParameter{{Name: "p", Type: "string", AllowedValues: []string{"a"}}},
		},
		Content: "echo", Hash: "content-hash",
	}
}

func TestContentApprovalStore_GetModeDefaultsToSigned(t *testing.T) {
	st, _ := newApprovalStore(t)
	for _, k := range []LibraryKind{LibraryKindScript, LibraryKindWorkflow} {
		m, err := st.GetMode(context.Background(), "msp", k)
		require.NoError(t, err)
		assert.Equal(t, ApprovalModeSigned, m)
	}
	assert.Equal(t, ApprovalModeSigned, ApprovalMode("").Effective())
}

func TestContentApprovalStore_SetModeValidation(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	for _, bad := range []ApprovalMode{"", "none", "Signed", "off", "approve "} {
		assert.Error(t, st.SetMode(ctx, "msp", LibraryKindScript, bad, "alice"), "mode %q", bad)
	}
	assert.Error(t, st.SetMode(ctx, "msp", "bogus", ApprovalModeApprove, "alice"))
	assert.Error(t, st.SetMode(ctx, "msp", LibraryKindScript, ApprovalModeApprove, ""))
	m, err := st.GetMode(ctx, "msp", LibraryKindScript)
	require.NoError(t, err)
	assert.Equal(t, ApprovalModeSigned, m, "rejected writes must not change the mode")
}

func TestContentApprovalStore_ModePerTenantPerKindNotInherited(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	require.NoError(t, st.SetMode(ctx, "msp", LibraryKindScript, ApprovalModeComment, "alice"))
	m, err := st.GetMode(ctx, "msp", LibraryKindScript)
	require.NoError(t, err)
	assert.Equal(t, ApprovalModeComment, m)
	for _, c := range []struct {
		tenant string
		kind   LibraryKind
	}{{"msp/client-1", LibraryKindScript}, {"client-1", LibraryKindScript}, {"msp", LibraryKindWorkflow}} {
		m, err := st.GetMode(ctx, c.tenant, c.kind)
		require.NoError(t, err)
		assert.Equal(t, ApprovalModeSigned, m, "%s/%s", c.tenant, c.kind)
	}
}

func TestContentApprovalStore_SetModeKeepsPrevious(t *testing.T) {
	st, cs := newApprovalStore(t)
	ctx := context.Background()
	require.NoError(t, st.SetMode(ctx, "msp", LibraryKindScript, ApprovalModeApprove, "alice"))
	require.NoError(t, st.SetMode(ctx, "msp", LibraryKindScript, ApprovalModeComment, "bob"))
	e, err := cs.GetConfig(ctx, modeKey("msp", LibraryKindScript))
	require.NoError(t, err)
	assert.Contains(t, string(e.Data), `"previous_mode":"approve"`)
	assert.Contains(t, string(e.Data), `"set_by":"bob"`)
}

func TestContentApprovalStore_InvalidStoredModeIsError(t *testing.T) {
	st, cs := newApprovalStore(t)
	ctx := context.Background()
	for _, raw := range []string{"comments", "", "SIGNED"} {
		data := []byte(`{"tenant_id":"msp","kind":"script","mode":"` + raw + `"}`)
		require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
			Key: modeKey("msp", LibraryKindScript), Data: data, Format: cfgconfig.ConfigFormatJSON, Checksum: "x",
		}))
		m, err := st.GetMode(ctx, "msp", LibraryKindScript)
		require.Error(t, err, "stored mode %q", raw)
		assert.NotEqual(t, ApprovalModeComment, m)
		assert.Empty(t, string(m))
	}
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: modeKey("msp", LibraryKindScript), Data: []byte(`{not json`), Format: cfgconfig.ConfigFormatJSON, Checksum: "x",
	}))
	_, err := st.GetMode(ctx, "msp", LibraryKindScript)
	require.Error(t, err)
}

// approvalReadFailStore returns a non-"not found" error from every read.
type approvalReadFailStore struct {
	cfgconfig.ConfigStore
}

func (approvalReadFailStore) GetConfig(context.Context, *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, errors.New("backend unavailable")
}

func TestContentApprovalStore_ReadErrorIsNotSignedDefault(t *testing.T) {
	_, cs := newApprovalStore(t)
	st, err := NewContentApprovalStore(approvalReadFailStore{cs})
	require.NoError(t, err)
	ctx := context.Background()

	m, err := st.GetMode(ctx, "msp", LibraryKindScript)
	require.Error(t, err)
	assert.Empty(t, string(m))

	a, err := st.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", "h")
	require.Error(t, err)
	assert.Nil(t, a)

	require.Error(t, st.PutApproval(ctx, ContentApproval{
		TenantID: "msp", Kind: LibraryKindScript, ContentID: "s1", Version: "1.0.0",
		ContentHash: "h", ApprovedBy: "alice", Method: ApprovalMethodApproveTap,
	}))
}

func approvalFor(owner, hash string) ContentApproval {
	return ContentApproval{
		TenantID: owner, Kind: LibraryKindScript, ContentID: "s1", Version: "1.0.0",
		ContentHash: hash, ApprovedBy: "alice", Method: ApprovalMethodApproveTap,
	}
}

func TestContentApprovalStore_GetApprovalRequiresIDVersionHash(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	require.NoError(t, st.PutApproval(ctx, approvalFor("msp", "H1")))

	got, err := st.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", "H1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "alice", got.ApprovedBy)
	assert.False(t, got.ApprovedAt.IsZero())

	for name, args := range map[string][5]string{
		"other hash":    {"msp", "script", "s1", "1.0.0", "H2"},
		"other version": {"msp", "script", "s1", "1.0.1", "H1"},
		"other id":      {"msp", "script", "s2", "1.0.0", "H1"},
		"other kind":    {"msp", "workflow", "s1", "1.0.0", "H1"},
		"other tenant":  {"client-1", "script", "s1", "1.0.0", "H1"},
	} {
		got, err := st.GetApproval(ctx, args[0], LibraryKind(args[1]), args[2], args[3], args[4])
		require.NoError(t, err, name)
		assert.Nil(t, got, name)
	}
}

func TestContentApprovalStore_ApprovalForH1DoesNotSatisfyH2(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	require.NoError(t, st.PutApproval(ctx, approvalFor("msp", "H1")))
	got, err := st.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", "H2")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestContentApprovalStore_OwnerTenantNotInterchangeable(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	vs := scriptFixture() // identical content hash for both owners
	mspHash := script.ScriptApprovalHash("msp", vs)
	clientHash := script.ScriptApprovalHash("client-1", vs)
	require.NotEqual(t, mspHash, clientHash)

	a := approvalFor("msp", mspHash)
	require.NoError(t, st.PutApproval(ctx, a))

	// A lookup resolved to owner client-1 carries client-1's approval hash.
	got, err := st.GetApproval(ctx, "client-1", LibraryKindScript, "s1", "1.0.0", clientHash)
	require.NoError(t, err)
	assert.Nil(t, got)
	// Presenting MSP's hash under client-1 does not match either.
	got, err = st.GetApproval(ctx, "client-1", LibraryKindScript, "s1", "1.0.0", mspHash)
	require.NoError(t, err)
	assert.Nil(t, got)

	// A record misfiled under another owner's key still does not match.
	b, err := st.store.GetConfig(ctx, approvalKey("msp", LibraryKindScript, "s1", "1.0.0", mspHash))
	require.NoError(t, err)
	require.NoError(t, st.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  approvalKey("client-1", LibraryKindScript, "s1", "1.0.0", mspHash),
		Data: b.Data, Format: cfgconfig.ConfigFormatJSON, Checksum: b.Checksum,
	}))
	got, err = st.GetApproval(ctx, "client-1", LibraryKindScript, "s1", "1.0.0", mspHash)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Workflow hashes bind the owner the same way.
	assert.NotEqual(t, WorkflowApprovalHash("msp", "w", "1", "c"), WorkflowApprovalHash("client-1", "w", "1", "c"))
}

func TestContentApprovalStore_ApprovalHashFieldsGateLookup(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	vs := scriptFixture()
	require.NoError(t, st.PutApproval(ctx, approvalFor("msp", script.ScriptApprovalHash("msp", vs))))

	vs.Metadata.Parameters[0].AllowedValues = []string{"a", "b"}
	got, err := st.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", script.ScriptApprovalHash("msp", vs))
	require.NoError(t, err)
	assert.Nil(t, got, "a changed parameter schema needs a fresh approval")
}

func TestContentApprovalStore_PutApprovalValidationAndImmutability(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	bad := []ContentApproval{
		{}, approvalFor("", "h"), approvalFor("msp", ""),
	}
	noMethod := approvalFor("msp", "h")
	noMethod.Method = "tap"
	badKind := approvalFor("msp", "h")
	badKind.Kind = "x"
	noApprover := approvalFor("msp", "h")
	noApprover.ApprovedBy = ""
	bad = append(bad, noMethod, badKind, noApprover)
	for i, a := range bad {
		assert.Error(t, st.PutApproval(ctx, a), "case %d", i)
	}

	first := approvalFor("msp", "H1")
	require.NoError(t, st.PutApproval(ctx, first))
	second := first
	second.ApprovedBy = "mallory"
	require.NoError(t, st.PutApproval(ctx, second))
	got, err := st.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", "H1")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.ApprovedBy)
}

func TestContentApprovalStore_ListApprovals(t *testing.T) {
	st, _ := newApprovalStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	for i, h := range []string{"H1", "H2"} {
		a := approvalFor("msp", h)
		a.ApprovedAt = base.Add(time.Duration(i) * time.Second)
		require.NoError(t, st.PutApproval(ctx, a))
	}
	wf := approvalFor("msp", "W1")
	wf.Kind = LibraryKindWorkflow
	wf.Method = ApprovalMethodWorkflowPublish
	require.NoError(t, st.PutApproval(ctx, wf))
	require.NoError(t, st.PutApproval(ctx, approvalFor("client-1", "H1")))

	list, err := st.ListApprovals(ctx, "msp", LibraryKindScript)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "H1", list[0].ContentHash)
	assert.Equal(t, "H2", list[1].ContentHash)

	_, err = st.ListApprovals(ctx, "", LibraryKindScript)
	assert.Error(t, err)
}

func TestContentApprovalStore_PersistsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	st, _, closeFn := openApprovalStore(t, root)
	require.NoError(t, st.SetMode(ctx, "msp", LibraryKindWorkflow, ApprovalModeApprove, "alice"))
	require.NoError(t, st.PutApproval(ctx, approvalFor("msp", "H1")))
	closeFn()

	st2, _, closeFn2 := openApprovalStore(t, root)
	defer closeFn2()
	m, err := st2.GetMode(ctx, "msp", LibraryKindWorkflow)
	require.NoError(t, err)
	assert.Equal(t, ApprovalModeApprove, m)
	got, err := st2.GetApproval(ctx, "msp", LibraryKindScript, "s1", "1.0.0", "H1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "alice", got.ApprovedBy)
}

// protectedApprovalNamespaces are the namespaces only ContentApprovalStore may
// write.
func protectedApprovalNamespaces() []string {
	return []string{contentApprovalNamespace, contentApprovalModeNamespace, contentPublicationNamespace}
}

// TestContentApprovalNamespaces_OnlyStoreWrites enumerates every registered
// route and every sync entry point and names the writers of the approval, mode
// and publication namespaces: content_approval_store.go is the only one.
func TestContentApprovalNamespaces_OnlyStoreWrites(t *testing.T) {
	protected := protectedApprovalNamespaces()

	// 1. No registered route addresses a protected namespace.
	srv := setupTestServer(t)
	var routes []string
	require.NoError(t, srv.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if p, err := r.GetPathTemplate(); err == nil {
			routes = append(routes, p)
		}
		return nil
	}))
	require.NotEmpty(t, routes, "route enumeration must see the registered routes")
	for _, p := range routes {
		for _, ns := range protected {
			assert.NotContains(t, p, ns, "route %s must not address a protected namespace", p)
		}
	}

	// 2. Scan non-test product source for the namespaces and for sync entry
	// points that write arbitrary namespaces.
	root := filepath.Join("..", "..", "..")
	syncEntryPoints := map[string]bool{"AddBinding": true, "TriggerSync": true, "TriggerWebhookSync": true}
	nsWriters := map[string]bool{}
	syncCallers := map[string]bool{}
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
			rel = filepath.ToSlash(rel)
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if v, uerr := strconv.Unquote(x.Value); uerr == nil {
							for _, ns := range protected {
								if v == ns {
									nsWriters[rel] = true
								}
							}
						}
					}
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && syncEntryPoints[sel.Sel.Name] && !strings.HasPrefix(rel, "pkg/gitsync/") {
						syncCallers[rel] = true
					}
				}
				return true
			})
			return nil
		}))
	}
	var writers []string
	for w := range nsWriters {
		writers = append(writers, w)
	}
	sort.Strings(writers)
	// The only file that names a protected namespace is the store; the
	// constants carry the names, so any other writer would have to repeat them.
	assert.Equal(t, []string{"features/controller/api/content_approval_store.go"}, writers)

	// The git sync entry points write caller-chosen namespaces. No code outside
	// pkg/gitsync reaches them today; a new caller must add a reserved-namespace
	// guard before it is allowed here.
	assert.Empty(t, syncCallers, "git sync entry points must have no caller until protected namespaces are guarded")

	// 3. The constants are the namespaces the store writes to.
	st, cs := newApprovalStore(t)
	ctx := context.Background()
	require.NoError(t, st.SetMode(ctx, "msp", LibraryKindScript, ApprovalModeApprove, "alice"))
	require.NoError(t, st.PutApproval(ctx, approvalFor("msp", "H1")))
	for _, ns := range []string{contentApprovalNamespace, contentApprovalModeNamespace} {
		entries, err := cs.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: "msp", Namespace: ns})
		require.NoError(t, err)
		assert.Len(t, entries, 1, ns)
	}
}
