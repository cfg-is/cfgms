// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerapi "github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const (
	dirTestAuthority = "directory:a.example"
	dirTestM365      = "m365:0f0e0d0c-0000-0000-0000-000000000001"
	dirTestTenant    = "root"
)

// dirCLIFixture runs the controller's real directory handlers (Issue #5557) behind an
// httptest server, with a real entity graph, a real membership store and a real
// root-scoped CLI session, and gives the CLI code an APIClient pointed at it.
type dirCLIFixture struct {
	t      *testing.T
	eg     *sqlite.SQLiteEntityGraphProvider
	mem    *directory.Membership
	client *APIClient
	clock  time.Time
}

func newDirCLIFixture(t *testing.T) *dirCLIFixture {
	t.Helper()

	base := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "controller-secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "data"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true")

	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	rbacManager := rbac.NewManagerWithStorage(sm.GetAuditStore(), sm.GetRBACStore())
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(ctx)
	})
	tenantManager := tenant.NewManager(tenant.NewStorageAdapter(sm.GetTenantStore()), rbacManager)
	_, err = tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: dirTestTenant})
	require.NoError(t, err)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, sm, controllerService)
	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	cfg := config.DefaultConfig()
	cfg.ExternalURL = "https://localhost:8080"
	cfg.Certificate.EnableCertManagement = false
	srv, err := controllerapi.New(cfg, logger, controllerService, configService, nil, service.NewRBACService(rbacManager),
		nil, tenantManager, rbacManager, nil, nil, nil, "", nil, auditMgr, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})

	eg, err := sqlite.NewSQLiteEntityGraphProvider(filepath.Join(base, "eg.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = eg.Close() })
	srv.SetEntityGraphProvider(eg)

	f := &dirCLIFixture{t: t, eg: eg, clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	mem, err := directory.NewMembership(sm.GetConfigStore(),
		dirCLIOwners{"a.example": dirTestTenant, "0f0e0d0c-0000-0000-0000-000000000001": dirTestTenant},
		directory.WithClock(func() time.Time { return f.clock }))
	require.NoError(t, err)
	srv.SetDirectoryMembershipStore(mem)
	f.mem = mem

	sessCfg := session.DefaultConfig()
	mgr := session.NewManager(sessCfg, session.NewMemStore(sessCfg, time.Now), time.Now)
	srv.SetSessionManager(mgr)
	_, token, err := mgr.IssueRootScoped(context.Background(), "directory-cli-test", "test", dirTestTenant)
	require.NoError(t, err)

	ts := httptest.NewServer(srv.GetRouter())
	t.Cleanup(ts.Close)
	f.client, err = NewAPIClient(&APIClientConfig{BaseURL: ts.URL, BearerToken: token})
	require.NoError(t, err)
	return f
}

type dirCLIOwners map[string]string

func (o dirCLIOwners) Owner(_ context.Context, domain string) (string, bool, error) {
	t, ok := o[domain]
	return t, ok, nil
}

func (f *dirCLIFixture) report(eid, kind string, attrs map[string]interface{}) {
	f.t.Helper()
	now := time.Now().UTC()
	payload := map[string]interface{}{"entity_kind": kind, "owning_tenant": dirTestTenant}
	for k, v := range attrs {
		payload[k] = v
	}
	require.NoError(f.t, f.eg.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:reporter",
		Observations: []egtypes.Observation{{
			Source: "test:reporter", ObservedAt: now, RecordedAt: now, Subject: eid,
			Kind: egtypes.ObservationKindState, Confidence: egtypes.ConfidenceHigh, Payload: payload,
		}},
	}), "report %s", eid)
}

func (f *dirCLIFixture) user(authority, id string, attrs map[string]interface{}) {
	f.t.Helper()
	f.report(authority+"/user:"+id, "user", attrs)
}

func (f *dirCLIFixture) group(authority, id string, attrs map[string]interface{}) {
	f.t.Helper()
	f.report(authority+"/group:"+id, "group", attrs)
}

func (f *dirCLIFixture) batch(ups ...directory.Fragment) {
	f.t.Helper()
	_, err := f.mem.ApplyBatch(context.Background(), "steward-1", dirTestAuthority, ups, nil)
	require.NoError(f.t, err)
}

func dirCLIUserFrag(id string, groups ...string) directory.Fragment {
	return directory.Fragment{Kind: egtypes.KindDirectoryUser, ObjectID: id, Attributes: map[string]any{"member_of": groups}}
}

// flags returns list flags with the defaults the commands register.
func dirFlags(mutate ...func(*directoryListFlags)) *directoryListFlags {
	f := &directoryListFlags{limit: 100, output: directoryOutputTable}
	for _, m := range mutate {
		m(f)
	}
	return f
}

func seedDirectory(f *dirCLIFixture) {
	f.user(dirTestAuthority, "alice", map[string]interface{}{
		"display_name": "Alice Smith", "sam_account_name": "alice", "user_principal_name": "alice@a.example",
		"mail": "alice@a.example", "description": "Engineer", "enabled": true, "managed": true,
	})
	f.user(dirTestAuthority, "bob", map[string]interface{}{"display_name": "Bob Jones", "enabled": false})
	f.user(dirTestM365, "carol", map[string]interface{}{"display_name": "Carol Cloud", "mail": "carol@cloud.example", "account_enabled": true})
	f.group(dirTestAuthority, "helpdesk", map[string]interface{}{"display_name": "Help Desk", "managed": true})
	f.group(dirTestM365, "cloud-admins", map[string]interface{}{"display_name": "Cloud Admins"})
}

func TestCfgDirectoryUserList_AgainstRealAPI(t *testing.T) {
	f := newDirCLIFixture(t)
	seedDirectory(f)
	ctx := context.Background()

	var out bytes.Buffer
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags()))
	table := out.String()
	for _, col := range []string{"SOURCE", "KIND", "ID", "AUTHORITY", "DISPLAY_NAME", "SAM_ACCOUNT_NAME",
		"USER_PRINCIPAL_NAME", "MAIL", "DESCRIPTION", "ENABLED", "MANAGED", "LAST_OBSERVED", "STALE"} {
		assert.Contains(t, table, col)
	}
	assert.Contains(t, table, "Alice Smith")
	assert.Contains(t, table, "Bob Jones")
	assert.Contains(t, table, "Carol Cloud")
	assert.NotContains(t, table, "Help Desk", "groups are not users")
	assert.NotContains(t, table, "More results", "one page holds all three")

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.source = "m365" })))
	assert.Contains(t, out.String(), "Carol Cloud")
	assert.NotContains(t, out.String(), "Alice Smith")

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.disabled = true })))
	assert.Contains(t, out.String(), "Bob Jones")
	assert.NotContains(t, out.String(), "Alice Smith")

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.enabled = true; o.managed = true })))
	assert.Contains(t, out.String(), "Alice Smith")
	assert.NotContains(t, out.String(), "Bob Jones")

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.query = "jones" })))
	assert.Contains(t, out.String(), "Bob Jones")
	assert.NotContains(t, out.String(), "Alice Smith")

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.query = "nobody-matches" })))
	assert.Equal(t, "No users found.\n", out.String())

	// One page of two with a next-page hint, then the hinted token continues.
	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.limit = 2 })))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	hint := lines[len(lines)-1]
	require.Contains(t, hint, "More results: --page-token ")
	assert.Len(t, lines, 4, "header, two rows, hint")
	token := strings.Fields(strings.TrimPrefix(hint, "More results: --page-token "))[0]

	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.limit = 2; o.pageToken = token })))
	assert.NotContains(t, out.String(), "More results")
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 2, "header and the last row")

	// --all follows every token.
	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.limit = 1; o.limitSet = true; o.all = true })))
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 4)
	assert.NotContains(t, out.String(), "More results")

	// JSON carries the API's shape.
	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.output = directoryOutputJSON })))
	var got struct {
		Items []map[string]interface{} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Len(t, got.Items, 3)

	// Flag errors are refused before any request.
	for _, bad := range []func(*directoryListFlags){
		func(o *directoryListFlags) { o.enabled = true; o.disabled = true },
		func(o *directoryListFlags) { o.output = "yaml" },
		func(o *directoryListFlags) { o.limit = 0 },
		func(o *directoryListFlags) { o.limit = 501 },
		func(o *directoryListFlags) { o.source = "ldap" },
		func(o *directoryListFlags) { o.all = true; o.pageToken = "x" },
	} {
		assert.Error(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(bad)))
	}
}

func TestCfgDirectoryUserShow_PrintsObjectAndGroups(t *testing.T) {
	f := newDirCLIFixture(t)
	seedDirectory(f)
	f.batch(dirCLIUserFrag("alice", "helpdesk"))
	ctx := context.Background()

	var out bytes.Buffer
	require.NoError(t, runDirectoryUserShow(ctx, &out, f.client, "ad/alice", dirFlags()))
	text := out.String()
	assert.Contains(t, text, "id: alice")
	assert.Contains(t, text, "display_name: Alice Smith")
	assert.Contains(t, text, "enabled: true")
	assert.Contains(t, text, "GROUPS")
	assert.Contains(t, text, "helpdesk")
	assert.Contains(t, text, "Help Desk")

	out.Reset()
	require.NoError(t, runDirectoryUserShow(ctx, &out, f.client, "ad/bob", dirFlags()))
	assert.Contains(t, out.String(), "(none)")

	out.Reset()
	require.NoError(t, runDirectoryUserShow(ctx, &out, f.client, "ad/alice", dirFlags(func(o *directoryListFlags) { o.output = directoryOutputJSON })))
	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &obj))
	assert.Equal(t, "alice", obj["id"])
	assert.Len(t, obj["groups"], 1)
}

func TestCfgDirectory_NotFoundIsNeutral(t *testing.T) {
	f := newDirCLIFixture(t)
	seedDirectory(f)
	ctx := context.Background()
	var out bytes.Buffer

	for name, run := range map[string]func() error{
		"user":    func() error { return runDirectoryUserShow(ctx, &out, f.client, "ad/ghost", dirFlags()) },
		"group":   func() error { return runDirectoryGroupShow(ctx, &out, f.client, "m365/ghost", dirFlags()) },
		"changes": func() error { return runDirectoryGroupChanges(ctx, &out, f.client, "ad/ghost", dirFlags()) },
	} {
		err := run()
		require.Error(t, err, name)
		assert.Equal(t, "not found", err.Error(), name)
	}
	assert.Empty(t, out.String())

	for _, ref := range []string{"ldap/x", "ad", "ad/", "/x", "ad/a b", "ad/.", "ad/..", "ad/" + strings.Repeat("a", 65), "ad/a/b"} {
		_, _, err := parseDirectoryRef(ref)
		assert.Error(t, err, ref)
	}
}

func TestCfgDirectoryGroupList_And_Show(t *testing.T) {
	f := newDirCLIFixture(t)
	seedDirectory(f)
	f.batch(dirCLIUserFrag("alice", "helpdesk"), dirCLIUserFrag("bob", "helpdesk"))
	ctx := context.Background()

	var out bytes.Buffer
	require.NoError(t, runDirectoryGroupList(ctx, &out, f.client, dirFlags()))
	assert.Contains(t, out.String(), "Help Desk")
	assert.Contains(t, out.String(), "Cloud Admins")
	assert.NotContains(t, out.String(), "ENABLED", "groups have no enabled field")
	assert.NotContains(t, out.String(), "Alice Smith")

	out.Reset()
	require.NoError(t, runDirectoryGroupList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.managed = true })))
	assert.Contains(t, out.String(), "Help Desk")
	assert.NotContains(t, out.String(), "Cloud Admins")

	out.Reset()
	require.NoError(t, runDirectoryGroupShow(ctx, &out, f.client, "ad/helpdesk", dirFlags()))
	assert.Contains(t, out.String(), "id: helpdesk")
	assert.Contains(t, out.String(), "MEMBERS")
	assert.Contains(t, out.String(), "alice")
	assert.Contains(t, out.String(), "bob")
}

func TestCfgDirectoryGroupShow_ListsAllMembersAcrossPages(t *testing.T) {
	f := newDirCLIFixture(t)
	f.group(dirTestAuthority, "everyone", map[string]interface{}{"display_name": "Everyone"})
	const total = 23
	ups := make([]directory.Fragment, 0, total)
	want := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("member-%02d", i)
		want = append(want, id)
		ups = append(ups, dirCLIUserFrag(id, "everyone"))
	}
	f.batch(ups...)
	ctx := context.Background()

	// A single page stops with a hint, and lists a strict subset.
	var out bytes.Buffer
	require.NoError(t, runDirectoryGroupShow(ctx, &out, f.client, "ad/everyone", dirFlags(func(o *directoryListFlags) { o.limit = 5 })))
	assert.Contains(t, out.String(), "More results: --page-token ")

	// --all with a small page size crosses several pages and loses and repeats nothing.
	out.Reset()
	require.NoError(t, runDirectoryGroupShow(ctx, &out, f.client, "ad/everyone", dirFlags(func(o *directoryListFlags) {
		o.limit = 5
		o.limitSet = true
		o.all = true
		o.output = directoryOutputJSON
	})))
	var got struct {
		ID      string `json:"id"`
		Members []struct {
			ID string `json:"id"`
		} `json:"members"`
		Next string `json:"next_page_token"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, "everyone", got.ID)
	assert.Empty(t, got.Next)
	ids := make([]string, 0, len(got.Members))
	for _, m := range got.Members {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	assert.Equal(t, want, ids)

	// The table form lists them all too.
	out.Reset()
	require.NoError(t, runDirectoryGroupShow(ctx, &out, f.client, "ad/everyone", dirFlags(func(o *directoryListFlags) {
		o.limit = 5
		o.limitSet = true
		o.all = true
	})))
	for _, id := range want {
		assert.Contains(t, out.String(), id)
	}
	assert.NotContains(t, out.String(), "More results")
}

func TestCfgDirectory_StripsTerminalControlSequences(t *testing.T) {
	f := newDirCLIFixture(t)
	hostile := "\x1b[31mred\x1b[0m\x1b]0;pwned\x07 tab\there\nnewline \u0085 c1\u009b31m del\x7f line\u2028sep \u202e"
	f.user(dirTestAuthority, "evil", map[string]interface{}{
		"display_name": hostile, "description": hostile, "mail": hostile, "sam_account_name": hostile, "user_principal_name": hostile,
	})
	f.group(dirTestAuthority, "evil-group", map[string]interface{}{"display_name": hostile, "description": hostile})
	f.batch(dirCLIUserFrag("evil", "evil-group"))
	ctx := context.Background()

	var outs []string
	var out bytes.Buffer
	for _, run := range []func() error{
		func() error { return runDirectoryUserList(ctx, &out, f.client, dirFlags()) },
		func() error { return runDirectoryUserShow(ctx, &out, f.client, "ad/evil", dirFlags()) },
		func() error { return runDirectoryGroupList(ctx, &out, f.client, dirFlags()) },
		func() error { return runDirectoryGroupShow(ctx, &out, f.client, "ad/evil-group", dirFlags()) },
	} {
		out.Reset()
		require.NoError(t, run())
		outs = append(outs, out.String())
	}
	for i, s := range outs {
		assert.Contains(t, s, "red", "output %d keeps the text", i)
		assert.Contains(t, s, `\x1b[31m`, "output %d shows ESC visibly", i)
		for _, r := range s {
			if r == '\n' {
				continue
			}
			assert.False(t, unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\u202e',
				"output %d holds raw control rune %U", i, r)
		}
	}

	// JSON is escaped by the encoder.
	out.Reset()
	require.NoError(t, runDirectoryUserList(ctx, &out, f.client, dirFlags(func(o *directoryListFlags) { o.output = directoryOutputJSON })))
	assert.NotContains(t, out.String(), "\x1b")
	assert.Contains(t, out.String(), `\u001b`)
}

// fieldKeys returns the sorted top-level keys of a JSON object.
func fieldKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m), string(raw))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstItem(t *testing.T, raw []byte, key string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m), string(raw))
	var arr []json.RawMessage
	require.NoError(t, json.Unmarshal(m[key], &arr), string(raw))
	require.NotEmpty(t, arr, string(raw))
	return arr[0]
}

func TestCfgDirectory_JSONFieldSetMatchesAPI(t *testing.T) {
	f := newDirCLIFixture(t)
	seedDirectory(f)
	// Group "helpdesk" gets members and a membership change so every shape is populated.
	f.batch(dirCLIUserFrag("alice", "helpdesk"))
	f.clock = f.clock.Add(time.Hour)
	f.batch(dirCLIUserFrag("alice", "helpdesk"), dirCLIUserFrag("bob", "helpdesk"))
	ctx := context.Background()
	jsonFlags := dirFlags(func(o *directoryListFlags) { o.output = directoryOutputJSON })

	api := func(path string) []byte {
		body, err := directoryGet(ctx, f.client, path, nil)
		require.NoError(t, err)
		return body
	}
	cli := func(run func(*bytes.Buffer) error) []byte {
		var out bytes.Buffer
		require.NoError(t, run(&out))
		return out.Bytes()
	}

	// User list row: every API field of the row, no more, no fewer.
	apiUsers := api("/api/v1/directory/users?source=ad&q=alice")
	cliUsers := cli(func(b *bytes.Buffer) error {
		fl := *jsonFlags
		fl.source, fl.query = "ad", "alice"
		return runDirectoryUserList(ctx, b, f.client, &fl)
	})
	assert.Equal(t, fieldKeys(t, firstItem(t, apiUsers, "items")), fieldKeys(t, firstItem(t, cliUsers, "items")))
	assert.Equal(t, fieldKeys(t, apiUsers), fieldKeys(t, cliUsers))
	assertSameJSON(t, firstItem(t, apiUsers, "items"), firstItem(t, cliUsers, "items"))

	// User show, with groups.
	apiUser := api("/api/v1/directory/users/ad/alice")
	cliUser := cli(func(b *bytes.Buffer) error { return runDirectoryUserShow(ctx, b, f.client, "ad/alice", jsonFlags) })
	assert.Equal(t, fieldKeys(t, apiUser), fieldKeys(t, cliUser))
	assertSameJSON(t, apiUser, cliUser)

	// Group list row.
	apiGroups := api("/api/v1/directory/groups?source=ad")
	cliGroups := cli(func(b *bytes.Buffer) error {
		fl := *jsonFlags
		fl.source = "ad"
		return runDirectoryGroupList(ctx, b, f.client, &fl)
	})
	assert.Equal(t, fieldKeys(t, firstItem(t, apiGroups, "items")), fieldKeys(t, firstItem(t, cliGroups, "items")))
	assertSameJSON(t, firstItem(t, apiGroups, "items"), firstItem(t, cliGroups, "items"))

	// Group show: the API's group fields plus members; member rows match the API's.
	apiGroup := api("/api/v1/directory/groups/ad/helpdesk")
	apiMembers := api("/api/v1/directory/groups/ad/helpdesk/members")
	cliGroup := cli(func(b *bytes.Buffer) error { return runDirectoryGroupShow(ctx, b, f.client, "ad/helpdesk", jsonFlags) })
	assert.Equal(t, sortedCopy(append(fieldKeys(t, apiGroup), "members")), fieldKeys(t, cliGroup))
	assertSameJSON(t, firstItem(t, apiMembers, "members"), firstItem(t, cliGroup, "members"))

	// Membership change rows.
	apiChanges := api("/api/v1/directory/groups/ad/helpdesk/membership-changes")
	cliChanges := cli(func(b *bytes.Buffer) error {
		return runDirectoryGroupChanges(ctx, b, f.client, "ad/helpdesk", jsonFlags)
	})
	assert.Equal(t, fieldKeys(t, firstItem(t, apiChanges, "events")), fieldKeys(t, firstItem(t, cliChanges, "events")))
	assert.Len(t, fieldKeys(t, firstItem(t, cliChanges, "events")), 8)
	assertSameJSON(t, firstItem(t, apiChanges, "events"), firstItem(t, cliChanges, "events"))
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func assertSameJSON(t *testing.T, want, got []byte) {
	t.Helper()
	var w, g interface{}
	require.NoError(t, json.Unmarshal(want, &w))
	require.NoError(t, json.Unmarshal(got, &g))
	if wm, ok := w.(map[string]interface{}); ok {
		// Group show carries members beside the group; compare the group's own fields.
		if gm, ok := g.(map[string]interface{}); ok {
			if _, has := wm["members"]; !has {
				delete(gm, "members")
			}
		}
	}
	assert.Equal(t, w, g)
}

// --- membership changes ---

func seedChanges(f *dirCLIFixture) {
	f.group(dirTestAuthority, "g1", map[string]interface{}{"display_name": "G1"})
	f.batch(dirCLIUserFrag("u-base", "g1")) // baseline
	f.clock = f.clock.Add(time.Hour)
	f.batch(dirCLIUserFrag("u-base", "g1"), dirCLIUserFrag("u-new", "g1"))
	f.clock = f.clock.Add(time.Hour)
	f.batch(dirCLIUserFrag("u-base"), dirCLIUserFrag("u-new", "g1"))
	f.clock = f.clock.Add(time.Hour)
	f.batch(dirCLIUserFrag("u-base"), dirCLIUserFrag("u-new"))
}

func TestCfgDirectoryGroupChanges_AgainstRealAPI(t *testing.T) {
	f := newDirCLIFixture(t)
	seedChanges(f)
	ctx := context.Background()

	var out bytes.Buffer
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags()))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4, "header and three changes; the baseline is excluded:\n%s", out.String())
	for _, col := range []string{"GROUP", "MEMBER", "MEMBER_TYPE", "OP", "OBSERVED_AT", "RECORDED_AT", "SOURCE", "BASELINE"} {
		assert.Contains(t, lines[0], col)
	}
	// Newest first: u-new removed, then u-base removed, then u-new added.
	assert.Contains(t, lines[1], "u-new")
	assert.Contains(t, lines[1], "removed")
	assert.Contains(t, lines[2], "u-base")
	assert.Contains(t, lines[2], "removed")
	assert.Contains(t, lines[3], "u-new")
	assert.Contains(t, lines[3], "added")
	assert.Contains(t, lines[3], "directory:a.example/group:g1")
	assert.Contains(t, lines[3], dirTestAuthority)

	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.includeBaseline = true })))
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 5)

	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.member = "u-base" })))
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 2)

	since := f.clock.Add(-30 * time.Minute).Format(time.RFC3339)
	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.since = since })))
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 2, "only the newest change is that recent")

	until := f.clock.Add(-150 * time.Minute).Format(time.RFC3339)
	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.until = until })))
	assert.Equal(t, "No membership changes found.\n", out.String(), "the baseline is excluded and nothing else is that old")

	out.Reset()
	err := runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.since = "yesterday" }))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC 3339")
}

func TestCfgDirectoryGroupChanges_AllFollowsPages(t *testing.T) {
	f := newDirCLIFixture(t)
	seedChanges(f)
	ctx := context.Background()

	var out bytes.Buffer
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) {
		o.includeBaseline = true
		o.limit = 2
	})))
	assert.Contains(t, out.String(), "More results: --page-token ")
	assert.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 4, "header, two rows, hint")

	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(ctx, &out, f.client, "ad/g1", dirFlags(func(o *directoryListFlags) {
		o.includeBaseline = true
		o.limit = 1
		o.limitSet = true
		o.all = true
		o.output = directoryOutputJSON
	})))
	var got struct {
		Events []APIDirectoryChange `json:"events"`
		Next   string               `json:"next_page_token"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got.Events, 4)
	assert.Empty(t, got.Next)
	for i := 1; i < len(got.Events); i++ {
		assert.False(t, got.Events[i].RecordedAt.After(got.Events[i-1].RecordedAt), "newest first across pages")
	}
	assert.True(t, got.Events[3].Baseline)
}

func TestCfgDirectoryGroupChanges_EscapesControlSequences(t *testing.T) {
	// Membership events come from validated ids, so the real API cannot be made to carry
	// hostile text here. This server returns what a compromised or buggy controller
	// could, to prove the client escapes each column of the table by itself.
	hostile := "\x1b[2J\x1b]0;pwned\x07evil\u0085\u009b"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/directory/groups/ad/g1/membership-changes", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events": []APIDirectoryChange{{
				Group: hostile, Member: hostile, MemberType: hostile, Op: hostile, Source: hostile,
				ObservedAt: time.Now(), RecordedAt: time.Now(),
			}},
			"next_page_token": hostile,
		})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client, err := NewAPIClient(&APIClientConfig{BaseURL: ts.URL, BearerToken: "unused"})
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, runDirectoryGroupChanges(context.Background(), &out, client, "ad/g1", dirFlags()))
	assert.Contains(t, out.String(), `\x1b[2J`)
	assert.Contains(t, out.String(), "evil")
	for _, r := range out.String() {
		if r == '\n' {
			continue
		}
		assert.False(t, unicode.IsControl(r), "raw control rune %U reached the table", r)
	}

	out.Reset()
	require.NoError(t, runDirectoryGroupChanges(context.Background(), &out, client, "ad/g1", dirFlags(func(o *directoryListFlags) { o.output = directoryOutputJSON })))
	assert.NotContains(t, out.String(), "\x1b")
	assert.NotContains(t, out.String(), "\x07")
}

func TestCfgDirectory_AllStopsAtCapAndSaysSo(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/directory/users", func(w http.ResponseWriter, r *http.Request) {
		calls++
		limit := 0
		_, _ = fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
		items := make([]map[string]interface{}, limit)
		for i := range items {
			items[i] = map[string]interface{}{"source": "ad", "kind": "user", "id": fmt.Sprintf("u%d-%d", calls, i), "authority": "a"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items, "next_page_token": fmt.Sprintf("t%d", calls)})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client, err := NewAPIClient(&APIClientConfig{BaseURL: ts.URL, BearerToken: "unused"})
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, runDirectoryUserList(context.Background(), &out, client, dirFlags(func(o *directoryListFlags) { o.all = true })))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	assert.Len(t, lines, directoryAllCap+2, "header, capped rows, and the stop notice")
	assert.Contains(t, lines[len(lines)-1], fmt.Sprintf("Stopped after %d rows", directoryAllCap))
	assert.Contains(t, lines[len(lines)-1], "--page-token t")
}

func TestCfgDirectory_CommandsAndFlagsAreRegistered(t *testing.T) {
	flagsOf := func(path ...string) []string {
		c, _, err := rootCmd.Find(path)
		require.NoError(t, err)
		require.NotEqual(t, rootCmd, c, strings.Join(path, " "))
		var names []string
		c.LocalFlags().VisitAll(func(fl *pflag.Flag) { names = append(names, fl.Name) })
		sort.Strings(names)
		return names
	}
	assert.Equal(t, []string{"all", "disabled", "enabled", "limit", "managed", "output", "page-token", "query", "source"}, flagsOf("directory", "user", "list"))
	assert.Equal(t, []string{"authority", "output"}, flagsOf("directory", "user", "show"))
	assert.Equal(t, []string{"all", "limit", "managed", "output", "page-token", "query", "source"}, flagsOf("directory", "group", "list"))
	assert.Equal(t, []string{"all", "authority", "limit", "output", "page-token"}, flagsOf("directory", "group", "show"))
	assert.Equal(t, []string{"all", "authority", "include-baseline", "limit", "member", "output", "page-token", "since", "until"}, flagsOf("directory", "group", "changes"))
}
