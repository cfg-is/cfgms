// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// issuingClient is a test implementation of modules.CredentialClient that
// returns a fixed password or error and counts requests.
type issuingClient struct {
	password string
	err      error
	calls    int
	got      []string
}

func (c *issuingClient) IssueInitialCredential(_ context.Context, resourceID, kind string) (string, error) {
	c.calls++
	c.got = append(c.got, kind+"/"+resourceID)
	return c.password, c.err
}

const testPassword = "Zq7#tP2m-Lw9xR4v"

func userDecl(name string, cfg map[string]interface{}) modules.DeclaredResource {
	return modules.DeclaredResource{Name: name, Module: "activedirectory.user", ResourceID: resourceIDFor(resourceUser, name), Config: cfg}
}

func groupDecl(name string, cfg map[string]interface{}) modules.DeclaredResource {
	return modules.DeclaredResource{Name: name, Module: "activedirectory.group", ResourceID: resourceIDFor(resourceGroup, name), Config: cfg}
}

func state(cfg map[string]interface{}) modules.ConfigState { return &resourceState{fields: cfg} }

// newDeclaredModule returns a module running against d with a binding store in
// stateDir (a new temp dir when empty) and, when client is not nil, that
// credential client.
func newDeclaredModule(t *testing.T, d *FakeDirectory, stateDir string, client modules.CredentialClient, logger logging.Logger) *activeDirectoryModule {
	t.Helper()
	if stateDir == "" {
		stateDir = t.TempDir()
	}
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	m := newWithRunners(logger, d.ReadRunner(), d.WriteRunner(), WithBindingStore(newTestBindingStore(stateDir)))
	if client != nil {
		require.NoError(t, m.SetCredentialClient(client))
	}
	return m
}

// converge runs one executor-shaped cycle for a declared resource: Get, then
// Set only when Get's state differs from the declared configuration.
func converge(t *testing.T, m *activeDirectoryModule, r modules.DeclaredResource) error {
	t.Helper()
	current, err := m.Get(context.Background(), r.ResourceID)
	if err != nil {
		return err
	}
	if equalFields(current.AsMap(), r.Config) {
		return nil
	}
	return m.Set(context.Background(), r.ResourceID, state(r.Config))
}

func equalFields(current, desired map[string]interface{}) bool {
	a, _ := yaml.Marshal(current)
	b, _ := yaml.Marshal(desired)
	return string(a) == string(b)
}

func jdoe() map[string]interface{} {
	return map[string]interface{}{
		"sam_account_name":    "jdoe",
		"user_principal_name": "jdoe@acme-corp.example",
		"display_name":        "J Doe",
		"mail":                "jdoe@acme-corp.example",
		"ou":                  "OU=Staff,DC=acme-corp,DC=example",
		"enabled":             true,
	}
}

func TestBinding_SurvivesModuleRestart(t *testing.T) {
	d := NewFakeDirectory()
	stateDir := t.TempDir()
	r := userDecl("jdoe", jdoe())

	first := newDeclaredModule(t, d, stateDir, &issuingClient{password: testPassword}, nil)
	first.SetDeclared([]modules.DeclaredResource{r})
	require.NoError(t, converge(t, first, r))
	created, ok := d.Lookup("jdoe")
	require.True(t, ok)

	// The object is renamed outside CFGMS. A fresh module (steward restart)
	// still finds it by the objectGUID recorded on disk, not by name.
	d.Rename(created, "jdoe-renamed")
	client := &issuingClient{password: testPassword}
	second := newDeclaredModule(t, d, stateDir, client, nil)
	second.SetDeclared([]modules.DeclaredResource{r})

	current, err := second.Get(context.Background(), r.ResourceID)
	require.NoError(t, err)
	assert.Equal(t, r.Config, current.AsMap(), "the restarted module matches the bound object by objectGUID")
	require.NoError(t, converge(t, second, r))
	assert.Equal(t, []string{opCreateUser}, d.WriteOps(), "nothing is created or written after the restart")
	assert.Zero(t, client.calls)

	data, err := os.ReadFile(filepath.Join(stateDir, bindingFileName))
	require.NoError(t, err)
	assert.Contains(t, string(data), created)
	assert.NotContains(t, string(data), testPassword, "the binding file holds no secret")
}

func TestSetUser_CredentialUnavailableCreatesNoAccount(t *testing.T) {
	cases := map[string]modules.CredentialClient{
		"no client":            nil,
		"controller error":     &issuingClient{err: errors.New("credential request refused")},
		"empty password":       &issuingClient{},
		"controller down only": &issuingClient{err: context.DeadlineExceeded},
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			d := NewFakeDirectory()
			stateDir := t.TempDir()
			m := newDeclaredModule(t, d, stateDir, client, nil)
			r := userDecl("jdoe", jdoe())
			m.SetDeclared([]modules.DeclaredResource{r})

			err := m.Set(context.Background(), r.ResourceID, state(r.Config))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no account was created")
			assert.NotContains(t, err.Error(), testPassword)
			assert.Empty(t, d.WriteOps(), "no write script ran")
			_, exists := d.Lookup("jdoe")
			assert.False(t, exists)
			_, statErr := os.Stat(filepath.Join(stateDir, bindingFileName))
			assert.True(t, os.IsNotExist(statErr), "no binding was recorded")
		})
	}
}

func TestSetUser_OverlongPasswordRejectedWithoutWriting(t *testing.T) {
	long := strings.Repeat("A", maxPasswordLen+1)
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", &issuingClient{password: long}, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})

	err := m.Set(context.Background(), r.ResourceID, state(r.Config))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no account was created")
	assert.NotContains(t, err.Error(), long)
	assert.Empty(t, d.WriteOps(), "no write script ran")
}

func TestSetUser_ExistingUnboundName_NotAdopted(t *testing.T) {
	d := NewFakeDirectory()
	existing := d.AddUser("jdoe")
	client := &issuingClient{password: testPassword}
	m := newDeclaredModule(t, d, "", client, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})

	err := m.Set(context.Background(), r.ResourceID, state(r.Config))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), "adopt")
	assert.Empty(t, d.WriteOps(), "nothing was changed")
	assert.Zero(t, client.calls)
	assert.True(t, d.Enabled(existing))
	_, bound, err := m.bindings.get(r.ResourceID)
	require.NoError(t, err)
	assert.False(t, bound)
}

func TestSetUser_AdoptBindsGUID(t *testing.T) {
	d := NewFakeDirectory()
	existing := d.AddUser("jdoe")
	client := &issuingClient{password: testPassword}
	m := newDeclaredModule(t, d, "", client, nil)
	cfg := jdoe()
	cfg["adopt"] = true
	cfg["enabled"] = false
	r := userDecl("jdoe", cfg)
	m.SetDeclared([]modules.DeclaredResource{r})

	require.NoError(t, converge(t, m, r))
	bound, ok, err := m.bindings.get(r.ResourceID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, existing, bound, "adopt binds the existing object's objectGUID")
	assert.ElementsMatch(t, []string{opSetUserAttributes, opSetUserEnabled}, d.WriteOps(),
		"adopt converges only display_name, mail and enabled")
	assert.False(t, d.Enabled(existing))
	assert.Zero(t, client.calls, "adopting never requests a password")

	require.NoError(t, converge(t, m, r))
	assert.Len(t, d.WriteOps(), 2, "a converged adopted object is left alone")
}

func TestSetUser_RenamedToOtherGUID_Refused(t *testing.T) {
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", &issuingClient{password: testPassword}, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})
	require.NoError(t, converge(t, m, r))
	bound, _ := d.Lookup("jdoe")

	// The bound object is renamed and another object takes the declared name.
	d.Rename(bound, "jdoe-old")
	other := d.AddUser("jdoe")
	writes := len(d.WriteOps())

	err := converge(t, m, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different object")
	assert.Len(t, d.WriteOps(), writes, "nothing was changed")
	assert.True(t, d.Enabled(other))
	got, _, _ := m.bindings.get(r.ResourceID)
	assert.Equal(t, bound, got, "the binding is not moved to the other object")
}

func TestSetUser_SecondCycleAfterCreate_IsNoOp(t *testing.T) {
	d := NewFakeDirectory()
	client := &issuingClient{password: testPassword}
	m := newDeclaredModule(t, d, "", client, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})

	require.NoError(t, converge(t, m, r))
	assert.Equal(t, []string{opCreateUser}, d.WriteOps())
	assert.Equal(t, []string{testPassword}, d.Passwords(), "the issued password reached the script on stdin")
	assert.Equal(t, 1, client.calls)
	assert.Equal(t, []string{"activedirectory.user/jdoe"}, client.got, "the credential is requested for the cfg resource name")

	current, err := m.Get(context.Background(), r.ResourceID)
	require.NoError(t, err)
	assert.Equal(t, r.Config, current.AsMap(), "after create, Get reports the declared state")
	require.NoError(t, converge(t, m, r))
	require.NoError(t, m.Set(context.Background(), r.ResourceID, state(r.Config)), "a direct Set on a converged user is a no-op")
	assert.Equal(t, []string{opCreateUser}, d.WriteOps(), "the second cycle writes nothing")
	assert.Equal(t, 1, client.calls, "the second cycle requests no password")
}

func TestSetUser_RenamedAndReplaced_Refused(t *testing.T) {
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", &issuingClient{password: testPassword}, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})
	require.NoError(t, converge(t, m, r))
	bound, _ := d.Lookup("jdoe")

	// The bound object is deleted outside CFGMS (simulated by renaming it out
	// of reach and dropping it) and a new object takes the name.
	d.mu.Lock()
	delete(d.objects, bound)
	d.mu.Unlock()
	d.AddUser("jdoe")
	writes := len(d.WriteOps())

	current, err := m.Get(context.Background(), r.ResourceID)
	require.NoError(t, err)
	assert.Empty(t, current.AsMap(), "a replaced object is never reported as the declared one")
	err = m.Set(context.Background(), r.ResourceID, state(r.Config))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer exists")
	assert.Len(t, d.WriteOps(), writes, "nothing was changed")
}

func TestSetGroup_OnlyListedMembersChange(t *testing.T) {
	d := NewFakeDirectory()
	group := d.AddGroup("finance")
	alice, bob, carol, dave := d.AddUser("alice"), d.AddUser("bob"), d.AddUser("carol"), d.AddUser("dave")
	nested := d.AddGroup("finance-leads")
	d.AddMember(group, bob)   // listed absent: removed
	d.AddMember(group, carol) // unlisted: untouched
	d.AddMember(group, dave)  // listed present, already a member

	m := newDeclaredModule(t, d, "", nil, nil)
	r := groupDecl("finance", map[string]interface{}{
		"sam_account_name": "finance",
		"adopt":            true,
		"members_present":  []interface{}{"alice", "dave", "finance-leads"},
		"members_absent":   []interface{}{"bob", "not-a-user"},
	})
	m.SetDeclared([]modules.DeclaredResource{r})

	require.NoError(t, converge(t, m, r))
	assert.True(t, d.IsMember(group, alice))
	assert.True(t, d.IsMember(group, nested), "groups are members like users")
	assert.True(t, d.IsMember(group, dave))
	assert.False(t, d.IsMember(group, bob))
	assert.True(t, d.IsMember(group, carol), "an unlisted member is never touched")
	assert.ElementsMatch(t, []string{opAddGroupMember, opAddGroupMember, opRemoveGroupMember}, d.WriteOps())

	require.NoError(t, converge(t, m, r))
	assert.Len(t, d.WriteOps(), 3, "a converged group is left alone")
}

func TestSetGroup_CreatesAndBinds(t *testing.T) {
	d := NewFakeDirectory()
	alice := d.AddUser("alice")
	m := newDeclaredModule(t, d, "", nil, nil)
	r := groupDecl("finance", map[string]interface{}{
		"sam_account_name": "finance",
		"group_scope":      "Universal",
		"members_present":  []interface{}{"alice"},
	})
	m.SetDeclared([]modules.DeclaredResource{r})

	require.NoError(t, converge(t, m, r))
	group, ok := d.Lookup("finance")
	require.True(t, ok)
	assert.True(t, d.IsMember(group, alice))
	assert.Equal(t, []string{opCreateGroup, opAddGroupMember}, d.WriteOps())
	got, bound, err := m.bindings.get(r.ResourceID)
	require.NoError(t, err)
	require.True(t, bound)
	assert.Equal(t, group, got)
}

func TestWriteScript_NoPlaintextPasswordCmdletParam(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("scripts", "write.ps1"))
	require.NoError(t, err)
	script := string(data)
	code := stripPSComments(script)

	for _, banned := range []string{
		"ConvertTo-SecureString", "AsPlainText", "Invoke-Expression", "iex ", "-EncodedCommand",
		"Write-Host", "Write-Output", "Write-Verbose", "Write-Debug", "Write-Information",
		"Start-Transcript", "Out-File", "Set-Content", "Add-Content", "ReadToEnd",
		"ConvertFrom-SecureString", "PtrToString", "SecureStringToBSTR", "NetworkCredential",
	} {
		assert.NotContains(t, strings.ToLower(code), strings.ToLower(banned), "write.ps1 must not use %s", banned)
	}

	// The password is read one character at a time into a SecureString.
	assert.Regexp(t, regexp.MustCompile(`\$secure\.AppendChar\(\[char\]\$c\)`), code)
	assert.Regexp(t, regexp.MustCompile(`\[Console\]::In\.Read\(\)`), code)
	assert.Contains(t, code, "AccountPassword'] = $password", "only the SecureString reaches New-ADUser")
	// The only stdout writer is Write-Record, and nothing it is given holds
	// the request or the password.
	for _, line := range strings.Split(code, "\n") {
		if strings.Contains(line, "Write-Record") && !strings.Contains(line, "function Write-Record") {
			assert.NotRegexp(t, regexp.MustCompile(`\$(password|secure|line|request|raw|c)\b`), line, "a record never carries the payload: %s", strings.TrimSpace(line))
		}
	}
	// Every operation the script accepts is an implemented write.
	for _, op := range writeOperations {
		assert.Contains(t, code, "'"+op+"'", "write.ps1 implements %s", op)
	}
	assert.NotRegexp(t, regexp.MustCompile(`(?i)Remove-AD(User|Group|Object)\b`), code, "write.ps1 never deletes an object")
}

// stripPSComments removes PowerShell line comments (outside strings, which
// write.ps1 does not use for '#').
func stripPSComments(script string) string {
	var out []string
	for _, line := range strings.Split(script, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestSet_UndeclaredObjectIsNeverWritten(t *testing.T) {
	d := NewFakeDirectory()
	d.AddUser("jdoe")
	client := &issuingClient{password: testPassword}
	m := newDeclaredModule(t, d, "", client, nil)
	declared := userDecl("alice", map[string]interface{}{"sam_account_name": "alice"})
	m.SetDeclared([]modules.DeclaredResource{declared})

	userCfg := jdoe()
	userCfg["adopt"] = true
	groupCfg := map[string]interface{}{"sam_account_name": "finance", "adopt": true}
	for id, cfg := range map[string]map[string]interface{}{"user:jdoe": userCfg, "group:finance": groupCfg} {
		err := m.Set(context.Background(), id, state(cfg))
		require.Error(t, err, "Set(%s)", id)
		assert.Contains(t, err.Error(), "not declared")
		_, err = m.Get(context.Background(), id)
		assert.Error(t, err)
	}

	// A removed resource is no longer declared: its object stays in place.
	m.SetDeclared(nil)
	err := m.Set(context.Background(), declared.ResourceID, state(declared.Config))
	require.Error(t, err)
	assert.Empty(t, d.WriteOps())
	assert.Zero(t, client.calls)
}

func TestNoDeleteOperationExists(t *testing.T) {
	for _, op := range writeOperations {
		assert.NotRegexp(t, regexp.MustCompile(`(?i)delete|remove_(user|group)$`), op)
	}
	data, err := os.ReadFile("module.yaml")
	require.NoError(t, err)
	var manifest struct {
		SupportedOperations map[string][]string `yaml:"supported_operations"`
	}
	require.NoError(t, yaml.Unmarshal(data, &manifest))
	for _, ops := range manifest.SupportedOperations {
		for _, op := range ops {
			assert.NotContains(t, strings.ToLower(op), "delete")
		}
	}

	// Removing a declared resource from the configuration leaves its object.
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", &issuingClient{password: testPassword}, nil)
	r := userDecl("jdoe", jdoe())
	m.SetDeclared([]modules.DeclaredResource{r})
	require.NoError(t, converge(t, m, r))
	id, _ := d.Lookup("jdoe")
	m.SetDeclared(nil)
	_, exists := d.Lookup("jdoe")
	assert.True(t, exists)

	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	for _, obj := range inventoryObjects(t, state) {
		if obj["id"] == id {
			assert.Equal(t, false, obj["attrs"].(map[string]interface{})["managed"], "an undeclared object is reported managed:false")
		}
	}
}

func TestSetUser_HostileNameIsRejected(t *testing.T) {
	hostile := []string{
		"jdoe; Remove-ADUser x", "$(whoami)", "jdoe`n", "jdoe\nx", "jdoe\x00", "jdoe\t",
		"-Identity", " jdoe", "jdoe'", `jdoe"`, "jdoe|x", "jdoe&x", "a,b", "a=b", "CN=x",
		strings.Repeat("a", maxUserSamLength+1), "ünïcode", "",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			d := NewFakeDirectory()
			client := &issuingClient{password: testPassword}
			m := newDeclaredModule(t, d, "", client, nil)
			cfg := map[string]interface{}{"sam_account_name": name}
			r := userDecl("hostile", cfg)
			m.SetDeclared([]modules.DeclaredResource{r})

			assert.Error(t, m.Validate(r.ResourceID, state(cfg)))
			assert.Error(t, m.Set(context.Background(), r.ResourceID, state(cfg)))
			assert.Empty(t, d.WriteOps())
			assert.Zero(t, client.calls)
		})
	}

	// Every other name field, the ou and member names are held to the same
	// rules.
	for field, value := range map[string]interface{}{
		"display_name":        "x; iex",
		"mail":                "a@b`c",
		"user_principal_name": "-x@acme-corp.example",
		"ou":                  "OU=x\\,y,DC=acme-corp,DC=example",
	} {
		cfg := map[string]interface{}{"sam_account_name": "jdoe", field: value}
		_, err := parseUserConfig(cfg)
		assert.Error(t, err, "%s=%q", field, value)
	}
	_, err := parseGroupConfig(map[string]interface{}{"sam_account_name": "g", "members_present": []interface{}{"a;b"}})
	assert.Error(t, err)

	// An ou outside the machine's domain is refused at Set.
	d := NewFakeDirectory()
	client := &issuingClient{password: testPassword}
	m := newDeclaredModule(t, d, "", client, nil)
	cfg := map[string]interface{}{"sam_account_name": "jdoe", "ou": "OU=Staff,DC=other,DC=example"}
	r := userDecl("jdoe", cfg)
	m.SetDeclared([]modules.DeclaredResource{r})
	err = m.Set(context.Background(), r.ResourceID, state(cfg))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inside the machine's domain")
	assert.Empty(t, d.WriteOps())
	assert.Zero(t, client.calls)
}

func TestValidate_ReservedInventoryNamesRejected(t *testing.T) {
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", nil, nil)
	cfg := state(map[string]interface{}{"sam_account_name": "x"})
	for _, name := range []string{kindDirectoryUser, kindDirectoryGroup, "Directory_User", "DIRECTORY_GROUP"} {
		for _, id := range []string{name, "user:" + name, "group:" + name, "domain:" + name} {
			err := m.Validate(id, cfg)
			require.Error(t, err, "Validate(%q)", id)
			assert.Contains(t, err.Error(), "reserved")
		}
	}
	assert.NoError(t, m.Validate("user:jdoe", cfg))
	assert.NoError(t, m.Validate("status", nil))
}

func TestSetDomain_VerifiesOnly(t *testing.T) {
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", nil, nil)
	ok := modules.DeclaredResource{Name: "corp", Module: "activedirectory.domain", ResourceID: "domain:corp", Config: map[string]interface{}{"domain": "ACME-corp.example."}}
	bad := modules.DeclaredResource{Name: "other", Module: "activedirectory.domain", ResourceID: "domain:other", Config: map[string]interface{}{"domain": "other.example"}}
	m.SetDeclared([]modules.DeclaredResource{ok, bad})

	require.NoError(t, converge(t, m, ok))
	err := converge(t, m, bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not this machine's domain")
	assert.Empty(t, d.WriteOps())
}

func TestManagedFlag_BoundByGUIDOrUnboundBySam(t *testing.T) {
	d := NewFakeDirectory()
	m := newDeclaredModule(t, d, "", &issuingClient{password: testPassword}, nil)
	created := userDecl("jdoe", jdoe())
	pending := userDecl("asmith", map[string]interface{}{"sam_account_name": "ASmith"})
	m.SetDeclared([]modules.DeclaredResource{created, pending})
	require.NoError(t, converge(t, m, created))
	jdoeID, _ := d.Lookup("jdoe")
	d.Rename(jdoeID, "jdoe2") // still managed: bound by objectGUID
	asmith := d.AddUser("asmith")
	other := d.AddUser("other")

	inv, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	managed := map[string]interface{}{}
	for _, obj := range inventoryObjects(t, inv) {
		managed[obj["id"].(string)] = obj["attrs"].(map[string]interface{})["managed"]
	}
	assert.Equal(t, map[string]interface{}{jdoeID: true, asmith: true, other: false}, managed)
}
