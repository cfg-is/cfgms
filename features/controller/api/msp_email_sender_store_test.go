// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	notifif "github.com/cfgis/cfgms/pkg/notification/interfaces"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	testMSPA        = "msp-a"
	testMSPB        = "msp-b"
	testMSPPassword = "Mq7-msp-sender-pw-do-not-leak"
)

func testMSPSender() MSPEmailSender {
	return MSPEmailSender{Host: "smtp.acme-corp.example", Port: 587, TLSMode: "starttls", From: "ops@acme-corp.example", Username: "mailer"}
}

// newMSPEmailTestServer returns a real API server whose real secret store and a
// durable config store back the MSP sender store.
func newMSPEmailTestServer(t *testing.T) (*Server, *MSPEmailSenderStore) {
	t.Helper()
	server := setupTestServer(t)
	_, cs := newApprovalStore(t)
	st, err := NewMSPEmailSenderStore(cs)
	require.NoError(t, err)
	server.SetMSPEmailSenderStore(st)
	return server, st
}

func TestMSPEmailSenderStore_RoundTripPerTenant(t *testing.T) {
	ctx := context.Background()
	_, st := newMSPEmailTestServer(t)

	got, err := st.Get(ctx, testMSPA)
	require.NoError(t, err)
	assert.Nil(t, got, "no record reads as no sender")

	stored, err := st.Put(ctx, testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)
	assert.Equal(t, testMSPSender(), *stored)

	got, err = st.Get(ctx, testMSPA)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, testMSPSender(), *got)

	other, err := st.Get(ctx, testMSPB)
	require.NoError(t, err)
	assert.Nil(t, other, "one MSP never sees another's record")

	b := testMSPSender()
	b.Host = "smtp.other-corp.example"
	b.TLSMode = ""
	storedB, err := st.Put(ctx, testMSPB, b, "bob")
	require.NoError(t, err)
	assert.Equal(t, "starttls", storedB.TLSMode, "an empty mode defaults to starttls")
	gotA, err := st.Get(ctx, testMSPA)
	require.NoError(t, err)
	assert.Equal(t, "smtp.acme-corp.example", gotA.Host)
	gotB, err := st.Get(ctx, testMSPB)
	require.NoError(t, err)
	assert.Equal(t, "smtp.other-corp.example", gotB.Host)

	// Replace.
	r := testMSPSender()
	r.From = "alerts@acme-corp.example"
	_, err = st.Put(ctx, testMSPA, r, "alice")
	require.NoError(t, err)
	gotA, err = st.Get(ctx, testMSPA)
	require.NoError(t, err)
	assert.Equal(t, "alerts@acme-corp.example", gotA.From)
}

func TestMSPEmailSenderStore_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	_, err := NewMSPEmailSenderStore(nil)
	assert.Error(t, err)

	_, st := newMSPEmailTestServer(t)
	_, err = st.Get(ctx, "")
	assert.Error(t, err)
	_, err = st.Put(ctx, "", testMSPSender(), "alice")
	assert.Error(t, err)
	_, err = st.Put(ctx, testMSPA, testMSPSender(), "")
	assert.Error(t, err)
	assert.Error(t, st.Delete(ctx, ""))

	bad := testMSPSender()
	bad.Host = ""
	_, err = st.Put(ctx, testMSPA, bad, "alice")
	assert.Error(t, err)
	got, err := st.Get(ctx, testMSPA)
	require.NoError(t, err)
	assert.Nil(t, got, "a rejected write stores nothing")

	// An undecodable record is an error and never reads as "no sender".
	require.NoError(t, st.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: mspEmailSenderKey(testMSPA), Data: []byte("not json"), Format: cfgconfig.ConfigFormatJSON,
		Checksum: "x", UpdatedBy: "test", Source: "test",
	}))
	_, err = st.Get(ctx, testMSPA)
	assert.Error(t, err)
}

func TestMSPEmailSender_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)
	root := t.TempDir()

	_, cs, closeFn := openApprovalStore(t, root)
	st, err := NewMSPEmailSenderStore(cs)
	require.NoError(t, err)
	_, err = st.Put(ctx, testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)
	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPA, testMSPPassword, "alice"))

	// Restart: close both stores and reopen them from what is on disk.
	closeFn()
	require.NoError(t, server.secretStore.Close())
	reopened, err := NewSecretStore(config.DefaultConfig())
	require.NoError(t, err)
	server.secretStore = reopened

	_, cs2, closeFn2 := openApprovalStore(t, root)
	defer closeFn2()
	st2, err := NewMSPEmailSenderStore(cs2)
	require.NoError(t, err)

	got, err := st2.Get(ctx, testMSPA)
	require.NoError(t, err)
	require.NotNil(t, got, "the record survives a restart")
	assert.Equal(t, testMSPSender(), *got)
	pw, err := server.readMSPEmailPassword(ctx, testMSPA)
	require.NoError(t, err)
	assert.Equal(t, testMSPPassword, pw, "the password survives a restart")
}

func TestMSPEmailSender_PasswordStoredUnderMSPTenant(t *testing.T) {
	ctx := context.Background()
	server, _ := newMSPEmailTestServer(t)

	pw, err := server.readMSPEmailPassword(ctx, testMSPA)
	require.NoError(t, err)
	assert.Empty(t, pw, "no secret reads as no password")

	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPA, testMSPPassword, "alice"))
	sec, err := server.readEmailCredential(ctx, testMSPA, mspEmailCredentialRef)
	require.NoError(t, err)
	assert.Equal(t, testMSPPassword, sec.Value)

	pwB, err := server.readMSPEmailPassword(ctx, testMSPB)
	require.NoError(t, err)
	assert.Empty(t, pwB, "another MSP has no password")
	_, err = server.readEmailCredential(ctx, emailCredentialTenantID, mspEmailCredentialRef)
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound, "the controller-wide tenant is untouched")

	assert.Error(t, server.storeMSPEmailPassword(ctx, testMSPA, "", "alice"))
	assert.Error(t, server.storeMSPEmailPassword(ctx, "", testMSPPassword, "alice"))
}

func TestMSPEmailSender_DeleteRemovesRecordAndSecret(t *testing.T) {
	ctx := context.Background()
	server, st := newMSPEmailTestServer(t)
	_, err := st.Put(ctx, testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)
	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPA, testMSPPassword, "alice"))
	_, err = st.Put(ctx, testMSPB, testMSPSender(), "bob")
	require.NoError(t, err)
	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPB, testMSPPassword, "bob"))

	require.NoError(t, st.Delete(ctx, testMSPA))
	require.NoError(t, server.deleteMSPEmailPassword(ctx, testMSPA))
	got, err := st.Get(ctx, testMSPA)
	require.NoError(t, err)
	assert.Nil(t, got)
	pw, err := server.readMSPEmailPassword(ctx, testMSPA)
	require.NoError(t, err)
	assert.Empty(t, pw)

	// A second delete is not an error.
	require.NoError(t, st.Delete(ctx, testMSPA))
	require.NoError(t, server.deleteMSPEmailPassword(ctx, testMSPA))

	// The other MSP is untouched.
	gotB, err := st.Get(ctx, testMSPB)
	require.NoError(t, err)
	require.NotNil(t, gotB)
	pwB, err := server.readMSPEmailPassword(ctx, testMSPB)
	require.NoError(t, err)
	assert.Equal(t, testMSPPassword, pwB)

	assert.Error(t, server.deleteMSPEmailPassword(ctx, ""))
}

func TestMSPEmailSender_NoExportedValueCarriesThePassword(t *testing.T) {
	ctx := context.Background()
	server, st := newMSPEmailTestServer(t)
	_, err := st.Put(ctx, testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)
	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPA, testMSPPassword, "alice"))

	stored, err := st.Get(ctx, testMSPA)
	require.NoError(t, err)
	putBack, err := st.Put(ctx, testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)

	for name, v := range map[string]interface{}{"get": stored, "put": putBack} {
		js, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(js), testMSPPassword, name)
		assert.NotContains(t, fmt.Sprintf("%v %+v %#v", v, v, v), testMSPPassword, name)
	}

	// Validation errors name the field, never the value.
	err = ValidateMSPEmailSender(testMSPSender(), testMSPPassword+"\n")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testMSPPassword)
	_, err = st.Put(ctx, testMSPA, MSPEmailSender{Host: "bad host", From: "a@b.example"}, "alice")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "bad host")

	// The raw stored record holds no password either.
	entry, err := st.store.GetConfig(ctx, mspEmailSenderKey(testMSPA))
	require.NoError(t, err)
	assert.NotContains(t, string(entry.Data), testMSPPassword)
}

func TestValidateMSPEmailSender(t *testing.T) {
	ok := testMSPSender()
	require.NoError(t, ValidateMSPEmailSender(ok, testMSPPassword))

	withMode := func(m string) MSPEmailSender { s := ok; s.TLSMode = m; return s }
	withPort := func(p int) MSPEmailSender { s := ok; s.Port = p; return s }
	withHost := func(h string) MSPEmailSender { s := ok; s.Host = h; return s }
	withFrom := func(f string) MSPEmailSender { s := ok; s.From = f; return s }
	withUser := func(u string) MSPEmailSender { s := ok; s.Username = u; return s }

	require.NoError(t, ValidateMSPEmailSender(withMode(""), testMSPPassword), "empty mode defaults to starttls")
	require.NoError(t, ValidateMSPEmailSender(withMode("implicit_tls"), testMSPPassword))
	require.NoError(t, ValidateMSPEmailSender(withPort(0), testMSPPassword), "empty port defaults by mode")
	require.NoError(t, ValidateMSPEmailSender(withPort(465), testMSPPassword))
	require.NoError(t, ValidateMSPEmailSender(withUser(""), testMSPPassword))

	cases := map[string]struct {
		sender   MSPEmailSender
		password string
	}{
		"empty host":              {withHost(""), testMSPPassword},
		"host with slash":         {withHost("smtp.acme-corp.example/x"), testMSPPassword},
		"host with space":         {withHost("smtp acme-corp.example"), testMSPPassword},
		"host with tab":           {withHost("smtp.acme-corp.example\t"), testMSPPassword},
		"host with CRLF":          {withHost("smtp.acme-corp.example\r\n"), testMSPPassword},
		"plaintext tls mode":      {withMode("plain"), testMSPPassword},
		"none tls mode":           {withMode("none"), testMSPPassword},
		"port 25":                 {withPort(25), testMSPPassword},
		"port 8080":               {withPort(8080), testMSPPassword},
		"negative port":           {withPort(-1), testMSPPassword},
		"port 0 unknown mode":     {func() MSPEmailSender { s := withPort(0); s.TLSMode = "tls"; return s }(), testMSPPassword},
		"empty from":              {withFrom(""), testMSPPassword},
		"from with display name":  {withFrom("Ops <ops@acme-corp.example>"), testMSPPassword},
		"from in angle brackets":  {withFrom("<ops@acme-corp.example>"), testMSPPassword},
		"from with LF":            {withFrom("ops@acme-corp.example\nBcc: x@y.example"), testMSPPassword},
		"from with CR":            {withFrom("ops@acme-corp.example\r"), testMSPPassword},
		"from not an address":     {withFrom("ops"), testMSPPassword},
		"from too long":           {withFrom(strings.Repeat("a", 250) + "@b.example"), testMSPPassword},
		"username with control":   {withUser("mail\x00er"), testMSPPassword},
		"username too long":       {withUser(strings.Repeat("u", 257)), testMSPPassword},
		"empty password":          {ok, ""},
		"password with newline":   {ok, "pw\nQUIT"},
		"password too long":       {ok, strings.Repeat("p", 1025)},
		"password with DEL char":  {ok, "pw\x7f"},
		"host with only spaces":   {withHost("   "), testMSPPassword},
		"host with NBSP":          {withHost("smtp acme-corp.example"), testMSPPassword},
		"host with NEL":           {withHost("smtp\u0085acme-corp.example"), testMSPPassword},
		"username with DEL":       {withUser("mail\x7fer"), testMSPPassword},
		"from with trailing text": {withFrom("ops@acme-corp.example, b@c.example"), testMSPPassword},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, ValidateMSPEmailSender(c.sender, c.password))
		})
	}
	assert.NoError(t, ValidateMSPEmailSender(ok, strings.Repeat("p", 1024)), "1024 bytes is allowed")
	assert.NoError(t, ValidateMSPEmailSender(withUser(strings.Repeat("u", 256)), testMSPPassword), "256 bytes is allowed")
}

// TestMSPEmailSender_PortAllowListIsAVariable proves the allow-list is the only
// port policy: widening it admits a port, restoring it refuses it again.
func TestMSPEmailSender_PortAllowListIsAVariable(t *testing.T) {
	s := testMSPSender()
	s.Port = 2525
	require.Error(t, ValidateMSPEmailSender(s, testMSPPassword))
	orig := mspEmailAllowedPorts
	mspEmailAllowedPorts = []int{2525}
	t.Cleanup(func() { mspEmailAllowedPorts = orig })
	require.NoError(t, ValidateMSPEmailSender(s, testMSPPassword))
}

func TestBuildMSPEmailNotifier_GuardRefusesLoopbackAndNilWithoutPassword(t *testing.T) {
	ctx := context.Background()
	smtp := newEmailTestSMTPServer(t)
	server, st := newMSPEmailTestServer(t)

	orig := mspEmailAllowedPorts
	mspEmailAllowedPorts = []int{smtp.Port}
	t.Cleanup(func() { mspEmailAllowedPorts = orig })
	server.mspEmailExtra = map[string]interface{}{"root_ca_pem": smtp.CAPEM}

	sender := MSPEmailSender{Host: "localhost", Port: smtp.Port, TLSMode: "implicit_tls", From: "ops@acme-corp.example", Username: testSMTPUser}
	_, err := st.Put(ctx, testMSPA, sender, "alice")
	require.NoError(t, err)

	n, err := server.buildMSPEmailNotifier(ctx, testMSPA)
	require.NoError(t, err)
	assert.Nil(t, n, "a record without a password is no sender")

	// A password under another tenant does not complete this MSP's sender.
	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPB, testSMTPPassword, "bob"))
	n, err = server.buildMSPEmailNotifier(ctx, testMSPA)
	require.NoError(t, err)
	assert.Nil(t, n)

	n, err = server.buildMSPEmailNotifier(ctx, "msp-without-record")
	require.NoError(t, err)
	assert.Nil(t, n, "no record is no sender")

	require.NoError(t, server.storeMSPEmailPassword(ctx, testMSPA, testSMTPPassword, "alice"))
	n, err = server.buildMSPEmailNotifier(ctx, testMSPA)
	require.NoError(t, err)
	require.NotNil(t, n)

	msg := notifif.Message{To: []string{"ops@acme-corp.example"}, Subject: "s", Body: "b"}
	_, err = n.Send(ctx, msg)
	require.Error(t, err, "the connect-time guard refuses a loopback host")
	assert.Empty(t, smtp.Messages(), "nothing reached the loopback server")
	assert.NotContains(t, err.Error(), testSMTPPassword)

	// With loopback admitted for the test the same notifier delivers, which shows
	// the refusal above came from the guard and the stored password is the one sent.
	t.Cleanup(pkgconfig.AllowLoopbackForTesting())
	res, err := n.Send(ctx, msg)
	require.NoError(t, err)
	assert.Empty(t, res.Failed())
	assert.Len(t, smtp.Messages(), 1)

	// A test extra cannot switch the guard off.
	server.mspEmailExtra = map[string]interface{}{"root_ca_pem": smtp.CAPEM, "guard_addresses": false}
	n, err = server.buildMSPEmailNotifier(ctx, testMSPA)
	require.NoError(t, err)
	require.NotNil(t, n)
}

func TestBuildMSPEmailNotifier_Unwired(t *testing.T) {
	server := setupTestServer(t)
	n, err := server.buildMSPEmailNotifier(context.Background(), testMSPA)
	require.NoError(t, err)
	assert.Nil(t, n, "no store wired is no sender")
}

func TestEmailProviderConfig(t *testing.T) {
	cfg := emailProviderConfig("h.example", "starttls", "a@b.example", 0, "", "pw")
	assert.Equal(t, map[string]interface{}{"host": "h.example", "security": "starttls", "from": "a@b.example"}, cfg,
		"a password is not passed without a username")
	cfg = emailProviderConfig("h.example", "implicit_tls", "a@b.example", 465, "u", "pw")
	assert.Equal(t, 465, cfg["port"])
	assert.Equal(t, "u", cfg["username"])
	assert.Equal(t, "pw", cfg["password"])
}

// TestMSPEmailSenderNamespaceOnlyStoreWrites names the writers of the MSP email
// sender namespace: msp_email_sender_store.go is the only one, and no registered
// route addresses it, so no generic config path can replace the host while keeping
// the stored password.
func TestMSPEmailSenderNamespaceOnlyStoreWrites(t *testing.T) {
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
		assert.NotContains(t, p, mspEmailSenderNamespace, "route %s must not address the namespace", p)
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
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil && v == mspEmailSenderNamespace {
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
	assert.Equal(t, []string{"features/controller/api/msp_email_sender_store.go"}, names)

	// The constant is the namespace the store writes to.
	_, st := newMSPEmailTestServer(t)
	_, err := st.Put(context.Background(), testMSPA, testMSPSender(), "alice")
	require.NoError(t, err)
	entries, err := st.store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: testMSPA, Namespace: mspEmailSenderNamespace})
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}
