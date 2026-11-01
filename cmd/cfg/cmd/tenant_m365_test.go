// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const m365CLISecret = "cli-secret-Qw8-5521"

// m365TestController serves the five M365 routes' HTTP contract and records requests.
type m365TestController struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recordedReq
}

func (c *m365TestController) requests() []recordedReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]recordedReq(nil), c.reqs...)
}

func newM365TestController(t *testing.T) *m365TestController {
	t.Helper()
	c := &m365TestController{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs = append(c.reqs, recordedReq{r.Method, r.URL.Path, r.Header.Clone(), b})
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(status int, body string) { w.WriteHeader(status); _, _ = w.Write([]byte(body)) }
		switch {
		case r.URL.Path == "/api/v1/tenants/client-1/m365-connection" && r.Method == http.MethodPut:
			write(200, `{"data":{"tenant_id":"client-1","mode":"direct","app_id":"app-1","m365_tenant_id":"dir-1","has_client_secret":true}}`)
		case r.URL.Path == "/api/v1/tenants/client-1/m365-connection" && r.Method == http.MethodGet:
			write(200, `{"data":{"tenant_id":"client-1","mode":"direct","app_id":"app-1","m365_tenant_id":"dir-1","has_client_secret":true}}`)
		case r.URL.Path == "/api/v1/tenants/client-2/m365-connection" && r.Method == http.MethodGet:
			write(200, `{"data":{"tenant_id":"client-2","mode":"partner","app_id":"papp","m365_tenant_id":"cust-1","partner_tenant_id":"partner-1","gdap_roles":["User-Administrator","Helpdesk-Administrator"],"has_client_secret":true}}`)
		case r.URL.Path == "/api/v1/tenants/client-9/m365-connection" && r.Method == http.MethodGet:
			write(404, `{"error":{"code":"M365_CONNECTION_NOT_FOUND","message":"tenant has no M365 connection"}}`)
		case r.URL.Path == "/api/v1/tenants/client-1/m365-connection" && r.Method == http.MethodDelete:
			write(200, `{"data":{"tenant_id":"client-1","deleted":true}}`)
		case r.URL.Path == "/api/v1/tenants/msp-a/m365-gdap-customers" && r.Method == http.MethodPost:
			write(200, `{"data":{"msp_tenant_id":"msp-a","customers":[
				{"customer_tenant_id":"cust-1","name":"Customer One","status":"active","expires_at":"2030-05-06T00:00:00Z","link_state":"linked","linked_to":"client-2"},
				{"customer_tenant_id":"cust-2","name":"Customer Two","status":"active","expires_at":"2030-06-07T00:00:00Z","link_state":"unlinked"}]}}`)
		case r.URL.Path == "/api/v1/tenants/msp-a/m365-gdap-links" && r.Method == http.MethodPost:
			write(200, `{"data":{"msp_tenant_id":"msp-a","linked":[{"customer_tenant_id":"cust-1","tenant_id":"client-1"},{"customer_tenant_id":"cust-2","tenant_id":"client-2"}]}}`)
		default:
			write(404, `{"error":{"code":"NOT_FOUND","message":"not found"}}`)
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func setupM365Cmd(t *testing.T, url, stdin string) {
	t.Helper()
	setupCrossingCmd(t, url)
	origStdin := m365Stdin
	origVars := []interface{}{m365AppID, m365DirectoryTenant, m365PartnerTenant, m365SecretStdin, m365Replace, m365Yes}
	origLinks, origRoles := m365Links, m365GDAPRoles
	t.Cleanup(func() {
		m365Stdin = origStdin
		m365AppID, m365DirectoryTenant, m365PartnerTenant = origVars[0].(string), origVars[1].(string), origVars[2].(string)
		m365SecretStdin, m365Replace, m365Yes = origVars[3].(bool), origVars[4].(bool), origVars[5].(bool)
		m365Links, m365GDAPRoles = origLinks, origRoles
	})
	m365Stdin = strings.NewReader(stdin)
	m365AppID, m365DirectoryTenant, m365PartnerTenant = "app-1", "dir-1", "partner-1"
	m365SecretStdin, m365Replace, m365Yes = true, false, true
	m365Links, m365GDAPRoles = nil, nil
}

func TestTenantM365Commands(t *testing.T) {
	t.Run("set sends the secret from stdin and never prints it", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365Set(tenantM365SetCmd, []string{"client-1"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPut, reqs[0].Method)
		assert.Equal(t, "/api/v1/tenants/client-1/m365-connection", reqs[0].Path)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, map[string]interface{}{"app_id": "app-1", "m365_tenant_id": "dir-1", "client_secret": m365CLISecret, "replace": false}, body)
		assert.NotContains(t, out, m365CLISecret)
		assert.Contains(t, out, "client secret: set")
	})

	t.Run("set needs --client-secret-stdin and a non-empty line", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		m365SecretStdin = false
		err := runTenantM365Set(tenantM365SetCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--client-secret-stdin")

		setupM365Cmd(t, srv.URL, "\n")
		require.Error(t, runTenantM365Set(tenantM365SetCmd, []string{"client-1"}))
		assert.Empty(t, srv.requests())
	})

	t.Run("confirm gate refuses without a terminal and without --yes", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		m365Yes, m365Replace = false, true
		err := runTenantM365Set(tenantM365SetCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to proceed")

		setupM365Cmd(t, srv.URL, "")
		m365Yes = false
		require.Error(t, runTenantM365Delete(tenantM365DeleteCmd, []string{"client-1"}))

		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		m365Yes, m365Links = false, []string{"cust-1=client-1"}
		require.Error(t, runTenantM365GDAPLink(tenantM365GDAPLinkCmd, []string{"msp-a"}))
		assert.Empty(t, srv.requests(), "a refused command sends nothing")
	})

	t.Run("get prints the connection without the secret", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365Get(tenantM365GetCmd, []string{"client-2"}))
		})
		for _, want := range []string{"mode: partner", "app ID: papp", "customer tenant: cust-1", "partner tenant: partner-1",
			"User-Administrator, Helpdesk-Administrator", "client secret: set"} {
			assert.Contains(t, out, want)
		}
		err := runTenantM365Get(tenantM365GetCmd, []string{"client-9"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no M365 connection")
	})

	t.Run("get --json prints the response data", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, "")
		tenantJSONOutput = true
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365Get(tenantM365GetCmd, []string{"client-1"}))
		})
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(out), &data))
		assert.Equal(t, "app-1", data["app_id"])
	})

	t.Run("delete calls DELETE", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365Delete(tenantM365DeleteCmd, []string{"client-1"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodDelete, reqs[0].Method)
		assert.Contains(t, out, "removed")
	})

	t.Run("gdap-customers prints the table", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365GDAPCustomers(tenantM365GDAPCustomersCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "/api/v1/tenants/msp-a/m365-gdap-customers", reqs[0].Path)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, map[string]interface{}{"partner_tenant_id": "partner-1", "app_id": "app-1", "client_secret": m365CLISecret}, body)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, []string{"CUSTOMER", "TENANT", "NAME", "STATUS", "EXPIRES", "LINKED", "TO"}, strings.Fields(lines[0]))
		assert.Contains(t, lines[1], "client-2")
		assert.Contains(t, lines[1], "2030-05-06")
		assert.True(t, strings.HasSuffix(strings.TrimSpace(lines[2]), "unlinked"))
		assert.NotContains(t, out, m365CLISecret)
	})

	t.Run("gdap-link sends all links in one request", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		m365Links = []string{"cust-1=client-1", "cust-2=client-2"}
		m365GDAPRoles = []string{"User-Administrator"}
		m365Replace = true
		out := captureStdout(t, func() {
			require.NoError(t, runTenantM365GDAPLink(tenantM365GDAPLinkCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "/api/v1/tenants/msp-a/m365-gdap-links", reqs[0].Path)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, []interface{}{
			map[string]interface{}{"customer_tenant_id": "cust-1", "tenant_id": "client-1"},
			map[string]interface{}{"customer_tenant_id": "cust-2", "tenant_id": "client-2"},
		}, body["links"])
		assert.Equal(t, []interface{}{"User-Administrator"}, body["gdap_roles"])
		assert.Equal(t, true, body["replace"])
		assert.Contains(t, out, "cust-2 -> client-2")
		assert.NotContains(t, out, m365CLISecret)
	})

	t.Run("gdap-link rejects malformed links before any request", func(t *testing.T) {
		srv := newM365TestController(t)
		for _, bad := range []string{"cust-1", "=client-1", "cust-1="} {
			setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
			m365Links = []string{bad}
			require.Error(t, runTenantM365GDAPLink(tenantM365GDAPLinkCmd, []string{"msp-a"}), bad)
		}
		assert.Empty(t, srv.requests())
	})

	t.Run("server errors name the code", func(t *testing.T) {
		srv := newM365TestController(t)
		setupM365Cmd(t, srv.URL, m365CLISecret+"\n")
		err := runTenantM365Set(tenantM365SetCmd, []string{"unknown"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NOT_FOUND")
	})

	t.Run("no flag accepts a secret value", func(t *testing.T) {
		require.True(t, func() bool {
			for _, c := range tenantCmd.Commands() {
				if c == tenantM365Cmd {
					return true
				}
			}
			return false
		}(), "m365 is registered on the tenant command")
		for _, c := range tenantM365Cmd.Commands() {
			c.Flags().VisitAll(func(f *pflag.Flag) {
				assert.NotContains(t, f.Name, "secret-value")
				if strings.Contains(f.Name, "secret") {
					assert.Equal(t, "client-secret-stdin", f.Name)
					assert.Equal(t, "bool", f.Value.Type(), "the secret flag is a switch, not a value")
				}
			})
		}
	})
}
