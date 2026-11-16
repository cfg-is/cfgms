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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const emailSenderCLIPassword = "smtp-pass-Zk4-7783"

// emailSenderTestController serves the four email-sender routes' HTTP contract and
// records requests. testResponse is the data payload of the test route.
type emailSenderTestController struct {
	*httptest.Server
	mu           sync.Mutex
	reqs         []recordedReq
	testResponse string
}

func (c *emailSenderTestController) requests() []recordedReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]recordedReq(nil), c.reqs...)
}

func newEmailSenderTestController(t *testing.T, testResponse string) *emailSenderTestController {
	t.Helper()
	c := &emailSenderTestController{testResponse: testResponse}
	const sender = `{"configured":true,"password_present":%s,"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"alerts@msp-a.example.com","username":"alerts"}`
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs = append(c.reqs, recordedReq{r.Method, r.URL.Path, r.Header.Clone(), b})
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(status int, body string) { w.WriteHeader(status); _, _ = w.Write([]byte(body)) }
		switch {
		case r.URL.Path == "/api/v1/tenants/msp-a/email-sender" && r.Method == http.MethodGet:
			write(200, `{"data":`+strings.Replace(sender, "%s", "true", 1)+`}`)
		case r.URL.Path == "/api/v1/tenants/msp-b/email-sender" && r.Method == http.MethodGet:
			write(200, `{"data":{"configured":true,"password_present":false,"host":"smtp.example.com","port":465,"tls_mode":"implicit_tls","from":"a@msp-b.example.com","username":""}}`)
		case r.URL.Path == "/api/v1/tenants/client-1/email-sender":
			write(404, `{"error":{"code":"TENANT_NOT_FOUND","message":"tenant not found"}}`)
		case r.URL.Path == "/api/v1/tenants/msp-a/email-sender" && r.Method == http.MethodPut:
			if strings.Contains(string(b), `"host":"bad host"`) {
				write(400, `{"error":{"code":"INVALID_EMAIL_SENDER","message":"msp email sender: host is required and must not contain whitespace or '/'"}}`)
				return
			}
			write(200, `{"data":`+strings.Replace(sender, "%s", "true", 1)+`}`)
		case r.URL.Path == "/api/v1/tenants/msp-a/email-sender" && r.Method == http.MethodDelete:
			write(200, `{"data":{"configured":false,"password_present":false,"host":"","port":0,"tls_mode":"","from":"","username":""}}`)
		case r.URL.Path == "/api/v1/tenants/msp-a/email-sender/test" && r.Method == http.MethodPost:
			write(200, `{"data":`+c.testResponse+`}`)
		default:
			write(404, `{"error":{"code":"NOT_FOUND","message":"not found"}}`)
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func setupEmailSenderCmd(t *testing.T, url, stdin string) {
	t.Helper()
	setupCrossingCmd(t, url)
	origStdin := emailSenderStdin
	origHost, origTLS, origFrom, origUser := emailSenderHost, emailSenderTLSMode, emailSenderFrom, emailSenderUsername
	origPort, origPW, origYes := emailSenderPort, emailSenderPasswordStdin, emailSenderYes
	t.Cleanup(func() {
		emailSenderStdin = origStdin
		emailSenderHost, emailSenderTLSMode, emailSenderFrom, emailSenderUsername = origHost, origTLS, origFrom, origUser
		emailSenderPort, emailSenderPasswordStdin, emailSenderYes = origPort, origPW, origYes
	})
	emailSenderStdin = strings.NewReader(stdin)
	emailSenderHost, emailSenderTLSMode, emailSenderFrom, emailSenderUsername = "smtp.example.com", "starttls", "alerts@msp-a.example.com", "alerts"
	emailSenderPort, emailSenderPasswordStdin, emailSenderYes = 587, true, true
}

func TestTenantEmailSenderRegistered(t *testing.T) {
	found, _, err := tenantCmd.Find([]string{"email-sender"})
	require.NoError(t, err)
	require.Equal(t, tenantEmailSenderCmd, found)
	for _, c := range []*cobra.Command{tenantEmailSenderShowCmd, tenantEmailSenderSetCmd, tenantEmailSenderRemoveCmd, tenantEmailSenderTestCmd} {
		sub, _, err := tenantCmd.Find([]string{"email-sender", strings.Fields(c.Use)[0]})
		require.NoError(t, err)
		assert.Equal(t, c, sub)
		assert.NotEmpty(t, c.Short)
		assert.NotEmpty(t, c.Long, "%s needs --help text", c.Use)
	}
}

func TestTenantEmailSenderSet(t *testing.T) {
	t.Run("sends the password in the request body only", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, emailSenderCLIPassword+"\n")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPut, reqs[0].Method)
		assert.Equal(t, "/api/v1/tenants/msp-a/email-sender", reqs[0].Path)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, map[string]interface{}{
			"host": "smtp.example.com", "port": float64(587), "tls_mode": "starttls",
			"from": "alerts@msp-a.example.com", "username": "alerts", "password": emailSenderCLIPassword,
		}, body)
		assert.NotContains(t, reqs[0].Path, emailSenderCLIPassword)
		for k, v := range reqs[0].Header {
			assert.NotContains(t, strings.Join(v, ","), emailSenderCLIPassword, "header %s", k)
		}
		assert.NotContains(t, out, emailSenderCLIPassword)
		assert.Contains(t, out, "password: present")
	})

	t.Run("password never appears in argv or error text", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, emailSenderCLIPassword+"\n")
		emailSenderHost = "bad host"
		err := runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"msp-a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "INVALID_EMAIL_SENDER")
		assert.NotContains(t, err.Error(), emailSenderCLIPassword)

		// An unreadable or empty stdin line is refused before any request, without echoing input.
		setupEmailSenderCmd(t, srv.URL, "\n")
		before := len(srv.requests())
		err = runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"msp-a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no password on stdin")
		assert.Len(t, srv.requests(), before)
	})

	t.Run("without --password-stdin and without a terminal the stored password is kept", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, emailSenderCLIPassword+"\n")
		emailSenderPasswordStdin = false
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, "", body["password"], "stdin is not read without --password-stdin")
		assert.NotContains(t, string(reqs[0].Body), emailSenderCLIPassword)
		assert.NotContains(t, out, emailSenderCLIPassword)
	})

	t.Run("a tenant that is not an MSP is reported as not found", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, emailSenderCLIPassword+"\n")
		err := runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant not found")
		assert.NotContains(t, err.Error(), emailSenderCLIPassword)
	})

	t.Run("--json prints the response data without the password", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, emailSenderCLIPassword+"\n")
		tenantJSONOutput = true
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderSet(tenantEmailSenderSetCmd, []string{"msp-a"}))
		})
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(out), &data))
		assert.Equal(t, "smtp.example.com", data["host"])
		assert.NotContains(t, out, emailSenderCLIPassword)
	})
}

func TestTenantEmailSenderNoPasswordFlag(t *testing.T) {
	for _, name := range []string{"password", "smtp-password"} {
		assert.Nil(t, tenantEmailSenderSetCmd.Flags().Lookup(name), "--%s must not exist", name)
	}
	assert.NotNil(t, tenantEmailSenderSetCmd.Flags().Lookup("password-stdin"))

	err := tenantEmailSenderSetCmd.ParseFlags([]string{"--password", emailSenderCLIPassword})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown flag: --password")
	assert.NotContains(t, strings.ReplaceAll(err.Error(), "--password", ""), emailSenderCLIPassword,
		"the error names the flag, never its value")
}

func TestTenantEmailSenderShow(t *testing.T) {
	t.Run("prints the settings and present, never a password", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderShow(tenantEmailSenderShowCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodGet, reqs[0].Method)
		for _, want := range []string{"tenant: msp-a", "host: smtp.example.com", "port: 587", "TLS mode: starttls",
			"from: alerts@msp-a.example.com", "username: alerts", "password: present"} {
			assert.Contains(t, out, want)
		}
		assert.NotContains(t, strings.ToLower(out), "password: absent")
	})

	t.Run("prints absent when no password is stored", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderShow(tenantEmailSenderShowCmd, []string{"msp-b"}))
		})
		assert.Contains(t, out, "password: absent")
		assert.Contains(t, out, "username: -")
		assert.NotContains(t, out, "password: present")
	})

	t.Run("a non-MSP tenant is an error", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		err := runTenantEmailSenderShow(tenantEmailSenderShowCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant not found")
	})
}

func TestTenantEmailSenderRemove(t *testing.T) {
	t.Run("refuses without --yes and without a terminal", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		emailSenderYes = false
		err := runTenantEmailSenderRemove(tenantEmailSenderRemoveCmd, []string{"msp-a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to proceed")
		assert.Empty(t, srv.requests(), "a refused command sends nothing")
	})

	t.Run("with --yes calls DELETE", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderRemove(tenantEmailSenderRemoveCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodDelete, reqs[0].Method)
		assert.Equal(t, "/api/v1/tenants/msp-a/email-sender", reqs[0].Path)
		assert.Contains(t, out, "removed")
	})

	t.Run("the yes flag is on remove only", func(t *testing.T) {
		assert.NotNil(t, tenantEmailSenderRemoveCmd.Flags().Lookup("yes"))
		assert.Nil(t, tenantEmailSenderSetCmd.Flags().Lookup("yes"))
	})
}

func TestTenantEmailSenderTest(t *testing.T) {
	t.Run("prints the accepted recipient for a success", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{"delivered":true,"recipients":[{"address":"alerts@msp-a.example.com","accepted":true}]}`)
		setupEmailSenderCmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			require.NoError(t, runTenantEmailSenderTest(tenantEmailSenderTestCmd, []string{"msp-a"}))
		})
		reqs := srv.requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPost, reqs[0].Method)
		assert.Equal(t, "/api/v1/tenants/msp-a/email-sender/test", reqs[0].Path)
		assert.Empty(t, reqs[0].Body)
		assert.Contains(t, out, "alerts@msp-a.example.com")
		assert.Contains(t, out, "accepted")
		assert.NotContains(t, out, "rejected")
		assert.NotContains(t, out, "failure:")
	})

	t.Run("prints the rejected recipient and the failure reason, and exits non-zero", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{"delivered":false,"recipients":[{"address":"alerts@msp-a.example.com","accepted":false,"reason":"mailbox unavailable"}],"failure_reason":"recipient not accepted"}`)
		setupEmailSenderCmd(t, srv.URL, "")
		var runErr error
		out := captureStdout(t, func() {
			runErr = runTenantEmailSenderTest(tenantEmailSenderTestCmd, []string{"msp-a"})
		})
		require.Error(t, runErr)
		assert.Contains(t, out, "alerts@msp-a.example.com")
		assert.Contains(t, out, "rejected")
		assert.Contains(t, out, "mailbox unavailable")
		assert.Contains(t, out, "failure: recipient not accepted")
	})

	t.Run("prints the failure reason when the send failed before any recipient", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{"delivered":false,"recipients":[],"failure_reason":"delivery timed out"}`)
		setupEmailSenderCmd(t, srv.URL, "")
		var runErr error
		out := captureStdout(t, func() {
			runErr = runTenantEmailSenderTest(tenantEmailSenderTestCmd, []string{"msp-a"})
		})
		require.Error(t, runErr)
		assert.Contains(t, out, "failure: delivery timed out")
	})

	t.Run("an unconfigured sender is an API error", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{}`)
		setupEmailSenderCmd(t, srv.URL, "")
		err := runTenantEmailSenderTest(tenantEmailSenderTestCmd, []string{"msp-z"})
		require.Error(t, err)
	})

	t.Run("recipient text cannot inject terminal control characters", func(t *testing.T) {
		srv := newEmailSenderTestController(t, `{"delivered":false,"recipients":[{"address":"a@b.example","accepted":false,"reason":"bad\u001b[31m"}],"failure_reason":"x"}`)
		setupEmailSenderCmd(t, srv.URL, "")
		out := captureStdout(t, func() {
			_ = runTenantEmailSenderTest(tenantEmailSenderTestCmd, []string{"msp-a"})
		})
		assert.NotContains(t, out, "\x1b")
	})
}
