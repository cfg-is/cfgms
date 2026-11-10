// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const automationTestPresenceToken = "presence-token-5859"

// automationHarness points the automation flags at a test controller with a
// generated admin bundle and captures what a command writes.
type automationHarness struct {
	cmd *cobra.Command
	out *bytes.Buffer
	err *bytes.Buffer
	dir string // working directory of the test; the credential must never land here
}

// newAutomationHarness resets every flag variable the automation commands read and
// restores them afterwards. The TLS test server is trusted through --tls-insecure,
// like the other cfg command tests.
func newAutomationHarness(t *testing.T, srvURL string) *automationHarness {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")

	type saved struct {
		url, serverName, name, tenant, expiresAt, version, approvalHash, contentHash, kind, bundle, output string
		insecure, noBundle, showDiff                                                                       bool
		expiresIn                                                                                          time.Duration
	}
	orig := saved{
		automationURL, automationServerName, automationGrantName, automationGrantTenant, automationGrantExpiresAt,
		automationVersion, automationApprovalHash, automationContentHash, automationKind, bundlePath, output,
		automationTLSInsecure, noBundle, automationShowDiff, automationGrantExpiresIn,
	}
	t.Cleanup(func() {
		automationURL, automationServerName, automationGrantName, automationGrantTenant, automationGrantExpiresAt = orig.url, orig.serverName, orig.name, orig.tenant, orig.expiresAt
		automationVersion, automationApprovalHash, automationContentHash, automationKind = orig.version, orig.approvalHash, orig.contentHash, orig.kind
		bundlePath, output, automationTLSInsecure, noBundle = orig.bundle, orig.output, orig.insecure, orig.noBundle
		automationShowDiff, automationGrantExpiresIn = orig.showDiff, orig.expiresIn
	})
	automationURL, automationTLSInsecure, bundlePath, noBundle, output = srvURL, true, bundleFilePath, false, "text"
	automationServerName, automationGrantName, automationGrantTenant, automationGrantExpiresAt = "", "", "", ""
	automationVersion, automationApprovalHash, automationContentHash = "", "", ""
	automationKind, automationShowDiff, automationGrantExpiresIn = automationKindScript, false, 0

	dir := t.TempDir()
	t.Chdir(dir)

	c := &cobra.Command{}
	h := &automationHarness{cmd: c, out: &bytes.Buffer{}, err: &bytes.Buffer{}, dir: dir}
	c.SetOut(h.out)
	c.SetErr(h.err)
	return h
}

// answerPresenceWith makes the presence relay return token for any challenge and
// records the permission the controller named.
func answerPresenceWith(t *testing.T, token string) *string {
	t.Helper()
	origTerminal, origFlow := isTerminalFn, presenceBrowserFlowFn
	t.Cleanup(func() { isTerminalFn, presenceBrowserFlowFn = origTerminal, origFlow })
	isTerminalFn = func() bool { return true }
	permission := new(string)
	presenceBrowserFlowFn = func(_ *APIClient, _, _ string, _ []byte, p string) (string, error) {
		*permission = p
		return token, nil
	}
	return permission
}

func writeAutomationData(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func challengePresence(w http.ResponseWriter, permission string) {
	w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="`+permission+`"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func readJSONBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

// filesContaining returns every regular file under roots whose content holds secret.
func filesContaining(t *testing.T, secret string, roots ...string) []string {
	t.Helper()
	var hits []string
	for _, root := range roots {
		require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(data), secret) {
				hits = append(hits, path)
			}
			return nil
		}))
	}
	return hits
}

func TestAutomationCommandTree(t *testing.T) {
	for _, path := range [][]string{
		{"automation", "grant", "create"},
		{"automation", "grant", "list"},
		{"automation", "grant", "revoke", "g-1"},
		{"automation", "approve", "script", "s-1"},
		{"automation", "approve", "workflow", "w-1"},
		{"automation", "approval", "revoke", "script", "s-1"},
		{"automation", "approval", "revoke", "workflow", "w-1"},
		{"automation", "pending"},
		{"automation", "mode", "get"},
		{"automation", "mode", "set", "approve"},
	} {
		found, _, err := rootCmd.Find(path)
		require.NoError(t, err, "%v", path)
		assert.NotNil(t, found.RunE, "%v must be runnable", path)
	}
}

func TestAutomationGrantCreate_RelaysPresenceAndPrintsCredentialOnce(t *testing.T) {
	const credential = "cfgms_grant_s3cr3t-credential-value-5859"
	var requests int
	var gotBody map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/automation/grants", r.URL.Path)
		if r.Header.Get("X-Presence-Token") != automationTestPresenceToken {
			challengePresence(w, "automation-grant:create")
			return
		}
		requests++
		gotBody = readJSONBody(t, r)
		writeAutomationData(w, http.StatusCreated, map[string]any{
			"grant": map[string]any{
				"id": "grant-1", "tenant_id": "acme", "name": "nightly",
				"expires_at": gotBody["expires_at"],
			},
			"credential": credential,
		})
	}))
	defer srv.Close()

	h := newAutomationHarness(t, srv.URL)
	permission := answerPresenceWith(t, automationTestPresenceToken)
	automationGrantName, automationGrantTenant, automationGrantExpiresIn = "nightly", "acme", 24*time.Hour

	before := time.Now()
	require.NoError(t, runAutomationGrantCreate(h.cmd, nil))

	assert.Equal(t, "automation-grant:create", *permission, "the presence challenge must be answered through the relay")
	assert.Equal(t, 1, requests)
	assert.Equal(t, "nightly", gotBody["name"])
	assert.Equal(t, "acme", gotBody["tenant_id"])
	expires, err := time.Parse(time.RFC3339, gotBody["expires_at"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, before.Add(24*time.Hour), expires, time.Minute)

	// The credential appears once, on stdout alone.
	assert.Equal(t, credential+"\n", h.out.String())
	assert.NotContains(t, h.err.String(), credential)
	assert.Contains(t, h.err.String(), "grant-1")

	// And cfg wrote it to no file: not into the working directory, not beside the bundle.
	assert.Empty(t, filesContaining(t, credential, h.dir, filepath.Dir(bundlePath)))
}

func TestAutomationGrantCreate_JSONOutputIsStdoutOnly(t *testing.T) {
	const credential = "cfgms_grant_json-credential-5859"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAutomationData(w, http.StatusCreated, map[string]any{
			"grant": map[string]any{"id": "grant-2"}, "credential": credential,
		})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationGrantName, automationGrantExpiresAt = "ci", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	output = "json"

	require.NoError(t, runAutomationGrantCreate(h.cmd, nil))

	assert.Equal(t, 1, strings.Count(h.out.String(), credential))
	assert.NotContains(t, h.err.String(), credential)
	assert.Empty(t, filesContaining(t, credential, h.dir))
}

func TestAutomationGrantCreate_ServerRefusalPrintsNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Audit trail unavailable; grant not created"})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationGrantName, automationGrantExpiresIn = "nightly", time.Hour

	err := runAutomationGrantCreate(h.cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Audit trail unavailable")
	assert.Empty(t, h.out.String())
}

func TestAutomationGrantCreate_EmptyCredentialIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAutomationData(w, http.StatusCreated, map[string]any{"grant": map[string]any{"id": "g"}, "credential": ""})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationGrantName, automationGrantExpiresIn = "nightly", time.Hour

	err := runAutomationGrantCreate(h.cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential")
}

func TestAutomationGrantCreate_InvalidFlagsMakeNoRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()

	cases := []struct {
		name    string
		setup   func()
		wantErr string
	}{
		{"no expiry", func() {}, "one of --expires-in or --expires-at is required"},
		{"both expiries", func() {
			automationGrantExpiresIn, automationGrantExpiresAt = time.Hour, "2030-01-01T00:00:00Z"
		}, "mutually exclusive"},
		{"negative expiry", func() { automationGrantExpiresIn = -time.Hour }, "must be positive"},
		{"bad expires-at", func() { automationGrantExpiresAt = "tomorrow" }, "RFC 3339"},
		{"blank name", func() { automationGrantName, automationGrantExpiresIn = "  ", time.Hour }, "--name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAutomationHarness(t, srv.URL)
			automationGrantName = "nightly"
			tc.setup()
			err := runAutomationGrantCreate(h.cmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
	assert.Equal(t, 0, hits)
}

func TestAutomationGrantList_Table(t *testing.T) {
	revoked := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/automation/grants", r.URL.Path)
		gotQuery = r.URL.RawQuery
		writeAutomationData(w, http.StatusOK, map[string]any{"count": 2, "grants": []map[string]any{
			{"id": "g-1", "tenant_id": "acme", "name": "nightly", "expires_at": "2031-01-01T00:00:00Z"},
			{"id": "g-2", "tenant_id": "acme", "name": "old", "expires_at": "2031-01-01T00:00:00Z", "revoked_at": revoked},
		}})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationGrantTenant = "root/acme"

	require.NoError(t, runAutomationGrantList(h.cmd, nil))

	assert.Equal(t, "tenant=root%2Facme", gotQuery)
	out := h.out.String()
	assert.Contains(t, out, "g-1")
	assert.Contains(t, out, "active")
	assert.Contains(t, out, "revoked")
	assert.NotContains(t, out, "credential")
}

func TestAutomationGrantList_EmptyAndError(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeAutomationData(w, http.StatusOK, map[string]any{"count": 0, "grants": []any{}})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)

	require.NoError(t, runAutomationGrantList(h.cmd, nil))
	assert.Contains(t, h.out.String(), "No automation grants found")

	fail = true
	err := runAutomationGrantList(h.cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list grants")
}

func TestAutomationGrantRevoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		if r.URL.Path == "/api/v1/automation/grants/missing" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Automation grant not found"})
			return
		}
		require.Equal(t, "/api/v1/automation/grants/g-1", r.URL.Path)
		writeAutomationData(w, http.StatusOK, map[string]any{"grant": map[string]any{"id": "g-1"}, "runs_ended": 2})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)

	require.NoError(t, runAutomationGrantRevoke(h.cmd, []string{"g-1"}))
	assert.Contains(t, h.out.String(), "Revoked grant g-1; 2 open run(s) ended.")

	err := runAutomationGrantRevoke(h.cmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Automation grant not found")
}

func TestAutomationApprove_RelaysPresence(t *testing.T) {
	for _, tc := range []struct {
		kind, idField, path string
	}{
		{automationKindScript, "script_id", "/api/v1/automation/approvals/scripts"},
		{automationKindWorkflow, "workflow_id", "/api/v1/automation/approvals/workflows"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var gotBody map[string]any
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, tc.path, r.URL.Path)
				if r.Header.Get("X-Presence-Token") != automationTestPresenceToken {
					challengePresence(w, "content-approval:approve")
					return
				}
				gotBody = readJSONBody(t, r)
				writeAutomationData(w, http.StatusCreated, map[string]any{"state": "approved"})
			}))
			defer srv.Close()
			h := newAutomationHarness(t, srv.URL)
			permission := answerPresenceWith(t, automationTestPresenceToken)
			automationVersion, automationApprovalHash, automationContentHash = "1.2.0", "hash-a", "hash-c"

			require.NoError(t, runAutomationApprove(h.cmd, tc.kind, "item-1"))

			assert.Equal(t, "content-approval:approve", *permission)
			assert.Equal(t, map[string]any{
				tc.idField: "item-1", "version": "1.2.0", "approval_hash": "hash-a", "content_hash": "hash-c",
			}, gotBody)
			assert.Contains(t, h.out.String(), "Approved "+tc.kind+" item-1 version 1.2.0.")
		})
	}
}

func TestAutomationApprove_HashMismatchAndNonInteractive(t *testing.T) {
	var presenceChallenges int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Presence-Token") == "" && r.URL.Path == "/api/v1/automation/approvals/workflows" {
			presenceChallenges++
			challengePresence(w, "content-approval:approve")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Hash does not match the stored script version"})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationVersion, automationApprovalHash = "1.0.0", "stale"

	err := runAutomationApprove(h.cmd, automationKindScript, "s-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Hash does not match")

	// Without a terminal the presence relay still runs (it only prints a URL and polls):
	// the step-up handler routes the presence challenge to it for the named permission.
	permission := answerPresenceWith(t, automationTestPresenceToken)
	isTerminalFn = func() bool { return false }
	err = runAutomationApprove(h.cmd, automationKindWorkflow, "w-1")
	require.Error(t, err)
	assert.Equal(t, "content-approval:approve", *permission, "the relay is invoked for the named permission without a terminal")
	// The request was replayed with the collected token: it got past the presence
	// challenge (still counted once) and reached the server's hash-mismatch rejection.
	assert.Contains(t, err.Error(), "Hash does not match")
	assert.Equal(t, 1, presenceChallenges, "only the first, token-less request was challenged")
}

func TestAutomationApprovalRevoke(t *testing.T) {
	for _, tc := range []struct{ kind, path string }{
		{automationKindScript, "/api/v1/automation/approvals/scripts/s%2F1/1.2.0/hash-a"},
		{automationKindWorkflow, "/api/v1/automation/approvals/workflows/s%2F1/1.2.0/hash-a"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodDelete, r.Method)
				gotPath = r.URL.EscapedPath()
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			h := newAutomationHarness(t, srv.URL)
			automationVersion, automationApprovalHash = "1.2.0", "hash-a"

			require.NoError(t, runAutomationApprovalRevoke(h.cmd, tc.kind, "s/1"))

			assert.Equal(t, tc.path, gotPath, "the id is escaped as one path segment")
			assert.Contains(t, h.out.String(), "Withdrew approval of "+tc.kind)
		})
	}
}

func TestAutomationApprovalRevoke_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Approval not found"})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationVersion, automationApprovalHash = "1.0.0", "h"

	err := runAutomationApprovalRevoke(h.cmd, automationKindScript, "s-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Approval not found")
	assert.Empty(t, h.out.String())
}

func TestAutomationPending_Scripts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/automation/approvals/scripts/pending", r.URL.Path)
		writeAutomationData(w, http.StatusOK, map[string]any{"changes": []map[string]any{
			{
				"script_id": "backup-all", "version": "1.1.0", "approval_hash": "hash-new",
				"previous_version": "1.0.0", "first_seen": "2030-01-01T00:00:00Z",
				"diff": "-echo old\n+echo new\x1b[31m\n",
			},
			{"script_id": "other", "version": "2.0.0", "approval_hash": "hash-o", "diff_unavailable": "no previous version"},
		}})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)

	require.NoError(t, runAutomationPending(h.cmd, nil))
	assert.Contains(t, h.out.String(), "hash-new")
	assert.NotContains(t, h.out.String(), "echo new", "the diff is shown only on request")

	h.out.Reset()
	automationShowDiff = true
	require.NoError(t, runAutomationPending(h.cmd, nil))
	assert.Contains(t, h.out.String(), "+echo new")
	assert.NotContains(t, h.out.String(), "\x1b", "control characters in a diff are escaped")
	assert.Contains(t, h.out.String(), `\x1b`)
	assert.Contains(t, h.out.String(), "(no diff: no previous version)")
}

func TestAutomationPending_ScriptsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAutomationData(w, http.StatusOK, map[string]any{"changes": []any{}})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)

	require.NoError(t, runAutomationPending(h.cmd, nil))
	assert.Contains(t, h.out.String(), "No pending changes.")
}

func TestAutomationPending_WorkflowsFiltersToPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/automation/approvals/workflows", r.URL.Path)
		writeAutomationData(w, http.StatusOK, map[string]any{"mode": "approve", "workflows": []map[string]any{
			{"workflow_id": "wf-done", "version": "1", "approval_hash": "h1", "state": "approved"},
			{"workflow_id": "wf-wait", "version": "2", "approval_hash": "h2", "state": "pending", "reason": "no approval"},
		}})
	}))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationKind = automationKindWorkflow

	require.NoError(t, runAutomationPending(h.cmd, nil))
	assert.Contains(t, h.out.String(), "wf-wait")
	assert.Contains(t, h.out.String(), "h2")
	assert.NotContains(t, h.out.String(), "wf-done")

	h.out.Reset()
	output = "json"
	require.NoError(t, runAutomationPending(h.cmd, nil))
	var parsed struct {
		Changes []map[string]any `json:"changes"`
	}
	require.NoError(t, json.Unmarshal(h.out.Bytes(), &parsed))
	require.Len(t, parsed.Changes, 1)
	assert.Equal(t, "wf-wait", parsed.Changes[0]["workflow_id"])
}

func TestAutomationPending_InvalidKindMakesNoRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)
	automationKind = "module"

	err := runAutomationPending(h.cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be script or workflow")
	assert.Equal(t, 0, hits)
}

func TestAutomationMode_GetAndSet(t *testing.T) {
	for _, kind := range []string{automationKindScript, automationKindWorkflow} {
		t.Run(kind, func(t *testing.T) {
			mode := "signed"
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/api/v1/automation/libraries/"+kind+"/mode", r.URL.Path)
				switch r.Method {
				case http.MethodGet:
				case http.MethodPut:
					if r.Header.Get("X-Presence-Token") != automationTestPresenceToken {
						challengePresence(w, "content-library:set-mode")
						return
					}
					mode = readJSONBody(t, r)["mode"].(string)
				default:
					t.Errorf("unexpected method %s", r.Method)
				}
				writeAutomationData(w, http.StatusOK, map[string]any{"kind": kind, "mode": mode})
			}))
			defer srv.Close()
			h := newAutomationHarness(t, srv.URL)
			permission := answerPresenceWith(t, automationTestPresenceToken)
			automationKind = kind

			require.NoError(t, runAutomationModeGet(h.cmd, nil))
			assert.Contains(t, h.out.String(), kind+" library approval mode: signed")

			h.out.Reset()
			require.NoError(t, runAutomationModeSet(h.cmd, []string{"approve"}))
			assert.Equal(t, "content-library:set-mode", *permission)
			assert.Equal(t, "approve", mode)
			assert.Contains(t, h.out.String(), kind+" library approval mode: approve")
		})
	}
}

func TestAutomationMode_InvalidInputMakesNoRequest(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	h := newAutomationHarness(t, srv.URL)

	err := runAutomationModeSet(h.cmd, []string{"yolo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be one of signed, approve, comment")

	automationKind = "module"
	err = runAutomationModeSet(h.cmd, []string{"approve"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be script or workflow")
	err = runAutomationModeGet(h.cmd, nil)
	require.Error(t, err)

	assert.Equal(t, 0, hits)
}

func TestAutomationCommands_NoCredentialIsAnError(t *testing.T) {
	h := newAutomationHarness(t, "https://127.0.0.1:1")
	bundlePath = filepath.Join(t.TempDir(), "absent.bundle.yaml")
	noBundle = true

	err := runAutomationGrantList(h.cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create API client")
}
