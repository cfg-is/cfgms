// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleRefRE_ValidRefs(t *testing.T) {
	valid := []string{
		"cfgms/hyperv@0.2.1",
		"acme-corp/custom-module@1.3.0",
		"publisher/name@version",
		"a/b@c",
		"vendor_a/tool.v2@1.0.0-rc1",
	}
	for _, ref := range valid {
		assert.True(t, moduleRefRE.MatchString(ref), "expected valid ref: %q", ref)
	}
}

func TestModuleRefRE_InvalidRefs(t *testing.T) {
	invalid := []string{
		"no-at-sign",
		"publisher/name",
		"@version",
		"/name@version",
		"publisher//name@version",
		"publisher/name@",
		"publisher name@version",
		"../evil/name@version",
	}
	for _, ref := range invalid {
		assert.False(t, moduleRefRE.MatchString(ref), "expected invalid ref: %q", ref)
	}
}

// TestModuleListCmd_StatusValidation verifies the status flag rejects illegal values.
// Only the validation path is tested here; valid statuses proceed to network I/O
// which is out of scope for unit tests.
func TestModuleListCmd_StatusValidation(t *testing.T) {
	invalidStatuses := []string{"invalid", "PENDING", "Approved", "queued", "ALL"}
	for _, s := range invalidStatuses {
		t.Run("invalid_"+s, func(t *testing.T) {
			origStatus := moduleListStatus
			moduleListStatus = s
			defer func() { moduleListStatus = origStatus }()

			err := runModuleList(moduleListCmd, nil)
			assert.ErrorContains(t, err, "invalid --status", "status %q must be rejected", s)
		})
	}
}

func TestModuleApproveCmd_ParsesRef(t *testing.T) {
	// Verify that a well-formed ref passes moduleRefRE validation.
	ref := "cfgms/hyperv@0.2.1"
	require.True(t, moduleRefRE.MatchString(ref))

	// Verify that runModuleApprove rejects an invalid ref without calling the API.
	err := runModuleApprove(moduleApproveCmd, []string{"invalid-ref-no-at"})
	assert.ErrorContains(t, err, "invalid module reference")
}

func TestShortHash(t *testing.T) {
	assert.Equal(t, "abc123def456...", shortHash("abc123def456xyz"))
	assert.Equal(t, "abc123", shortHash("abc123"))
	assert.Equal(t, "abc123456789", shortHash("abc123456789"))
}

// TestModuleListCmd_NoTenantFlag is AC2: --tenant must no longer be a
// registered flag on `cfg module list`, so parsing it fails with cobra's
// standard "unknown flag" error rather than silently being ignored.
func TestModuleListCmd_NoTenantFlag(t *testing.T) {
	assert.Nil(t, moduleListCmd.Flags().Lookup("tenant"), "moduleListCmd must not register --tenant")

	fs := pflag.NewFlagSet("module list", pflag.ContinueOnError)
	moduleListCmd.Flags().VisitAll(func(f *pflag.Flag) {
		fs.AddFlag(f)
	})
	err := fs.Parse([]string{"--tenant", "root/msp-a"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown flag")
}

// saveModuleFlags snapshots module-related global flags and returns a restore func.
func saveModuleFlags(t *testing.T) func() {
	t.Helper()
	origAPIURL := moduleAPIURL
	origStatus := moduleListStatus
	origJSON := moduleListJSON
	origBundlePath := bundlePath
	origContentHash := moduleApproveContentHash

	return func() {
		moduleAPIURL = origAPIURL
		moduleListStatus = origStatus
		moduleListJSON = origJSON
		bundlePath = origBundlePath
		moduleApproveContentHash = origContentHash
	}
}

// setupModuleTest creates a real HTTP test server, a real admin mTLS bundle
// pointed at it, and wires bundlePath so getModuleAPIClient resolves it.
// Plain HTTP is used intentionally (see webauthn_test.go's newWebAuthnListServer
// doc comment): the client TLS config is built but no handshake occurs.
func setupModuleTest(t *testing.T, handler http.HandlerFunc) (*httptest.Server, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	restore := saveModuleFlags(t)
	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	return srv, restore
}

// TestRunModuleList_HappyPath verifies runModuleList unwraps the APIResponse
// envelope ({"data": {"modules": [...], "total": N}}) into moduleListResponse —
// a bare (non-enveloped) decode would silently leave Modules nil and Total 0.
func TestRunModuleList_HappyPath(t *testing.T) {
	var gotPath string
	_, restore := setupModuleTest(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"modules":[
			{"publisher":"cfgms","name":"hyperv","version":"0.2.1","content_hash":"AAAA","status":"pending"},
			{"publisher":"cfgms","name":"firewall","version":"1.0.0","content_hash":"BBBB","status":"approved"}
		],"total":2},"timestamp":"2026-01-01T00:00:00Z"}`))
	})
	defer restore()

	moduleListStatus = "pending"
	moduleListJSON = true

	var out bytes.Buffer
	moduleListCmd.SetOut(&out)
	t.Cleanup(func() { moduleListCmd.SetOut(nil) })

	require.NoError(t, runModuleList(moduleListCmd, nil))
	assert.Contains(t, out.String(), "hyperv")
	assert.Contains(t, out.String(), "firewall")
	assert.Contains(t, gotPath, "/api/v1/modules")
	assert.Contains(t, gotPath, "status=pending")
	assert.NotContains(t, gotPath, "tenant")
}

// TestRunModuleApprove_Success verifies runModuleApprove resolves the ref
// against GET /api/v1/modules/approvals's pending set and POSTs approve using
// that entry's address, rather than guessing a path (Issue #4270, AC3).
func TestRunModuleApprove_Success(t *testing.T) {
	const wantAddress = "cfgms:hyperv:0.2.1:AAAA"
	var approvePath string
	_, restore := setupModuleTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/modules/approvals":
			_, _ = w.Write([]byte(`{"data":{"pending":[
				{"address":"` + wantAddress + `","publisher":"cfgms","name":"hyperv","version":"0.2.1","content_hash":"AAAA"}
			]},"timestamp":"2026-01-01T00:00:00Z"}`))
		case r.Method == http.MethodPost:
			approvePath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"status":"approved"},"timestamp":"2026-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer restore()

	var out bytes.Buffer
	moduleApproveCmd.SetOut(&out)
	t.Cleanup(func() { moduleApproveCmd.SetOut(nil) })

	err := runModuleApprove(moduleApproveCmd, []string{"cfgms/hyperv@0.2.1"})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/modules/approvals/"+wantAddress+"/approve", approvePath)
	// The success line must bind the operator's confirmation to specific content.
	assert.Contains(t, out.String(), "cfgms/hyperv@0.2.1")
	assert.Contains(t, out.String(), "AAAA")
}

// pendingQueueHandler serves the given pending entries from
// GET /api/v1/modules/approvals and records any approve POST path.
func pendingQueueHandler(t *testing.T, pendingJSON string, approvePath *string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/modules/approvals":
			_, _ = w.Write([]byte(`{"data":{"pending":[` + pendingJSON + `]},"timestamp":"2026-01-01T00:00:00Z"}`))
		case r.Method == http.MethodPost:
			*approvePath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"status":"approved"},"timestamp":"2026-01-01T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// ambiguousPendingJSON is two distinct bundles queued under the same
// publisher/name@version — possible because the cache key includes the content
// hash, and because an unknown publisher is queued before signature verification
// (so the publisher name is self-asserted at that point).
const ambiguousPendingJSON = `
	{"address":"cfgms:hyperv:0.2.1:aaaa1111","publisher":"cfgms","name":"hyperv","version":"0.2.1","content_hash":"aaaa1111reviewed"},
	{"address":"cfgms:hyperv:0.2.1:bbbb2222","publisher":"cfgms","name":"hyperv","version":"0.2.1","content_hash":"bbbb2222attacker"}`

// TestRunModuleApprove_AmbiguousRefIsRefused is the core of the approval-confusion
// fix: when a ref matches more than one pending bundle, approve must fail naming
// every candidate content hash and must NOT approve any of them (Issue #4270).
func TestRunModuleApprove_AmbiguousRefIsRefused(t *testing.T) {
	var approvePath string
	_, restore := setupModuleTest(t, pendingQueueHandler(t, ambiguousPendingJSON, &approvePath))
	defer restore()

	moduleApproveContentHash = ""

	err := runModuleApprove(moduleApproveCmd, []string{"cfgms/hyperv@0.2.1"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "matches 2 pending bundles")
	assert.ErrorContains(t, err, "--content-hash")
	assert.ErrorContains(t, err, "aaaa1111reviewed")
	assert.ErrorContains(t, err, "bbbb2222attacker")
	assert.Empty(t, approvePath, "no bundle may be approved for an ambiguous ref")
}

// TestRunModuleApprove_ContentHashSelectsBundle verifies --content-hash resolves
// the ambiguous case to the exact reviewed bundle, by full value and by prefix.
func TestRunModuleApprove_ContentHashSelectsBundle(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentHash string
		wantAddress string
	}{
		{"full_hash", "bbbb2222attacker", "cfgms:hyperv:0.2.1:bbbb2222"},
		{"unique_prefix", "aaaa", "cfgms:hyperv:0.2.1:aaaa1111"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var approvePath string
			_, restore := setupModuleTest(t, pendingQueueHandler(t, ambiguousPendingJSON, &approvePath))
			defer restore()

			moduleApproveContentHash = tc.contentHash

			var out bytes.Buffer
			moduleApproveCmd.SetOut(&out)
			t.Cleanup(func() { moduleApproveCmd.SetOut(nil) })

			require.NoError(t, runModuleApprove(moduleApproveCmd, []string{"cfgms/hyperv@0.2.1"}))
			assert.Equal(t, "/api/v1/modules/approvals/"+tc.wantAddress+"/approve", approvePath)
		})
	}
}

// TestRunModuleApprove_ContentHashNoMatch verifies a content hash that matches no
// pending bundle fails instead of falling back to the ref-only match.
func TestRunModuleApprove_ContentHashNoMatch(t *testing.T) {
	var approvePath string
	_, restore := setupModuleTest(t, pendingQueueHandler(t, ambiguousPendingJSON, &approvePath))
	defer restore()

	moduleApproveContentHash = "cccc3333"

	err := runModuleApprove(moduleApproveCmd, []string{"cfgms/hyperv@0.2.1"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "not found in pending approval queue")
	assert.Empty(t, approvePath)
}

// TestSelectPendingApproval covers the resolution table directly, including the
// ambiguous-prefix case that must not silently pick a candidate.
func TestSelectPendingApproval(t *testing.T) {
	pending := []moduleApprovalQueueEntry{
		{Address: "cfgms:hyperv:0.2.1:aa", Publisher: "cfgms", Name: "hyperv", Version: "0.2.1", ContentHash: "aa11"},
		{Address: "cfgms:hyperv:0.2.1:ab", Publisher: "cfgms", Name: "hyperv", Version: "0.2.1", ContentHash: "ab11"},
		{Address: "cfgms:other:1.0.0:cc", Publisher: "cfgms", Name: "other", Version: "1.0.0", ContentHash: "cc11"},
	}

	t.Run("unique_triple_needs_no_hash", func(t *testing.T) {
		got, err := selectPendingApproval(pending, "cfgms", "other", "1.0.0", "")
		require.NoError(t, err)
		assert.Equal(t, "cc11", got.ContentHash)
	})

	t.Run("ambiguous_triple_refused", func(t *testing.T) {
		_, err := selectPendingApproval(pending, "cfgms", "hyperv", "0.2.1", "")
		require.Error(t, err)
		assert.ErrorContains(t, err, "matches 2 pending bundles")
	})

	t.Run("ambiguous_prefix_refused", func(t *testing.T) {
		_, err := selectPendingApproval(pending, "cfgms", "hyperv", "0.2.1", "a")
		require.Error(t, err)
		assert.ErrorContains(t, err, "prefix of more than one candidate")
	})

	t.Run("unique_prefix_resolves", func(t *testing.T) {
		got, err := selectPendingApproval(pending, "cfgms", "hyperv", "0.2.1", "ab")
		require.NoError(t, err)
		assert.Equal(t, "cfgms:hyperv:0.2.1:ab", got.Address)
	})

	// A hash pasted in the URL-safe rendering (from a composite address) must
	// select the same bundle as its standard-base64 rendering.
	t.Run("url_safe_rendering_matches", func(t *testing.T) {
		withSlash := []moduleApprovalQueueEntry{
			{Address: "cfgms:hyperv:0.2.1:a_b-c", Publisher: "cfgms", Name: "hyperv", Version: "0.2.1", ContentHash: "a/b+c=="},
		}
		got, err := selectPendingApproval(withSlash, "cfgms", "hyperv", "0.2.1", "a_b-c")
		require.NoError(t, err)
		assert.Equal(t, "a/b+c==", got.ContentHash)

		got, err = selectPendingApproval(withSlash, "cfgms", "hyperv", "0.2.1", "a/b+c==")
		require.NoError(t, err)
		assert.Equal(t, "a/b+c==", got.ContentHash)
	})

	t.Run("empty_queue", func(t *testing.T) {
		_, err := selectPendingApproval(nil, "cfgms", "hyperv", "0.2.1", "")
		require.Error(t, err)
		assert.ErrorContains(t, err, "not found in pending approval queue")
	})
}

// TestRunModuleApprove_NotFoundInQueue verifies that a ref with no matching
// pending entry fails client-side with a clear error and never calls approve.
func TestRunModuleApprove_NotFoundInQueue(t *testing.T) {
	approveCalled := false
	_, restore := setupModuleTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/modules/approvals":
			_, _ = w.Write([]byte(`{"data":{"pending":[
				{"address":"cfgms:other:1.0.0:CCCC","publisher":"cfgms","name":"other","version":"1.0.0","content_hash":"CCCC"}
			]},"timestamp":"2026-01-01T00:00:00Z"}`))
		case r.Method == http.MethodPost:
			approveCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer restore()

	err := runModuleApprove(moduleApproveCmd, []string{"cfgms/hyperv@0.2.1"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "not found in pending approval queue")
	assert.False(t, approveCalled, "approve must not be called for an unresolved ref")
}
