// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testWorkflowHash   = strings.Repeat("ab", 32)
	testWorkflowExpiry = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func testWorkflow() WorkflowVersion {
	return WorkflowVersion{TenantID: "root/msp-a/client-1", Name: "onboard<user>&co", Version: "3", ContentHash: testWorkflowHash}
}

func TestWorkflowEnvelope_GoldenBytes(t *testing.T) {
	e, err := WorkflowEnvelope(testWorkflow(), "nonce-1", testWorkflowExpiry)
	require.NoError(t, err)
	got, err := CanonicalBytes(e)
	require.NoError(t, err)

	want, err := os.ReadFile("testdata/workflow_canonical.golden")
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))

	content, err := os.ReadFile("testdata/workflow_content.golden")
	require.NoError(t, err)
	assert.Equal(t, string(content), string(e.Content))
}

func TestWorkflowEnvelope_AnyFieldChangesChallengeHash(t *testing.T) {
	base, err := WorkflowEnvelope(testWorkflow(), "n", testWorkflowExpiry)
	require.NoError(t, err)
	baseHash, err := ChallengeHash(base)
	require.NoError(t, err)

	mutations := map[string]func(*WorkflowVersion){
		"tenant":  func(w *WorkflowVersion) { w.TenantID = "root/msp-a/client-2" },
		"name":    func(w *WorkflowVersion) { w.Name = "other" },
		"version": func(w *WorkflowVersion) { w.Version = "4" },
		"hash":    func(w *WorkflowVersion) { w.ContentHash = strings.Repeat("cd", 32) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := testWorkflow()
			mutate(&w)
			e, err := WorkflowEnvelope(w, "n", testWorkflowExpiry)
			require.NoError(t, err)
			h, err := ChallengeHash(e)
			require.NoError(t, err)
			assert.NotEqual(t, baseHash, h)
		})
	}
}

func TestWorkflowEnvelope_ChallengeHashDistinctFromOtherEnvelopes(t *testing.T) {
	e, err := WorkflowEnvelope(testWorkflow(), "n", testWorkflowExpiry)
	require.NoError(t, err)
	wfHash, err := ChallengeHash(e)
	require.NoError(t, err)

	for _, shell := range []string{ActionShell, TerminalShell, "bash", "powershell", "sh"} {
		other := e
		other.Shell = shell
		h, err := ChallengeHash(other)
		require.NoError(t, err)
		assert.NotEqual(t, wfHash, h, "shell %s", shell)
	}

	// Real action and terminal content built by their own constructors.
	actionContent, err := ActionContent(Action{Verb: "v", TargetKind: "k", TargetName: "n"})
	require.NoError(t, err)
	termContent, err := TerminalContent(testWorkflow().TenantID, "bash")
	require.NoError(t, err)
	for shell, content := range map[string][]byte{ActionShell: actionContent, TerminalShell: termContent} {
		h, err := ChallengeHash(Envelope{Content: content, Shell: shell, Targets: e.Targets, Nonce: "n", ExpiresAt: testWorkflowExpiry})
		require.NoError(t, err)
		assert.NotEqual(t, wfHash, h)
	}
}

func TestWorkflowEnvelope_TargetsIsTenant(t *testing.T) {
	e, err := WorkflowEnvelope(testWorkflow(), "n", testWorkflowExpiry)
	require.NoError(t, err)
	assert.Equal(t, []string{"root/msp-a/client-1"}, e.Targets)
	assert.Equal(t, WorkflowShell, e.Shell)
}

func TestWorkflowShell_NotScriptShell(t *testing.T) {
	assert.NotEqual(t, ActionShell, WorkflowShell)
	assert.NotEqual(t, TerminalShell, WorkflowShell)
	for _, s := range []string{"bash", "sh", "powershell", "pwsh", "cmd", "zsh"} {
		assert.NotEqual(t, s, WorkflowShell)
	}
}

func TestWorkflowEnvelope_Rejects(t *testing.T) {
	cases := map[string]func(*WorkflowVersion){
		"empty tenant":       func(w *WorkflowVersion) { w.TenantID = "" },
		"empty name":         func(w *WorkflowVersion) { w.Name = "" },
		"empty version":      func(w *WorkflowVersion) { w.Version = "" },
		"empty hash":         func(w *WorkflowVersion) { w.ContentHash = "" },
		"pipe in tenant":     func(w *WorkflowVersion) { w.TenantID = "a|b" },
		"comma in tenant":    func(w *WorkflowVersion) { w.TenantID = "a,b" },
		"control in name":    func(w *WorkflowVersion) { w.Name = "a\nb" },
		"control in version": func(w *WorkflowVersion) { w.Version = "1\x00" },
		"control in tenant":  func(w *WorkflowVersion) { w.TenantID = "a\tb" },
		"invalid utf8":       func(w *WorkflowVersion) { w.Name = "n\xff" },
		"short hash":         func(w *WorkflowVersion) { w.ContentHash = "abcd" },
		"non-hex hash":       func(w *WorkflowVersion) { w.ContentHash = strings.Repeat("zz", 32) },
		"uppercase hash":     func(w *WorkflowVersion) { w.ContentHash = strings.Repeat("AB", 32) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := testWorkflow()
			mutate(&w)
			_, err := WorkflowContent(w)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidEnvelope))
			_, err = WorkflowEnvelope(w, "n", testWorkflowExpiry)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidEnvelope))
		})
	}
}

func TestWorkflowEnvelope_RejectsBadEnvelopeFields(t *testing.T) {
	_, err := WorkflowEnvelope(testWorkflow(), "", testWorkflowExpiry)
	assert.True(t, errors.Is(err, ErrInvalidEnvelope))
	_, err = WorkflowEnvelope(testWorkflow(), "a|b", testWorkflowExpiry)
	assert.True(t, errors.Is(err, ErrInvalidEnvelope))
	_, err = WorkflowEnvelope(testWorkflow(), "n", time.Time{})
	assert.True(t, errors.Is(err, ErrInvalidEnvelope))
}

func TestWorkflowContent_ExactForm(t *testing.T) {
	got, err := WorkflowContent(WorkflowVersion{TenantID: "t", Name: "n", Version: "1", ContentHash: testWorkflowHash})
	require.NoError(t, err)
	assert.Equal(t, `{"v":1,"tenant_id":"t","name":"n","version":"1","content_hash":"`+testWorkflowHash+`"}`, string(got))
}
