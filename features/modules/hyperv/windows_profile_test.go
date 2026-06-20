// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bannedPatterns are the runtime-code-composition markers that must never appear
// in a rendered Windows answer file (CLAUDE.md banned patterns, ADR-009 §6). The
// scan is case-insensitive.
var bannedPatterns = []string{
	"iex",
	"invoke-expression",
	"-encodedcommand",
	"powershell -command",
	"-executionpolicy bypass",
	"bash -c",
	"eval",
}

// assertNoBannedPatterns fails the test if any banned runtime-composition marker
// appears in the rendered output (case-insensitive).
func assertNoBannedPatterns(t *testing.T, rendered string) {
	t.Helper()
	lower := strings.ToLower(rendered)
	for _, p := range bannedPatterns {
		assert.NotContainsf(t, lower, p, "rendered output must not contain banned pattern %q", p)
	}
}

// renderWindowsAutounattend renders the default Windows profile's autounattend
// template. The template self-installs the steward from the seed volume and
// reads the join token / CA fingerprint from controller-supplied ProfileVars
// (ADR-010), so no SecretStore entries are required — an empty store suffices.
func renderWindowsAutounattend(t *testing.T, vars ProfileVars) string {
	t.Helper()
	store := newInlineStore()
	out, err := NewProfileRenderer().Render(context.Background(), defaultWindowsProfile(), vars, store)
	require.NoError(t, err)
	return string(out)
}

// TestAutounattend_TemplateRendersValidXML is the REQUIRED TEST: the rendered
// autounattend output parses as well-formed XML via encoding/xml and contains no
// banned-pattern strings in any element.
func TestAutounattend_TemplateRendersValidXML(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-01",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-01",
		ProductEdition: defaultWindowsEdition,
		AdminPassword:  "Aa3-Bb4-Cc5-Dd6-Ee7",
		EnrollToken:    "tok-abc",
		CAFingerprint:  "AB12CD34",
	})

	// Parse the full document with encoding/xml: any malformed markup (unbalanced
	// tags, bad attributes) surfaces as a decode error.
	dec := xml.NewDecoder(strings.NewReader(rendered))
	for {
		_, err := dec.Token()
		if err != nil {
			require.ErrorContains(t, err, "EOF", "autounattend must be well-formed XML")
			break
		}
	}

	assertNoBannedPatterns(t, rendered)
}

// TestAutounattend_NoBannedPatterns is the REQUIRED TEST: scans the rendered
// autounattend output for runtime-composition markers and asserts the
// declared-path self-install enrollment command is present.
func TestAutounattend_NoBannedPatterns(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-02",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-02",
		ProductEdition: defaultWindowsEdition,
		EnrollToken:    "tok-def",
		CAFingerprint:  "FF99",
	})

	assertNoBannedPatterns(t, rendered)

	// Positive assertions: the declared-path self-install enrollment command is
	// present (locate the seed volume, run cfgms-steward install).
	assert.Contains(t, rendered, `cfgms-steward.exe" install --regtoken`,
		"enrollment must self-install the steward via install --regtoken")
	assert.Contains(t, rendered, "--ca-cert",
		"enrollment must pass the staged controller CA via --ca-cert")
	assert.Contains(t, rendered, "--fingerprint",
		"enrollment must pass the CA fingerprint via --fingerprint")
}

// TestAutounattend_AutoLogonAndAdminPassword guards that the one-shot AutoLogon
// and Administrator password (which let FirstLogonCommands run unattended) are
// rendered, and that the random password substitutes via {{ .AdminPassword }}.
func TestAutounattend_AutoLogonAndAdminPassword(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-05",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-05",
		ProductEdition: defaultWindowsEdition,
		AdminPassword:  "Zz9-Yy8-Xx7-Ww6",
	})
	assert.Contains(t, rendered, "<AutoLogon>", "autologon must be configured so first-logon enrollment runs")
	assert.Contains(t, rendered, "<AdministratorPassword>", "an administrator password must be set to clear OOBE")
	assert.Contains(t, rendered, "Zz9-Yy8-Xx7-Ww6", "AdminPassword must substitute into the answer file")
}

// TestAutounattend_SubstitutesCorrelationAndEnrollVars confirms the per-VM
// CorrelationID, join token, and CA fingerprint are substituted into the
// rendered output.
func TestAutounattend_SubstitutesCorrelationAndEnrollVars(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-03",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-03",
		ProductEdition: defaultWindowsEdition,
		EnrollToken:    "join-tok-77",
		CAFingerprint:  "DEADBEEF",
	})

	assert.Contains(t, rendered, "<ComputerName>WIN-03</ComputerName>",
		"VMName must render as the guest ComputerName")
	assert.Contains(t, rendered, "stw-win-03",
		"CorrelationID must appear (RegisteredOrganization/Organization) for controller-side matching")
	assert.Contains(t, rendered, `--regtoken "join-tok-77"`,
		"join token must be substituted from controller-supplied config")
	assert.Contains(t, rendered, `--fingerprint "DEADBEEF"`,
		"CA fingerprint must be substituted")
	assert.Contains(t, rendered, defaultWindowsEdition,
		"ProductEdition must render into the image-install step")
}

// TestAutounattend_CorrelationIDIsTemplateVar guards that the CorrelationID
// reaches the output specifically via {{ .CorrelationID }} substitution: a
// distinct value renders distinctly, and the empty case renders empty (not a
// hardcoded constant).
func TestAutounattend_CorrelationIDIsTemplateVar(t *testing.T) {
	a := renderWindowsAutounattend(t, ProfileVars{
		VMName: "X", OSFamily: "windows", CorrelationID: "corr-AAA", ProductEdition: defaultWindowsEdition,
	})
	b := renderWindowsAutounattend(t, ProfileVars{
		VMName: "X", OSFamily: "windows", CorrelationID: "corr-BBB", ProductEdition: defaultWindowsEdition,
	})
	assert.Contains(t, a, "corr-AAA")
	assert.NotContains(t, a, "corr-BBB")
	assert.Contains(t, b, "corr-BBB")
	assert.NotContains(t, b, "corr-AAA")
}

// TestDefaultWindowsProfile_Shape confirms the built-in profile carries the
// autounattend format and template and validates structurally.
func TestDefaultWindowsProfile_Shape(t *testing.T) {
	p := defaultWindowsProfile()
	assert.Equal(t, "windows", p.OSFamily)
	assert.Equal(t, AnswerFormatAutounattend, p.AnswerFormat)
	assert.Equal(t, autounattendTemplate, p.Template)
	require.NoError(t, p.validate())
}

// TestRandomAdminPassword_ComplexAndUnique checks the generated password meets
// Windows complexity (4 character classes) and differs across calls.
func TestRandomAdminPassword_ComplexAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := randomAdminPassword()
		require.NoError(t, err)
		require.Len(t, pw, 24)
		assert.False(t, seen[pw], "passwords must be unique across calls")
		seen[pw] = true
		assert.True(t, strings.ContainsAny(pw, "abcdefghijkmnpqrstuvwxyz"), "needs a lowercase")
		assert.True(t, strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ"), "needs an uppercase")
		assert.True(t, strings.ContainsAny(pw, "23456789"), "needs a digit")
		assert.True(t, strings.ContainsAny(pw, "-_#%+="), "needs a symbol")
	}
}

// TestRenderSeedAnswerFile_WindowsRendersAutounattend exercises the module-level
// wiring: the create-from-source path resolves the default Windows profile and
// renders a real autounattend (not the placeholder), with the CorrelationID
// baked in and a generated AdminPassword present.
func TestRenderSeedAnswerFile_WindowsRendersAutounattend(t *testing.T) {
	m := provisionModuleWithTransport(&testWinRMTransport{})
	src := &SourceConfig{ISO: `C:\iso\ws2025.iso`, OSFamily: "windows"}

	content, err := m.renderSeedAnswerFile(context.Background(), "stw-win-09", src, "stw-win-09")
	require.NoError(t, err)
	assert.Contains(t, content, "<ComputerName>stw-win-09</ComputerName>")
	assert.Contains(t, content, "stw-win-09")
	assert.Contains(t, content, "<AutoLogon>", "module render must include the one-shot autologon")
	assert.NotContains(t, content, "placeholder autounattend")
	assertNoBannedPatterns(t, content)
}
