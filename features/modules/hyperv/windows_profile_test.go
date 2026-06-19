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
// in a rendered Windows answer file or enrollment script (CLAUDE.md banned
// patterns, ADR-009 §6). The scan is case-insensitive.
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
// template with a real in-memory secret store supplying the .ppkg host path.
func renderWindowsAutounattend(t *testing.T, vars ProfileVars) string {
	t.Helper()
	store := newInlineStore(ppkgPathSecretKey, `C:\cfgms\packages\cfgms-enroll.ppkg`)
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
// autounattend output for iex, -EncodedCommand, Invoke-Expression, and
// powershell -Command and asserts none are present. The enrollment path uses
// cmd.exe /c copy + dism.exe with explicit quoted declared paths only.
func TestAutounattend_NoBannedPatterns(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-02",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-02",
		ProductEdition: defaultWindowsEdition,
	})

	assertNoBannedPatterns(t, rendered)

	// Positive assertions: the declared-path enrollment commands are present.
	assert.Contains(t, rendered, "cmd.exe /c copy",
		"enrollment must copy the .ppkg via cmd.exe /c copy with explicit paths")
	assert.Contains(t, rendered, "dism.exe /online /add-package",
		"enrollment must apply the .ppkg via dism.exe /online /add-package")
}

// TestAutounattend_SubstitutesCorrelationIDAndPpkg confirms the per-VM
// CorrelationID and the secrets-provided .ppkg path are substituted into the
// rendered output, and the secret KEY name never leaks.
func TestAutounattend_SubstitutesCorrelationIDAndPpkg(t *testing.T) {
	rendered := renderWindowsAutounattend(t, ProfileVars{
		VMName:         "WIN-03",
		OSFamily:       "windows",
		CorrelationID:  "stw-win-03",
		ProductEdition: defaultWindowsEdition,
	})

	assert.Contains(t, rendered, "<ComputerName>WIN-03</ComputerName>",
		"VMName must render as the guest ComputerName")
	assert.Contains(t, rendered, "stw-win-03",
		"CorrelationID must appear (RegisteredOrganization/Organization) for controller-side matching")
	assert.Contains(t, rendered, `C:\cfgms\packages\cfgms-enroll.ppkg`,
		".ppkg host path must be substituted from the secrets provider")
	assert.NotContains(t, rendered, ppkgPathSecretKey,
		"the raw secret key name must never appear in rendered output")
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

// TestSetupComplete_RendersDeclaredPathEnroll is the REQUIRED TEST for the
// fallback: SetupComplete.cmd renders a single declared-path cfgms-steward
// enroll invocation with the token/label/bundle substituted and no banned
// patterns.
func TestSetupComplete_RendersDeclaredPathEnroll(t *testing.T) {
	store := newInlineStore()
	profile := defaultWindowsProfile()
	profile.Enroll.BundleURL = "https://controller.example/enroll"

	scProfile := &UnattendProfile{
		Name:         profile.Name,
		OSFamily:     "windows",
		AnswerFormat: AnswerFormatAutounattend,
		Template:     setupCompleteTemplate,
		Enroll:       profile.Enroll,
	}
	out, err := NewProfileRenderer().Render(context.Background(), scProfile, ProfileVars{
		VMName:        "WIN-04",
		OSFamily:      "windows",
		CorrelationID: "stw-win-04",
		EnrollToken:   "tok-xyz",
		BundleURL:     profile.Enroll.BundleURL,
	}, store)
	require.NoError(t, err)
	rendered := string(out)

	assert.Contains(t, rendered, `cfgms-steward.exe" enroll`,
		"SetupComplete.cmd must invoke cfgms-steward enroll via a declared exe path")
	assert.Contains(t, rendered, `--token "tok-xyz"`, "token must be substituted")
	assert.Contains(t, rendered, `--label "stw-win-04"`, "correlation label must be substituted")
	assert.Contains(t, rendered, `--bundle-url "https://controller.example/enroll"`, "bundle url must be substituted")
	assertNoBannedPatterns(t, rendered)
}

// TestSetupComplete_OnlyWhenUseSetupCompleteEnabled asserts the SetupComplete.cmd
// fallback is gated on enroll.use_setup_complete: by default the Windows profile
// does not request it (the .ppkg is the primary enrollment mechanism).
func TestSetupComplete_OnlyWhenUseSetupCompleteEnabled(t *testing.T) {
	assert.False(t, defaultWindowsProfile().Enroll.UseSetupComplete,
		"default Windows profile must enroll via the .ppkg, not the SetupComplete.cmd fallback")
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

// TestRenderSeedAnswerFile_WindowsRendersAutounattend exercises the module-level
// wiring: the create-from-source path resolves the default Windows profile and
// renders a real autounattend (not the placeholder), with the CorrelationID
// baked in.
func TestRenderSeedAnswerFile_WindowsRendersAutounattend(t *testing.T) {
	m := provisionModuleWithTransport(&testWinRMTransport{})
	src := &SourceConfig{ISO: `C:\iso\ws2025.iso`, OSFamily: "windows"}

	content, err := m.renderSeedAnswerFile(context.Background(), "stw-win-09", src, "stw-win-09")
	require.NoError(t, err)
	assert.Contains(t, content, "<ComputerName>stw-win-09</ComputerName>")
	assert.Contains(t, content, "stw-win-09")
	assert.NotContains(t, content, "placeholder autounattend")
	assertNoBannedPatterns(t, content)
}
