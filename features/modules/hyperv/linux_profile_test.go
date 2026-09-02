// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preseedTestStore returns an empty in-memory SecretStore. The built-in Debian
// profile no longer resolves secrets at render time (ADR-010: the join token is
// a controller-supplied ProfileVar, the user password is randomized) — but
// Render still requires a non-nil store, so this supplies a real empty double.
func preseedTestStore() *inlineSecretStore {
	return newInlineStore()
}

// TestLinuxPreseed_TemplateRendersValidSyntax renders the built-in Debian 12
// preseed template with synthetic vars and asserts no template errors and the
// presence of the key preseed directives (ADR-009 §6), with the controller-
// supplied join token baked in via {{ .EnrollToken }} (ADR-010).
func TestLinuxPreseed_TemplateRendersValidSyntax(t *testing.T) {
	profile := defaultLinuxProfile()
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: "stw-lin-01",
		EnrollToken:   "reg-token-stub-value",
		AdminPassword: "Aa3-Bb4-Cc5-Dd6-Ee7",
		BundleURL:     profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.NoError(t, err, "preseed template must render without errors")

	rendered := string(out)
	for _, directive := range []string{
		"d-i partman",
		"d-i passwd",
		"late_command",
		"d-i debian-installer/locale",
		"d-i netcfg",
	} {
		assert.Contains(t, rendered, directive, "rendered preseed must contain %q", directive)
	}

	// The controller-supplied join token lands in the install command.
	assert.Contains(t, rendered, "install --regtoken reg-token-stub-value",
		"join token must be substituted into the real registration command")
	assert.NotContains(t, rendered, "cfgms-steward enroll",
		"the non-existent 'enroll' subcommand must not appear")
}

// TestLinuxPreseed_CorrelationIDInOutput asserts the CorrelationID is threaded
// into the rendered preseed as the enrollment hostname so the controller-side
// reconciler (#2050) can match the steward back to the record by hostname.
func TestLinuxPreseed_CorrelationIDInOutput(t *testing.T) {
	profile := defaultLinuxProfile()
	const corr = "stw-corr-abc123"
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: corr,
		EnrollToken:   "tok",
		AdminPassword: "Aa3-Bb4-Cc5-Dd6-Ee7",
		BundleURL:     profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.NoError(t, err)

	rendered := string(out)
	assert.Contains(t, rendered, "d-i netcfg/get_hostname string "+corr,
		"CorrelationID must be the enrollment hostname the reconciler matches on")
}

// TestLinuxPreseed_NoBannedPatterns scans the rendered preseed for the banned
// runtime-code-composition patterns (CLAUDE.md module/script rules) and asserts
// none are present.
func TestLinuxPreseed_NoBannedPatterns(t *testing.T) {
	profile := defaultLinuxProfile()
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: "stw-lin-01",
		BundleURL:     profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.NoError(t, err)

	rendered := strings.ToLower(string(out))
	for _, banned := range []string{"eval", "bash -c", "iex"} {
		assert.NotContains(t, rendered, banned,
			"rendered preseed must not contain banned pattern %q", banned)
	}
}

// TestLinuxPreseed_EnrollTokenInjectionRejectedByRenderBackstop is the
// REQUIRED TEST render-level backstop (Issue #3788): an EnrollToken value
// carrying a newline must be refused by Render even if it somehow bypassed
// Configure's enrollTokenPattern allowlist — the newline would otherwise let
// the value inject an additional preseed command into the
// `d-i preseed/late_command string` shell line.
func TestLinuxPreseed_EnrollTokenInjectionRejectedByRenderBackstop(t *testing.T) {
	profile := defaultLinuxProfile()
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-03",
		OSFamily:      "linux",
		CorrelationID: "stw-lin-03",
		EnrollToken:   "tok\nin-target rm -rf /",
		AdminPassword: "Aa3-Bb4-Cc5-Dd6-Ee7",
		BundleURL:     profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.Error(t, err, "a newline-bearing EnrollToken must be rejected by Render's defence-in-depth backstop")
	assert.Nil(t, out, "no partial output may escape a rejected render")
}
