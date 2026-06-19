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

// preseedTestStore returns an in-memory SecretStore seeded with the secret keys
// the built-in Debian profile resolves at render time (registration token +
// crypted user password). No mocks — a real in-memory store double.
func preseedTestStore() *inlineSecretStore {
	return newInlineStore(
		"hyperv/enroll/regtoken", "reg-token-stub-value",
		"hyperv/enroll/user-password-crypted", "$6$rounds=4096$stub$cryptedstub",
	)
}

// TestLinuxPreseed_TemplateRendersValidSyntax renders the built-in Debian 12
// preseed template with synthetic vars/secrets and asserts no template errors
// and the presence of the key preseed directives (ADR-009 §6).
func TestLinuxPreseed_TemplateRendersValidSyntax(t *testing.T) {
	profile := defaultLinuxProfile()
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: "stw-lin-01",
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

	// The resolved secret value lands in the output (not the key name).
	assert.Contains(t, rendered, "reg-token-stub-value", "registration token secret must be substituted")
	assert.NotContains(t, rendered, `secret "hyperv/enroll/regtoken"`, "secret template call must be resolved, not left literal")
}

// TestLinuxPreseed_CorrelationIDInOutput asserts the CorrelationID is threaded
// into the rendered preseed (as the enrollment hostname/label) so the
// controller-side reconciler (#2050) can match the steward back to the record.
func TestLinuxPreseed_CorrelationIDInOutput(t *testing.T) {
	profile := defaultLinuxProfile()
	const corr = "stw-corr-abc123"
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: corr,
		BundleURL:     profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.NoError(t, err)

	rendered := string(out)
	assert.Contains(t, rendered, "d-i netcfg/get_hostname string "+corr,
		"CorrelationID must be the enrollment hostname hint")
	assert.Contains(t, rendered, "--label "+corr,
		"CorrelationID must be passed as the enroll label in late_command")
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
