// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
)

// newLibraryRunFixtureWithSigning is newLibraryRunFixture with the steward handler
// rebuilt around cfg. The fixture key is added to cfg.TrustedKeys as the sole trusted
// key, so a run signed by f.key is trusted and any other key is not.
func newLibraryRunFixtureWithSigning(t *testing.T, cfg script.ModuleSigningConfig) *libraryRunFixture {
	t.Helper()
	f := newLibraryRunFixture(t)
	cfg.TrustedKeys = []script.TrustedKeyEntry{{
		Name:       "library-signing-key",
		Thumbprint: computeThumbprintFromPEM(sigTestPubKeyPEM(f.key)),
	}}

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:     "steward-test",
		OnStatus:      cb,
		Logger:        newTestLogger(t),
		SigningConfig: cfg,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()
	f.handler = h
	f.events = getEvents
	return f
}

var libraryRunSigningMatrix = []struct {
	name   string
	policy script.SigningPolicy
	trust  script.TrustMode
}{
	{"empty_policy_trusted_keys", "", script.TrustModeTrustedKeys},
	{"empty_policy_any_valid", "", script.TrustModeAnyValid},
	{"none_trusted_keys", script.SigningPolicyNone, script.TrustModeTrustedKeys},
	{"none_any_valid", script.SigningPolicyNone, script.TrustModeAnyValid},
	{"optional_trusted_keys", script.SigningPolicyOptional, script.TrustModeTrustedKeys},
	{"optional_any_valid", script.SigningPolicyOptional, script.TrustModeAnyValid},
	{"required_trusted_keys", script.SigningPolicyRequired, script.TrustModeTrustedKeys},
	{"required_any_valid", script.SigningPolicyRequired, script.TrustModeAnyValid},
}

// Unsigned library content never runs on a steward, whatever the signing policy or
// trust mode: the controller's approval cannot substitute for a signature.
func TestLibraryRun_Unsigned_RefusedUnderEveryPolicyAndTrustMode(t *testing.T) {
	for _, tc := range libraryRunSigningMatrix {
		t.Run(tc.name, func(t *testing.T) {
			f := newLibraryRunFixtureWithSigning(t, script.ModuleSigningConfig{Policy: tc.policy, TrustMode: tc.trust})
			f.seed(t, "tenant-a", "unsigned-script", echoScriptBody("nope"), "", nil)

			err := f.run(t, "tenant-a", "unsigned-script", "lib-policy-unsigned")
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)
			assert.Contains(t, err.Error(), "library script requires a script signature")
			assert.Nil(t, f.completed())
		})
	}
}

// Control for the refusals above: the same fixture executes content signed by a
// trusted key under Policy required.
func TestLibraryRun_SignedByTrustedKey_ExecutedUnderPolicyRequired(t *testing.T) {
	for _, trust := range []script.TrustMode{script.TrustModeTrustedKeys, script.TrustModeAnyValid} {
		t.Run(string(trust), func(t *testing.T) {
			f := newLibraryRunFixtureWithSigning(t, script.ModuleSigningConfig{Policy: script.SigningPolicyRequired, TrustMode: trust})
			body := echoScriptBody("library-required-ok")
			f.seed(t, "tenant-a", "signed-script", body, body, f.key)

			require.NoError(t, f.run(t, "tenant-a", "signed-script", "lib-policy-signed"))
			assert.NotNil(t, f.completed(), "a library script signed by a trusted key must execute under policy required")
		})
	}
}

// any_valid does not widen library trust beyond TrustedKeys.
func TestLibraryRun_UntrustedKey_RefusedUnderAnyValidTrustMode(t *testing.T) {
	f := newLibraryRunFixtureWithSigning(t, script.ModuleSigningConfig{Policy: script.SigningPolicyRequired, TrustMode: script.TrustModeAnyValid})
	body := echoScriptBody("untrusted-any-valid")
	f.seed(t, "tenant-a", "untrusted-script", body, body, sigTestRSAKey(t))

	err := f.run(t, "tenant-a", "untrusted-script", "lib-policy-untrusted")
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Nil(t, f.completed())
}
