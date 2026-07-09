// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinuxCloudInit_DebugSSHKey verifies the optional operator debug SSH public
// key is threaded into the cloud-init user-data as an ssh_authorized_keys entry
// when set, and is entirely absent (production default) when unset.
func TestLinuxCloudInit_DebugSSHKey(t *testing.T) {
	profile := defaultLinuxCloudInitProfile()
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAADEBUGKEY operator@lab"

	base := ProfileVars{
		VMName:        "stw-lin-01",
		OSFamily:      "linux",
		CorrelationID: "stw-corr-1",
		EnrollToken:   "tok",
		CAFingerprint: "abcd",
		BundleURL:     profile.Enroll.BundleURL,
	}

	// Debug key set → cloud-init adds it to the guest's authorized_keys.
	withKey := base
	withKey.DebugSSHKey = key
	out, err := NewProfileRenderer().Render(context.Background(), profile, withKey, preseedTestStore())
	require.NoError(t, err)
	rendered := string(out)
	assert.Contains(t, rendered, "ssh_authorized_keys:", "cloud-init must carry ssh_authorized_keys when a debug key is set")
	assert.Contains(t, rendered, key, "the operator's public key must appear verbatim")

	// Unset → no ssh_authorized_keys directive at all (secure default).
	out2, err := NewProfileRenderer().Render(context.Background(), profile, base, preseedTestStore())
	require.NoError(t, err)
	assert.NotContains(t, string(out2), "ssh_authorized_keys", "no debug SSH access unless explicitly configured")
}

// TestLinuxCloudInit_InstallUsesControllerCAFlag guards against the flag-name drift
// that silently broke enrollment: the cloud-init install line must invoke
// `cfgms-steward install ... --controller-ca ...` (the actual flag registered by
// the steward install command), NOT the non-existent `--ca-cert`, which aborts the
// install at flag parsing ("unknown flag: --ca-cert") so the steward never installs.
func TestLinuxCloudInit_InstallUsesControllerCAFlag(t *testing.T) {
	profile := defaultLinuxCloudInitProfile()
	out, err := NewProfileRenderer().Render(context.Background(), profile, ProfileVars{
		VMName: "stw-lin-01", OSFamily: "linux", CorrelationID: "corr-1",
		EnrollToken: "tok", CAFingerprint: "abcd", BundleURL: profile.Enroll.BundleURL,
	}, preseedTestStore())
	require.NoError(t, err)
	rendered := string(out)
	assert.Contains(t, rendered, "--controller-ca", "install must use the real --controller-ca flag")
	assert.NotContains(t, rendered, "--ca-cert", "the steward install command has no --ca-cert flag (aborts enrollment)")
}
