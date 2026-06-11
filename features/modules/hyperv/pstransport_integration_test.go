// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration && windows

package hyperv

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPSHostTransport_GetVM_NoSuchVM hits the persistent PS host against a
// guaranteed-nonexistent VM and asserts the well-known {"found":false}
// shape that vm.go:getVM expects (post-F14 contract: parses out as
// state:absent in the executor's drift check).
//
// Run:
//
//	GOOS=windows go test -tags=integration -run TestPSHostTransport_GetVM_NoSuchVM \
//	    ./features/modules/hyperv/...
//
// Requires CFGMS_HYPERV_LIVE_PS=1 + Hyper-V role installed on the host.
func TestPSHostTransport_GetVM_NoSuchVM(t *testing.T) {
	if os.Getenv("CFGMS_HYPERV_LIVE_PS") != "1" {
		t.Skip("CFGMS_HYPERV_LIVE_PS=1 not set — live PS host validation skipped")
	}

	ctx := context.Background()
	tr, err := newPSHostTransport(ctx)
	require.NoError(t, err, "PS host must start with preamble loaded")
	t.Cleanup(func() { _ = tr.Close() })

	out, err := tr.ExecutePS(ctx, psGetVM,
		map[string]string{"Name": "cfgms-no-such-vm__guaranteed-missing"})
	require.NoError(t, err, "Cfgms-GetVM dispatch must succeed")

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, false, resp["found"],
		"missing VM must surface as {\"found\":false} so vm.go:getVM emits state:absent")
}

// TestPSHostTransport_SessionReuse exercises the persistent-session
// optimisation directly — two Get calls on the same transport must both
// succeed without re-spawning powershell.exe. This is the whole reason for
// the design over per-call exec.
func TestPSHostTransport_SessionReuse(t *testing.T) {
	if os.Getenv("CFGMS_HYPERV_LIVE_PS") != "1" {
		t.Skip("CFGMS_HYPERV_LIVE_PS=1 not set — live PS host validation skipped")
	}

	ctx := context.Background()
	tr, err := newPSHostTransport(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	// First call — proves preamble + dispatch work
	out1, err := tr.ExecutePS(ctx, psGetVM,
		map[string]string{"Name": "cfgms-reuse-test__call-one"})
	require.NoError(t, err)
	assert.Contains(t, out1, `"found":false`)

	// Second call on the SAME transport — proves the host stayed alive
	// across calls and the sentinel framing recovers cleanly
	out2, err := tr.ExecutePS(ctx, psGetVM,
		map[string]string{"Name": "cfgms-reuse-test__call-two"})
	require.NoError(t, err)
	assert.Contains(t, out2, `"found":false`)
}

// TestPSHostTransport_GetVSwitch_NoSuchSwitch covers the vSwitch read path
// — same shape as VM, distinct dispatch case.
func TestPSHostTransport_GetVSwitch_NoSuchSwitch(t *testing.T) {
	if os.Getenv("CFGMS_HYPERV_LIVE_PS") != "1" {
		t.Skip("CFGMS_HYPERV_LIVE_PS=1 not set — live PS host validation skipped")
	}

	ctx := context.Background()
	tr, err := newPSHostTransport(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	out, err := tr.ExecutePS(ctx, psGetVSwitch,
		map[string]string{"Name": "cfgms-no-such-vswitch__missing"})
	require.NoError(t, err)
	assert.Contains(t, out, `"found":false`)
}

// TestPSHostTransport_SurfacesPSErrors verifies that a PS-side failure
// (here: requesting Start-VM on a name that doesn't exist) is surfaced as
// a Go error containing the PS error message — i.e. the stderr drain +
// per-call boundary actually work.
func TestPSHostTransport_SurfacesPSErrors(t *testing.T) {
	if os.Getenv("CFGMS_HYPERV_LIVE_PS") != "1" {
		t.Skip("CFGMS_HYPERV_LIVE_PS=1 not set — live PS host validation skipped")
	}

	ctx := context.Background()
	tr, err := newPSHostTransport(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })

	_, err = tr.ExecutePS(ctx, psStartVM,
		map[string]string{"Name": "cfgms-no-such-vm__guaranteed-missing-for-start"})
	require.Error(t, err, "Start-VM on missing VM must surface as a Go error")
	assert.True(t, strings.Contains(err.Error(), "Hyper-V") ||
		strings.Contains(err.Error(), "VM") ||
		strings.Contains(err.Error(), "not find") ||
		strings.Contains(err.Error(), "could not"),
		"error must contain the PS-side failure reason; got: %s", err.Error())

	// After an error, the session must still be usable for the next call.
	out, err := tr.ExecutePS(ctx, psGetVM,
		map[string]string{"Name": "cfgms-recovery-test__after-error"})
	require.NoError(t, err, "transport must remain usable after a per-call PS failure")
	assert.Contains(t, out, `"found":false`)
}
