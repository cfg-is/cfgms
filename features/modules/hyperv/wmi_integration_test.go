// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration && windows

package hyperv

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWMITransport_GetVM_NoSuchVM hits the live WMI provider on the test host
// and asserts that querying a guaranteed-nonexistent VM returns the
// well-known {"found":false} JSON the existing vm.go parser expects.
//
// Run with:
//
//	GOOS=windows go test -tags=integration -run TestWMITransport_GetVM_NoSuchVM ./features/modules/hyperv/...
//
// Requires CFGMS_HYPERV_LIVE_WMI=1 and a Windows host with the Hyper-V role
// enabled. Skips otherwise — this is the live-validation hook for #1887,
// not a CI test.
func TestWMITransport_GetVM_NoSuchVM(t *testing.T) {
	if os.Getenv("CFGMS_HYPERV_LIVE_WMI") != "1" {
		t.Skip("CFGMS_HYPERV_LIVE_WMI=1 not set — live WMI validation skipped")
	}

	tr := newWMITransport("test-tenant")
	require.NotNil(t, tr, "newWMITransport must return a usable transport on Windows")

	out, err := tr.ExecutePS(context.Background(), psGetVM,
		map[string]string{"Name": "cfgms-no-such-vm__guaranteed-missing"})
	require.NoError(t, err)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &resp),
		"output must be valid JSON in psGetVM shape")
	assert.Equal(t, false, resp["found"],
		"missing VM must surface as {\"found\":false} so vm.go:getVM emits state:absent")
}
