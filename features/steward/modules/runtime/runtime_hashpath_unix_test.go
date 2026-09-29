// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
)

// TestEchoModuleLifecycleWithHashFallbackRuntimeDir is the regression test for
// the macOS CI concern (PR #1897 review): on macOS, t.TempDir() returns paths
// under /var/folders/... that, joined with the socket filename, exceed the
// 104-byte sun_path limit. The runtime must hash the socket name into the
// steward-private sockets directory (never /tmp) so net.Listen("unix", ...)
// succeeds.
//
// A runtimeDir of exactly 71 chars is used: the minimum that triggers the hash
// fallback (natural = 71+33 = 104 > 103) while the hash path still fits
// within the private dir (hash = 71+32 = 103 ≤ 103). shortBaseDir gives a
// predictably short base (~28 chars) to pad from.
//
// This file is !windows because sun_path — and therefore the hash fallback it
// forces — does not exist on Windows: makeSocketPath there returns a named
// pipe name and ignores runtimeDir entirely (see socket_windows.go), so there
// is no runtimeDir length this test could construct that would exercise
// anything.
func TestEchoModuleLifecycleWithHashFallbackRuntimeDir(t *testing.T) {
	const targetLen = 71
	base := shortBaseDir(t)
	if len(base) >= targetLen {
		t.Fatalf("base dir %q (%d bytes) is already >= %d", base, len(base), targetLen)
	}
	paddingLen := targetLen - len(base) - 1
	long := filepath.Join(base, strings.Repeat("d", paddingLen))
	require.NoError(t, os.MkdirAll(long, 0o755))

	rt := runtime.NewModuleRuntime(long)
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	require.NotNil(t, handle)

	ctx := context.Background()
	resp, err := handle.Client.Get(ctx, &proto.GetRequest{ResourceId: "long-path"})
	require.NoError(t, err)
	assert.Equal(t, "echo:long-path", resp.ConfigData)

	require.NoError(t, rt.Stop(handle))
}
