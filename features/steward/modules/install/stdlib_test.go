// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package install

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// [REQUIRED TEST] drift guard: StdlibModuleNames equals the sorted directory
// names under features/modules/stdlib/.
func TestStdlibModuleNames_MatchStdlibDirectories(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	stdlibDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "modules", "stdlib")
	entries, err := os.ReadDir(stdlibDir)
	require.NoError(t, err)

	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	assert.Equal(t, dirs, StdlibModuleNames())
	assert.True(t, sort.StringsAreSorted(StdlibModuleNames()))
	assert.Len(t, StdlibModuleNames(), 10)
}

func TestStdlibModuleNames_ReturnsCopy(t *testing.T) {
	n := StdlibModuleNames()
	n[0] = "tampered"
	assert.NotEqual(t, "tampered", StdlibModuleNames()[0])
	assert.True(t, isStdlibName("FILE"))
	assert.False(t, isStdlibName("widget"))
}
