// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteInstalled_MidWriteFailureLeavesNothing aborts the write after each
// file in turn and requires that neither root nor a staging directory remains.
func TestWriteInstalled_MidWriteFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "module.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("name: x\nversion: 1.0.0\npublisher: acme-corp\nexecutors: [steward]\n"), 0o600))
	src := filepath.Join(dir, "bin")
	require.NoError(t, os.WriteFile(src, []byte("binary"), 0o600))
	key := runtime.GOOS + "-" + runtime.GOARCH
	b, err := Assemble(AssembleSpec{ManifestPath: manifest, Binaries: map[string]PlatformBinary{key: {FileName: "tool", SourcePath: src}}})
	require.NoError(t, err)

	boom := errors.New("injected write failure")
	for _, failAfter := range []string{ManifestFileName, "tool"} {
		t.Run(failAfter, func(t *testing.T) {
			out := t.TempDir()
			root := filepath.Join(out, "root")
			writeFileHook = func(name string) error {
				if name == failAfter {
					return boom
				}
				return nil
			}
			t.Cleanup(func() { writeFileHook = nil })

			err := WriteInstalled(b, root, WriteOptions{})
			assert.ErrorIs(t, err, boom)
			assert.NoDirExists(t, root)
			left, err := os.ReadDir(out)
			require.NoError(t, err)
			assert.Empty(t, left, "no staging directory is left behind")
		})
	}
}
