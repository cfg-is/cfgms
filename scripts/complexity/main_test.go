// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunPrintsCountAndJSONLines(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pkg", "a.go"),
		[]byte("package pkg\n\nfunc F(a bool) {\n\tif a {\n\t}\n}\n"), 0o644))

	var out bytes.Buffer
	require.NoError(t, run(root, &out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	assert.Equal(t, "1", lines[0])
	var rec map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &rec))
	assert.Equal(t, "F", rec["name"])
	assert.EqualValues(t, 2, rec["cc"])
}

func TestRunReportsParseError(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "bad.go"), []byte("package"), 0o644))
	assert.Error(t, run(root, &bytes.Buffer{}))
}
