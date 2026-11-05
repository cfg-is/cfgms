// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package metrics

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	in := Report{
		Version: Version, Threshold: 150, BaseCommit: "abc",
		Aggregate:          Aggregate{DuplicatedLines: 7, AnnotatedLines: 2, ProductionLines: 100, ProductionFiles: 3, Runs: 1},
		ByPackage:          map[string]int{"pkg/a": 7},
		Runs:               []Run{{File: "pkg/a/x.go", StartLine: 1, EndLine: 9, Tokens: 160}},
		InvalidAnnotations: []InvalidAnnotation{{File: "pkg/a/x.go", Line: 3, Reason: "no reason"}},
	}
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, in))
	out, err := Read(&buf)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestWriteEmptyCollectionsAreNotNull(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, Report{Version: Version}))
	s := buf.String()
	assert.Contains(t, s, `"runs": []`)
	assert.Contains(t, s, `"invalid_annotations": []`)
	assert.Contains(t, s, `"by_package": {}`)
}

func TestReadRejectsWrongVersion(t *testing.T) {
	_, err := Read(strings.NewReader(`{"version": 2}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 2")
}

func TestReadRejectsUnknownFieldAndGarbage(t *testing.T) {
	_, err := Read(strings.NewReader(`{"version": 1, "window_hashes": []}`))
	require.Error(t, err)
	_, err = Read(strings.NewReader(`not json`))
	require.Error(t, err)
}
