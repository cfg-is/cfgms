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

func TestNearestRank20Values95thIs19th(t *testing.T) {
	series := make([]float64, 20)
	for i := range series {
		series[i] = float64((i + 1) * 10)
	}
	assert.Equal(t, 190.0, NearestRank(series, 0.95))
	assert.Equal(t, 0.0, NearestRank(nil, 0.95))
	assert.Equal(t, 10.0, NearestRank(series, 0))
	assert.Equal(t, 200.0, NearestRank(series, 1))
}

func TestSummarize(t *testing.T) {
	recs := []FuncRecord{
		{CC: 1, Volume: 1, Effort: 1}, {CC: 11, Volume: 2, Effort: 2},
		{CC: 25, Volume: 3, Effort: 3}, {CC: 55, Volume: 4, Effort: 4},
	}
	got := Summarize(recs)
	assert.Equal(t, 4, got.Functions)
	assert.Equal(t, 3, got.Hotspots)
	assert.Equal(t, 1+15+45, got.AggregateExcess)
	assert.Equal(t, 2, got.Over20)
	assert.Equal(t, 1, got.Over30)
	assert.Equal(t, 1, got.Over50)
	assert.Equal(t, 23.0, got.MeanCC)
	assert.Equal(t, 4.0, got.P95Effort)
	assert.Equal(t, Totals{}, Summarize(nil))
}

func TestWriteReadRoundTripOneFunctionPerLine(t *testing.T) {
	m := Measurement{
		SchemaVersion: SchemaVersion, BaseCommit: "abc", AnalyzerVersion: "1",
		ManifestSHA256: "def", HotspotThreshold: HotspotThreshold, Status: StatusPass, Form: FormFull,
		Segments:  map[string]Totals{"pkg": {Functions: 2}},
		Functions: []FuncRecord{{Identity: "a.go::.F#0", File: "a.go", Line: 3, Segment: "pkg", CC: 12}, {Identity: "a.go::.G#0", File: "a.go", Line: 9, Segment: "pkg", CC: 2}},
	}
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, m))
	assert.Equal(t, 2, strings.Count(buf.String(), `"id":`))
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, `"id":`) {
			assert.Contains(t, l, `"cc":`)
		}
	}
	got, err := Read(&buf)
	require.NoError(t, err)
	m.Violations = []string{}
	assert.Equal(t, m, got)
}

func TestWriteEmptyFunctionsIsValid(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, Measurement{SchemaVersion: SchemaVersion, Status: StatusError}))
	got, err := Read(&buf)
	require.NoError(t, err)
	assert.Equal(t, StatusError, got.Status)
	assert.Empty(t, got.Functions)
}

func TestReadRejectsBadSchemaAndUnknownFields(t *testing.T) {
	_, err := Read(strings.NewReader(`{"schema_version":99}`))
	assert.ErrorContains(t, err, "schema_version")
	_, err = Read(strings.NewReader(`{"schema_version":1,"bogus":1}`))
	assert.Error(t, err)
	_, err = Read(strings.NewReader(`not json`))
	assert.Error(t, err)
}

func TestHotspotsOnly(t *testing.T) {
	got := HotspotsOnly([]FuncRecord{{CC: 10}, {CC: 11}})
	require.Len(t, got, 1)
	assert.Equal(t, 11, got[0].CC)
}
