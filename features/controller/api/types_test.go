// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cfgis/cfgms/api/proto/common"
)

func marshalDNAToMap(t *testing.T, dna *common.DNA) map[string]interface{} {
	t.Helper()
	info := DNAFromProto(dna)
	require.NotNil(t, info)
	raw, err := json.Marshal(info)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestDNAFromProto_CollectedAt(t *testing.T) {
	t.Run("nil LastUpdated omits collected_at", func(t *testing.T) {
		out := marshalDNAToMap(t, &common.DNA{ConfigHash: "abc"})
		assert.NotContains(t, out, "collected_at")
	})

	t.Run("zero LastUpdated omits collected_at", func(t *testing.T) {
		out := marshalDNAToMap(t, &common.DNA{LastUpdated: &timestamppb.Timestamp{}})
		assert.NotContains(t, out, "collected_at")
	})

	t.Run("set LastUpdated marshals the real time", func(t *testing.T) {
		want := time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC)
		out := marshalDNAToMap(t, &common.DNA{LastUpdated: timestamppb.New(want)})
		require.Contains(t, out, "collected_at")
		assert.Equal(t, "2026-10-05T12:30:00Z", out["collected_at"])
	})
}
