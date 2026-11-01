// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"encoding/json"
	"testing"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	dptypes "github.com/cfgis/cfgms/pkg/dataplane/types"
)

// FuzzReassembleDNA fuzzes the two json.Unmarshal calls in reassembleDNA
// (dna_handler.go:170, :174) at the compromised-steward-to-controller wire
// boundary. The function takes a typed chunk slice rather than raw bytes, so
// the fuzz input is wrapped in a single-chunk slice matching the real 1-chunk
// reassembly path. Multi-chunk ordering invariants are covered by existing
// conventional tests in dna_handler_test.go.
func FuzzReassembleDNA(f *testing.F) {
	// Seed with real DNATransfer JSON fixtures matching the steward send path.
	seeds := []map[string]string{
		{"hostname": "cfg-70-02", "os": "windows", "cpu_count": "8"},
		{"hostname": "cfg-ab-02", "os": "linux", "arch": "amd64"},
		{"os": "windows", "primary_mac": "00:15:5d:ea:a3:35", "memory_bytes": "17179869184"},
		{},
	}
	for _, attrs := range seeds {
		attrJSON, err := json.Marshal(attrs)
		if err != nil {
			f.Fatal(err)
		}
		payload, err := json.Marshal(&dptypes.DNATransfer{
			StewardID:  "fuzz-steward",
			TenantID:   "t1",
			Attributes: attrJSON,
		})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(payload)
	}

	// Empty payload seed — exercises the len(payload)==0 short-circuit.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		chunks := []*transportpb.DNAChunk{
			{
				Data:        data,
				ChunkIndex:  0,
				TotalChunks: 1,
			},
		}
		// Any panic inside reassembleDNA is a bug. Errors are expected and safe.
		_, _, _ = reassembleDNA(chunks, "fuzz-steward")
	})
}
