// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package grpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
)

// TestChunksToDNATransfer_TenantIDMismatch_SanitizesErrorText is the required
// log-injection regression test for pkg/dataplane/providers/grpc/stream.go
// (Issue #4341). TenantId is a peer-supplied field carried on the wire
// inside a DNAChunk — a compromised or malicious steward controls its
// content. chunksToDNATransfer previously embedded it, raw, into the
// tenant-mismatch error's message text via fmt.Errorf's %q verb. Any caller
// that eventually logs that error (directly, or via
// logging.SanitizeLogValue(err.Error()) applied to a value that was never
// itself cleaned at the source) must not see a forged CR/LF-delimited log
// line smuggled in through the wire-controlled TenantId.
func TestChunksToDNATransfer_TenantIDMismatch_SanitizesErrorText(t *testing.T) {
	const maliciousTenantID = "tenant-b\r\nINJECTED: fake log line\nlevel=error msg=forged"

	chunks := []*transportpb.DNAChunk{
		{StewardId: "s1", TenantId: "tenant-a", Data: []byte("x"), ChunkIndex: 0, TotalChunks: 2},
		{StewardId: "s1", TenantId: maliciousTenantID, Data: []byte("y"), ChunkIndex: 1, TotalChunks: 2},
	}

	_, err := chunksToDNATransfer(chunks)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTenantIDInconsistent))

	msg := err.Error()
	assert.NotContains(t, msg, "\r", "error text must not carry a raw CR from wire-supplied TenantId")
	assert.NotContains(t, msg, "\n", "error text must not carry a raw LF from wire-supplied TenantId")
}

// TestChunksToBulkTransfer_ChecksumMismatch_SanitizesErrorText covers the
// second wire-controlled string embedded in a stream.go error: the
// "checksum" key of a BulkChunk's peer-supplied Metadata map.
// chunksToBulkTransfer previously embedded that value raw into
// ErrChecksumMismatch's message text via %s.
func TestChunksToBulkTransfer_ChecksumMismatch_SanitizesErrorText(t *testing.T) {
	const maliciousChecksum = "sha256:bad\r\nINJECTED: fake log line\nlevel=error msg=forged"

	payload := []byte("actual payload")
	chunks := []*transportpb.BulkChunk{{
		TransferId: "bulk-tamper",
		Data:       payload,
		Offset:     0,
		TotalSize:  int64(len(payload)),
		IsLast:     true,
		Metadata: map[string]string{
			"checksum": maliciousChecksum,
		},
	}}

	_, err := chunksToBulkTransfer(chunks)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrChecksumMismatch))

	msg := err.Error()
	assert.NotContains(t, msg, "\r", "error text must not carry a raw CR from wire-supplied checksum metadata")
	assert.NotContains(t, msg, "\n", "error text must not carry a raw LF from wire-supplied checksum metadata")
}
