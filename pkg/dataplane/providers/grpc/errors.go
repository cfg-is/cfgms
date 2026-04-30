// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import "errors"

var (
	ErrEmptyChunkList       = errors.New("dataplane: chunk list is empty")
	ErrChunkCountMismatch   = errors.New("dataplane: TotalChunks does not match received chunk count")
	ErrChunkSequenceGap     = errors.New("dataplane: chunk sequence has gap or duplicate")
	ErrPayloadTooLarge      = errors.New("dataplane: assembled payload exceeds maximum size")
	ErrTotalSizeMismatch    = errors.New("dataplane: BulkChunk TotalSize does not match assembled length")
	ErrChecksumMismatch     = errors.New("bulk transfer checksum mismatch")
	ErrTenantIDInconsistent = errors.New("DNA chunks carry inconsistent tenant IDs")
)
