// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package drift

import (
	"context"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// DNAStorage is the minimal storage interface needed by drift monitoring.
// Callers supply concrete implementations (e.g. fleet/storage.Manager adapter)
// so this package has no dependency on any specific storage backend.
type DNAStorage interface {
	GetCurrent(ctx context.Context, deviceID string) (*DNAStorageRecord, error)
	GetHistory(ctx context.Context, deviceID string, opts *DNAHistoryQuery) (*DNAHistoryResult, error)
}

// DNAStorageRecord is a storage-agnostic DNA snapshot.
type DNAStorageRecord struct {
	DeviceID string
	DNA      *commonpb.DNA
	StoredAt time.Time
	Version  int64
}

// DNAHistoryQuery specifies parameters for a historical DNA query.
type DNAHistoryQuery struct {
	StartTime   time.Time
	EndTime     time.Time
	Limit       int
	IncludeData bool
}

// DNAHistoryResult holds a page of historical DNA records.
type DNAHistoryResult struct {
	Records []*DNAStorageRecord
}
