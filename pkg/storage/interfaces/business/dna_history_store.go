// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package business defines business-data storage contracts for CFGMS
package business

import "context"

// DNAHistoryStore defines storage access for DNA snapshot history.
// Used by drift detection to fetch previously captured DNA for a device.
//
// The options and return types are deliberately loose (interface{}) so this
// contract avoids a circular dependency with the DNA feature package.
// Callers should type-assert to the concrete DNA history options/result
// types they expect from the configured storage backend.
type DNAHistoryStore interface {
	GetHistory(ctx context.Context, deviceID string, options interface{}) (interface{}, error)
}
