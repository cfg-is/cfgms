// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines storage interfaces for the controller business tier.
package business

import (
	"github.com/cfgis/cfgms/features/controller/batchjob"
)

// ErrBatchJobNotFound is returned when a batch job record does not exist.
// Re-exported from the batchjob package so callers that already import business
// continue to work unchanged.
var ErrBatchJobNotFound = batchjob.ErrBatchJobNotFound

// BatchJobStore defines the storage interface for fleet rolling-batch job persistence.
// Re-exported from the batchjob package as a type alias to break the import cycle:
//
//	batchjob (executor/store) → business → batchjob
//
// Because it is a type alias (=) callers that declare variables as business.BatchJobStore
// or pass implementations to functions accepting batchjob.BatchJobStore interchangeably
// continue to compile and behave identically.
//
// All implementations must be safe for concurrent use.
type BatchJobStore = batchjob.BatchJobStore
