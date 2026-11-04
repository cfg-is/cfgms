// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package batchjob implements fleet-wide rolling batch update jobs. The job
// types and store contract live in pkg/storage/interfaces/business.
package batchjob

// StewardMeta carries the minimal per-steward context the executor and
// QuorumChecker need. Using a local type keeps the batchjob package free of
// the fleet import — avoiding the potential cycle batchjob → fleet → business.
type StewardMeta struct {
	// ID is the steward's unique identifier.
	ID string

	// DNAAttributes holds device DNA key/value pairs (e.g. "cluster_role": "hyperv-cluster").
	DNAAttributes map[string]string
}
