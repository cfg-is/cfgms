// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

// Exported for the external test package: the ingest caps the tests probe at
// exactly the limit and one past it.
const (
	MaxEdgesPerFragmentForTest = maxEdgesPerFragment
	MaxEdgesPerBatchForTest    = maxEdgesPerBatch
	MaxEdgesPerSubjectForTest  = maxEdgesPerSubject
)
