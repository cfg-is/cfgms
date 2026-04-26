// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package file

import "errors"

var (
	// ErrAllowedBasePathRequired is returned when AllowedBasePath is missing or non-absolute.
	// See docs/modules/file.md for configuration guidance and migration instructions.
	ErrAllowedBasePathRequired = errors.New("AllowedBasePath is required and must be an absolute path; see docs/modules/file.md")
)
