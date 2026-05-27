// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package common

// Validator interface for proto messages that support validation
type Validator interface {
	Validate() error
}
