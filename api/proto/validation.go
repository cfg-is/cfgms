// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package common

// Validator interface for proto messages that support validation
type Validator interface {
	Validate() error
}
