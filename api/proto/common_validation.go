// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package common

import "fmt"

// Validate implements the Validator interface
func (m *DNA) Validate() error {
	if m.Id == "" {
		return fmt.Errorf("DNA ID cannot be empty")
	}
	if m.LastUpdated == nil {
		return fmt.Errorf("DNA LastUpdated cannot be nil")
	}
	return nil
}
