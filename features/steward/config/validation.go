// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"fmt"
	"strconv"
)

// validatePermissions validates that a permissions value is within valid range (0-0777 octal).
func validatePermissions(perms interface{}) error {
	var permValue int

	switch v := perms.(type) {
	case int:
		permValue = v
	case int64:
		permValue = int(v)
	case float64:
		permValue = int(v)
	case string:
		// Parse string as octal (e.g., "0644" -> 420 decimal)
		parsed, err := strconv.ParseInt(v, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid permissions string: %s (must be octal format like '0644')", v)
		}
		permValue = int(parsed)
	default:
		return fmt.Errorf("invalid permissions type: %T", perms)
	}

	// Check range: permissions must be between 0 and 0777 (octal)
	// In decimal, 0777 octal = 511 decimal
	if permValue < 0 || permValue > 0777 {
		return fmt.Errorf("invalid permissions value: %d (must be between 0 and 0777 octal)", permValue)
	}

	return nil
}
