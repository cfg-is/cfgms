// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"time"
)

// getCurrentTimestamp returns the current time in UTC
func getCurrentTimestamp() time.Time {
	return time.Now().UTC()
}
