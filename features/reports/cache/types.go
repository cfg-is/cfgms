// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package cache

import "errors"

// Common cache errors
var (
	ErrCacheMiss  = errors.New("cache miss")
	ErrCacheWrite = errors.New("cache write failed")
)

// CacheStats represents cache statistics
type CacheStats struct {
	Entries int `json:"entries"`
	Expired int `json:"expired"`
	Active  int `json:"active"`
}
