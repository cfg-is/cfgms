// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenerateRequestID_IsUUIDv4(t *testing.T) {
	s := setupTestServer(t)
	id := s.generateRequestID()
	assert.Regexp(t, uuidV4Re, id, "generateRequestID must return a UUID v4")
}

func TestGenerateRequestID_Uniqueness(t *testing.T) {
	s := setupTestServer(t)
	const n = 1000

	ids := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			ids[i] = s.generateRequestID()
		}()
	}
	wg.Wait()

	seen := make(map[string]struct{}, n)
	for _, id := range ids {
		require.NotEmpty(t, id)
		assert.Regexp(t, uuidV4Re, id)
		_, dup := seen[id]
		assert.False(t, dup, "duplicate request ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, n, "expected %d unique IDs", n)
}
