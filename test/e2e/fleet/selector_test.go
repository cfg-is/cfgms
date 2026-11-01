// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveSelectorResponse mirrors the data envelope from POST /api/v1/fleet/resolve.
type resolveSelectorResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// resolveSelector calls POST /api/v1/fleet/resolve with the given selector expression
// and returns the list of matching steward IDs. Uses s.httpClient (mTLS admin bundle).
func (s *FleetTestSuite) resolveSelector(t *testing.T, selector string) ([]string, int) {
	t.Helper()

	body, err := json.Marshal(map[string]string{"selector": selector})
	require.NoError(t, err, "marshal resolve request")

	url := fmt.Sprintf("%s/api/v1/fleet/resolve", s.controllerURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url,
		bytes.NewReader(body))
	require.NoError(t, err, "build resolve request")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	require.NoError(t, err, "POST /api/v1/fleet/resolve")
	defer func() { _ = resp.Body.Close() }()

	rawBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read resolve response body")

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}

	var result resolveSelectorResponse
	require.NoError(t, json.Unmarshal(rawBody, &result), "unmarshal resolve response: %s", string(rawBody))

	ids := make([]string, 0, len(result.Data))
	for _, item := range result.Data {
		ids = append(ids, item.ID)
	}
	return ids, resp.StatusCode
}

// TestFleetIDSelector exercises the id: selector key against real registered stewards.
//
// This test satisfies AC #6 (Issue #1913): an integration test that calls the
// POST /api/v1/fleet/resolve endpoint with an id: selector where the ID comes from
// a steward registered during the test run — not seeded in-memory data.
//
// Scenarios:
//   - Single-ID exact match returns the targeted steward and no others
//   - Unknown ID returns an empty result set (no error)
//   - Multi-value id:a,b selects both stewards (OR semantics)
func TestFleetIDSelector(t *testing.T) {
	s := setupFleetSuite(t)

	steward1ID := s.stewardIDs["fleet-steward-1"]
	steward2ID := s.stewardIDs["fleet-steward-2"]

	// Both stewards must be connected before selector tests can be meaningful.
	for _, id := range []string{steward1ID, steward2ID} {
		if !s.waitForConvergence(t, id, 30*time.Second) {
			t.Fatalf("steward %s not connected within 30s; cannot test id: selector", id)
		}
	}

	t.Run("SingleIDExactMatch", func(t *testing.T) {
		ids, status := s.resolveSelector(t, "id:"+steward1ID)
		require.Equal(t, http.StatusOK, status)
		require.Len(t, ids, 1, "id: selector must return exactly the targeted steward; got %v", ids)
		assert.Equal(t, steward1ID, ids[0])
	})

	t.Run("UnknownIDReturnsEmpty", func(t *testing.T) {
		ids, status := s.resolveSelector(t, "id:steward-nonexistent-0000000000")
		require.Equal(t, http.StatusOK, status, "unknown id: must return 200 with empty result, not an error")
		assert.Empty(t, ids, "unknown steward ID must yield empty result set")
	})

	t.Run("MultiValueOR", func(t *testing.T) {
		selector := fmt.Sprintf("id:%s,%s", steward1ID, steward2ID)
		ids, status := s.resolveSelector(t, selector)
		require.Equal(t, http.StatusOK, status)
		require.Len(t, ids, 2, "comma-separated id: must return both stewards (OR semantics); got %v", ids)
		assert.ElementsMatch(t, []string{steward1ID, steward2ID}, ids)
	})
}
