// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package moduleserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The client Run builds retries a throttled (429) response.
func TestNewGraphClient_RetriesThrottledResponses(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&count, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"id":"u1","userPrincipalName":"a@example.com"}`))
	}))
	defer srv.Close()

	c := newGraphClient(graph.WithBaseURL(srv.URL), graph.WithHTTPClient(srv.Client()))
	start := time.Now()
	_, err := c.GetUser(context.Background(), &auth.AccessToken{Token: "t", TokenType: "Bearer"}, "a@example.com")
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&count))
	assert.GreaterOrEqual(t, time.Since(start), time.Second)
}
