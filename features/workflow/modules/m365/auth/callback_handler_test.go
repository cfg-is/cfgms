// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestCallbackHandler_WithLogger_routesError verifies that server errors in the
// callback server goroutine are routed through the injected logger.
func TestCallbackHandler_WithLogger_routesError(t *testing.T) {
	mockLog := pkgtesting.NewMockLogger(false)

	handler := NewCallbackHandler()
	handler.WithLogger(mockLog)

	ctx := context.Background()
	err := handler.StartCallbackServer(ctx, "0")
	require.NoError(t, err)

	// Forcefully close the underlying listener (not via Shutdown) so that
	// server.Serve returns a non-ErrServerClosed error, triggering the log path.
	require.NotNil(t, handler.listener)
	require.NoError(t, handler.listener.Close())

	// Give the goroutine time to react and log the error.
	deadline := time.Now().Add(2 * time.Second)
	var errLogs []pkgtesting.LogEntry
	for time.Now().Before(deadline) {
		errLogs = mockLog.GetLogs("error")
		if len(errLogs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	require.NotEmpty(t, errLogs, "expected error log when listener is closed externally")
	assert.Equal(t, "callback server error", errLogs[0].Message)
}

// TestCallbackHandler_WithLogger_chainsReturn verifies that WithLogger returns
// the handler itself for chaining.
func TestCallbackHandler_WithLogger_chainsReturn(t *testing.T) {
	h := NewCallbackHandler()
	mockLog := pkgtesting.NewMockLogger(false)
	returned := h.WithLogger(mockLog)
	assert.Same(t, h, returned, "WithLogger must return the receiver for chaining")
}

// TestCallbackHandler_WithLogger_nilIsIgnored verifies that passing nil to
// WithLogger does not replace the existing logger.
func TestCallbackHandler_WithLogger_nilIsIgnored(t *testing.T) {
	h := NewCallbackHandler()
	original := h.logger
	h.WithLogger(nil)
	assert.Equal(t, original, h.logger, "nil logger should not replace the existing logger")
}

// TestCallbackHandler_defaultLogger_isNoopLogger verifies that a freshly
// constructed CallbackHandler has a non-nil logger.
func TestCallbackHandler_defaultLogger_isNoopLogger(t *testing.T) {
	h := NewCallbackHandler()
	assert.NotNil(t, h.logger, "default logger must be non-nil")
}

// TestCallbackHandler_handleCallback_escapesRequestValues verifies that
// request-derived query values are never reflected into the HTML page unescaped.
func TestCallbackHandler_handleCallback_escapesRequestValues(t *testing.T) {
	payload := "<script>alert(1)</script>"

	cases := map[string]url.Values{
		"error":    {"error": {payload}, "error_description": {payload}, "state": {"s"}},
		"code":     {"code": {"c"}, "state": {payload}},
		"state-js": {"code": {"c"}, "state": {"');alert(1);//"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			h := NewCallbackHandler()
			req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
			rec := httptest.NewRecorder()

			h.handleCallback(rec, req)

			body := rec.Body.String()
			assert.NotContains(t, body, payload)
			// The quote must arrive backslash-escaped, never terminating the JS string.
			assert.NotContains(t, body, "state: '');alert(1);//")
			assert.NotContains(t, body, "state: ''")
			// Only the page's own <script> block may exist.
			assert.Equal(t, 1, strings.Count(body, "<script>"))
		})
	}

	t.Run("escaped form is present", func(t *testing.T) {
		h := NewCallbackHandler()
		q := url.Values{"error": {payload}}
		req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		h.handleCallback(rec, req)
		assert.Contains(t, rec.Body.String(), "&lt;script&gt;alert(1)&lt;/script&gt;")
	})
}

// TestCallbackHandler_handleCallback_rendersVisibleText verifies the success and
// error pages keep their expected visible text and JS state value.
func TestCallbackHandler_handleCallback_rendersVisibleText(t *testing.T) {
	render := func(q url.Values) string {
		h := NewCallbackHandler()
		req := httptest.NewRequest(http.MethodGet, "/callback?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		h.handleCallback(rec, req)
		assert.Equal(t, "text/html", rec.Header().Get("Content-Type"))
		return rec.Body.String()
	}

	t.Run("success", func(t *testing.T) {
		body := render(url.Values{"code": {"c"}, "state": {"abc123"}})
		assert.Contains(t, body, "Microsoft 365 Authorization")
		assert.Contains(t, body, "Authorization successful! Processing your request...")
		assert.Contains(t, body, `class="status-icon success">✅`)
		assert.Contains(t, body, "<strong>Next Steps:</strong>")
		assert.Contains(t, body, "if ( true )")
		assert.Contains(t, body, `state: "abc123"`)
		assert.NotContains(t, body, "<strong>Error:</strong>")
	})

	t.Run("error", func(t *testing.T) {
		body := render(url.Values{"error": {"access_denied"}, "error_description": {"User said no"}, "state": {"s"}})
		assert.Contains(t, body, "Authorization failed. Please close this window and try again.")
		assert.Contains(t, body, `class="status-icon error">❌`)
		assert.Contains(t, body, "<strong>Error:</strong> access_denied<br>User said no<br><br>")
		assert.Contains(t, body, "if ( false )")
	})

	t.Run("missing code", func(t *testing.T) {
		body := render(url.Values{"state": {"s"}})
		assert.Contains(t, body, "Missing authorization code. Please close this window and try again.")
		assert.Contains(t, body, "<strong>Error:</strong> invalid_request")
	})
}
