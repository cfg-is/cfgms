// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// auditCapturingLogger records Info and Warn calls for audit log assertions.
// It is a real implementation backed by a test buffer — not a mock of any
// CFGMS component (same pattern as the terminal log-redaction stories #979, #981).
type auditCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []auditLogEntry
}

type auditLogEntry struct {
	level string
	msg   string
	kvs   []interface{}
}

func (l *auditCapturingLogger) Info(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditLogEntry{level: "INFO", msg: msg, kvs: kvs})
}

func (l *auditCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditLogEntry{level: "WARN", msg: msg, kvs: kvs})
}

// formattedOutput renders all captured entries as "key=value" pairs for substring assertions.
func (l *auditCapturingLogger) formattedOutput() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, e := range l.entries {
		b.WriteString(e.level)
		b.WriteByte(' ')
		b.WriteString(e.msg)
		for i := 0; i+1 < len(e.kvs); i += 2 {
			fmt.Fprintf(&b, " %v=%v", e.kvs[i], e.kvs[i+1])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// kvValue returns the value associated with key across all captured entries, or nil.
func (l *auditCapturingLogger) kvValue(key string) interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				return e.kvs[i+1]
			}
		}
	}
	return nil
}

// hasLevel reports whether any entry was captured at the given level.
func (l *auditCapturingLogger) hasLevel(level string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.level == level {
			return true
		}
	}
	return false
}

func TestFlattenFieldsToKV_SortedDeterministic(t *testing.T) {
	fields := map[string]interface{}{
		"zebra":  "z",
		"apple":  "a",
		"mango":  "m",
		"banana": "b",
	}
	kv := flattenFieldsToKV(fields)
	require.Equal(t, 8, len(kv), "2 entries per field")

	// Keys must appear in alphabetical order.
	keys := make([]string, 0, 4)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		require.True(t, ok, "key at index %d must be string", i)
		keys = append(keys, k)
	}
	assert.Equal(t, []string{"apple", "banana", "mango", "zebra"}, keys)

	// Second call must return the same order.
	kv2 := flattenFieldsToKV(fields)
	for i := 0; i < len(kv); i++ {
		assert.Equal(t, kv[i], kv2[i], "index %d must be identical across calls", i)
	}
}

func TestFlattenFieldsToKV_EmptyMap(t *testing.T) {
	kv := flattenFieldsToKV(map[string]interface{}{})
	assert.Empty(t, kv)
}

func TestFlattenFieldsToKV_NilMap(t *testing.T) {
	kv := flattenFieldsToKV(nil)
	assert.Empty(t, kv)
}

func TestGenerateRequestID_UniqueUnderConcurrency(t *testing.T) {
	server := setupTestServer(t)

	const count = 1000
	ids := make([]string, count)
	var wg sync.WaitGroup
	wg.Add(count)

	for i := 0; i < count; i++ {
		i := i
		go func() {
			defer wg.Done()
			ids[i] = server.generateRequestID()
		}()
	}
	wg.Wait()

	seen := make(map[string]struct{}, count)
	for _, id := range ids {
		require.NotEmpty(t, id)
		_, duplicate := seen[id]
		assert.False(t, duplicate, "duplicate request ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, count)
}

func TestGenerateRequestID_UUIDv4Format(t *testing.T) {
	server := setupTestServer(t)
	id := server.generateRequestID()
	// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars)
	require.Len(t, id, 36)
	assert.Equal(t, '4', rune(id[14]), "UUID version nibble must be 4")
	assert.Contains(t, "89ab", string(id[19]), "UUID variant nibble must be 8, 9, a, or b")
}

func TestAuditAuthorizationDecision_DoesNotPanic(t *testing.T) {
	server := setupTestServer(t)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		decision *AuthorizationDecision
	}{
		{
			name: "granted",
			decision: &AuthorizationDecision{
				Granted:      true,
				PermissionID: "steward:read",
				Resource:     "steward:test-id",
				Action:       "read",
				Decision:     "ALLOW",
				Reason:       "API key has required permission: steward:read",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-1",
			},
		},
		{
			name: "denied",
			decision: &AuthorizationDecision{
				Granted:      false,
				PermissionID: "rbac:admin",
				Resource:     "rbac:*",
				Action:       "admin",
				Decision:     "DENY",
				Reason:       "API key lacks required permission: rbac:admin",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-1",
			},
		},
		{
			name: "cross-tenant denial produces CRITICAL severity without panic",
			decision: &AuthorizationDecision{
				Granted:      false,
				PermissionID: "steward:read",
				Resource:     "steward:*",
				Action:       "read",
				Decision:     "DENY",
				Reason:       "Cross-tenant access attempt",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-other",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				server.auditAuthorizationDecision(req, tc.decision)
			})
		})
	}
}

// TestAuditAuthorizationDecision_FieldsAppearInLogOutput verifies that after fixing
// the map-drop bug (passing a map as a single arg to a variadic logger), audit fields
// actually appear in the captured log output.
func TestAuditAuthorizationDecision_FieldsAppearInLogOutput(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	t.Run("granted path uses Info and fields appear", func(t *testing.T) {
		capLog.mu.Lock()
		capLog.entries = nil
		capLog.mu.Unlock()

		decision := &AuthorizationDecision{
			Granted:      true,
			PermissionID: "steward:read",
			Resource:     "steward:test-id",
			Action:       "read",
			Decision:     "ALLOW",
			Reason:       "API key has required permission: steward:read",
			CheckedAt:    time.Now(),
			SubjectID:    "subject-abc",
			TenantID:     "tenant-xyz",
		}
		server.auditAuthorizationDecision(req, decision)

		out := capLog.formattedOutput()
		assert.True(t, capLog.hasLevel("INFO"), "granted path must log at INFO")
		assert.Contains(t, out, "subject_id=subject-abc")
		assert.Contains(t, out, "tenant_id=tenant-xyz")
		assert.Contains(t, out, "resource=steward:test-id")
	})

	t.Run("denied path uses Warn and fields appear", func(t *testing.T) {
		capLog.mu.Lock()
		capLog.entries = nil
		capLog.mu.Unlock()

		decision := &AuthorizationDecision{
			Granted:      false,
			PermissionID: "rbac:admin",
			Resource:     "rbac:*",
			Action:       "admin",
			Decision:     "DENY",
			Reason:       "API key lacks required permission: rbac:admin",
			CheckedAt:    time.Now(),
			SubjectID:    "subject-abc",
			TenantID:     "tenant-xyz",
		}
		server.auditAuthorizationDecision(req, decision)

		out := capLog.formattedOutput()
		assert.True(t, capLog.hasLevel("WARN"), "denied path must log at WARN")
		assert.Contains(t, out, "subject_id=subject-abc")
		assert.Contains(t, out, "tenant_id=tenant-xyz")
		assert.Contains(t, out, "resource=rbac:*")
	})
}

// TestAuditAuthorizationDecision_SanitizesUserInput verifies that attacker-controlled
// fields (Reason, SubjectID, Resource, X-Request-ID header) are sanitized before
// reaching the logger — closing CodeQL go/log-injection alert #528 (CWE-117).
func TestAuditAuthorizationDecision_SanitizesUserInput(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)
	req = req.WithContext(context.Background())
	req.Header.Set("X-Request-ID", "rid\nFAKE")

	decision := &AuthorizationDecision{
		Granted:      false,
		PermissionID: "steward:read",
		Resource:     "res\x1b[31mevil\x1b[0m",
		Action:       "read",
		Decision:     "DENY",
		Reason:       "denied\n[FAKE LOG] admin granted access",
		CheckedAt:    time.Now(),
		SubjectID:    "user\x00inj",
		TenantID:     "tenant-1",
	}
	server.auditAuthorizationDecision(req, decision)

	// Assert the sanitized replacement char is present in the logged value — not just
	// absence of the bad char (absence-of-newline is insufficient because JSON encoding
	// masks newlines, but the replacement underscore is a positive signal).
	assert.Equal(t, "denied_[FAKE LOG] admin granted access", capLog.kvValue("reason"),
		"newline in Reason must be replaced with underscore")
	assert.Equal(t, "user_inj", capLog.kvValue("subject_id"),
		"null byte in SubjectID must be replaced with underscore")
	assert.Equal(t, "res_[31mevil_[0m", capLog.kvValue("resource"),
		"ESC bytes in Resource must be replaced with underscore")
	assert.Equal(t, "rid_FAKE", capLog.kvValue("request_id"),
		"newline in X-Request-ID header must be replaced with underscore")

	// Check no raw control characters in the individual logged string values.
	for _, key := range []string{"reason", "subject_id", "resource", "request_id"} {
		if s, ok := capLog.kvValue(key).(string); ok {
			assert.NotContains(t, s, "\n", "key %q must not contain LF", key)
			assert.NotContains(t, s, "\r", "key %q must not contain CR", key)
			assert.NotContains(t, s, "\x00", "key %q must not contain NUL", key)
			assert.NotContains(t, s, "\x1b", "key %q must not contain ESC", key)
		}
	}
}

// TestAuditAuthorizationDecision_SanitizesNestedConditionalVars verifies that
// SanitizeFieldsRecursive is applied to ConditionalVars, recursing into nested
// maps and slices to neutralise injected control characters.
func TestAuditAuthorizationDecision_SanitizesNestedConditionalVars(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	decision := &AuthorizationDecision{
		Granted:      true,
		PermissionID: "steward:read",
		Resource:     "steward:*",
		Action:       "read",
		Decision:     "ALLOW",
		Reason:       "allowed",
		CheckedAt:    time.Now(),
		SubjectID:    "user-1",
		TenantID:     "tenant-1",
		ConditionalVars: map[string]interface{}{
			"k": []interface{}{"a\nb"},
			"m": map[string]interface{}{"deep": "v\x00x"},
		},
	}
	server.auditAuthorizationDecision(req, decision)

	// Retrieve the sanitized conditional_vars from the captured key/value pairs.
	cv := capLog.kvValue("conditional_vars")
	require.NotNil(t, cv, "conditional_vars must be present in log output")

	cvMap, ok := cv.(map[string]interface{})
	require.True(t, ok, "conditional_vars must be a map after sanitization")

	// Nested slice: "k" → ["a_b"] (newline replaced)
	kSlice, ok := cvMap["k"].([]interface{})
	require.True(t, ok, "conditional_vars[k] must be a slice")
	require.Len(t, kSlice, 1)
	assert.Equal(t, "a_b", kSlice[0], "newline in slice element must be replaced")

	// Nested map: "m" → {"deep": "v_x"} (null byte replaced)
	mMap, ok := cvMap["m"].(map[string]interface{})
	require.True(t, ok, "conditional_vars[m] must be a nested map")
	assert.Equal(t, "v_x", mMap["deep"], "null byte in nested map value must be replaced")
}
