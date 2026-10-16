// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// rawHandler is a minimal slog.Handler that writes each record's message and
// attribute values verbatim, with no quoting or escaping of control
// characters — unlike slog.TextHandler and slog.JSONHandler, which both quote
// or escape "\r"/"\n" in a value on their own (strconv.Quote-style for text,
// JSON string escaping for JSON), which would silently mask an application
// that forgot to sanitize before logging. rawHandler exists so this test
// verifies logging.SanitizeLogValue was actually applied at the call site in
// manager.go, not that some downstream encoder happened to neutralize an
// unsanitized value.
type rawHandler struct {
	buf   *bytes.Buffer
	attrs []slog.Attr // attrs bound via Logger.With, applied per record in Handle
}

func (h *rawHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *rawHandler) Handle(_ context.Context, r slog.Record) error {
	fmt.Fprintf(h.buf, "msg=%s", r.Message)
	for _, a := range h.attrs {
		fmt.Fprintf(h.buf, " %s=%v", a.Key, a.Value.Any())
	}
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(h.buf, " %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.buf.WriteByte('\n')
	return nil
}

func (h *rawHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &rawHandler{buf: h.buf, attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

func (h *rawHandler) WithGroup(string) slog.Handler { return h }

// TestManager_LogsSanitizeInjectedErrorContent proves that an error returned
// from the store (writeBatch's "audit entry permanently lost" Error log and
// appendWithRetry's "append attempt failed, retrying" Warn log, manager.go)
// cannot forge log lines even when the error text carries attacker-controlled
// CR/LF, the way a store/decode error can carry caller-tainted input back out
// inside its message text (CLAUDE.md's log-sanitization rule). Issue #4341.
//
// Not a mock: store is a real flatfile-backed business.AuditStore wrapped by
// failingAppendAuditStore (defined in manager_test.go), which fails one
// specific entry's AppendChainedEntry call with an error we control while
// every other call passes through to the real backing store.
func TestManager_LogsSanitizeInjectedErrorContent(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	// injectedErr models a store/decode error whose message embeds
	// caller-tainted content, including a raw CRLF and a forged log line an
	// attacker would use to fake a second log entry (CWE-117 log forgery).
	const forgedLine = "level=ERROR msg=\"forged: admin escalated privileges\""
	injectedErr := errors.New("append failed for resource\r\n" + forgedLine)

	store := &failingAppendAuditStore{
		AuditStore: storageManager.GetAuditStore(),
		failFor:    map[string]error{"injection-target": injectedErr},
	}

	// Capture every log record the manager emits for the duration of this
	// test only; restored via t.Cleanup regardless of pass/fail. Safe here
	// because no test in this package runs in parallel (verified: no
	// t.Parallel() call in pkg/audit).
	var logBuf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(&rawHandler{buf: &logBuf}))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	manager, err := audit.NewManager(store, "log-injection-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	ctx := context.Background()
	require.NoError(t, manager.RecordEvent(ctx, audit.NewEventBuilder().
		Tenant("log-injection-tenant").
		Type(business.AuditEventConfiguration).
		Action("injection_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "injection-target", "").
		Severity(business.AuditSeverityMedium)))

	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The injected failure is permanent (failFor has no fallback), so Flush
	// is expected to report the lost entry; that behavior is already covered
	// by TestManager_LostEntriesReportedByFlushAndStop. This test only cares
	// about what reached the log while that failure was being retried and
	// recorded as lost.
	_ = manager.Flush(flushCtx)

	logged := logBuf.String()
	require.NotEmpty(t, logged, "the injected append failure must have produced at least one log record to inspect")

	assert.NotContains(t, logged, "\r",
		"a raw CR from a store error must never reach the log verbatim — it must be replaced by logging.SanitizeLogValue")

	// Every genuine record boundary is a "\n" rawHandler itself inserts at the
	// end of Handle, and every record starts with "msg=". If the injected
	// error's own "\n" reached the log unsanitized, it would split a single
	// record into two lines mid-value — the second beginning with the forged
	// "level=ERROR msg=..." text instead of "msg=", forging what looks like an
	// independent log entry (CWE-117). Asserting every line starts with
	// "msg=" catches that whether or not the forged text itself is scrubbed,
	// which is the actual injection property this test is about.
	logged = strings.TrimSuffix(logged, "\n")
	for i, line := range strings.Split(logged, "\n") {
		assert.True(t, strings.HasPrefix(line, "msg="),
			"line %d does not start with \"msg=\" — an unsanitized \"\\n\" split a record's value into a forged extra log line: %q", i, line)
	}
}

// TestManager_AuditEntryFieldsNeutralizeControlCharacters proves that
// caller-controlled strings in SessionID, ErrorCode, RequestID, ErrorMessage,
// Tags and nested Details/Changes values are stored without raw CR/LF, and
// that the chain checksum still verifies (Issue #5079).
func TestManager_AuditEntryFieldsNeutralizeControlCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager, err := audit.NewManager(storageManager.GetAuditStore(), "entry-injection-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	const inj = "x\r\nforged=1"
	ctx := context.Background()
	require.NoError(t, manager.RecordEvent(ctx, audit.NewEventBuilder().
		Tenant("entry-injection-tenant").
		Type(business.AuditEventConfiguration).
		Action("injection_action").
		User("user1", business.AuditUserTypeHuman).
		Session(inj).
		Resource("resource", "res-1", "").
		Error(inj, inj).
		Request(inj, "GET", "/p", "127.0.0.1", "ua").
		Tags([]string{"ok", inj}).
		Details(map[string]interface{}{
			"nested": map[string]interface{}{"s": inj, "n": 5},
			"list":   []interface{}{inj, 7},
		}).
		Changes(map[string]interface{}{"a": inj}, map[string]interface{}{"b": inj}, nil).
		Severity(business.AuditSeverityMedium)))

	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(flushCtx))

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{TenantID: "entry-injection-tenant", Order: "asc"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	e := entries[0]

	var values []string
	values = append(values, e.SessionID, e.ErrorCode, e.RequestID, e.ErrorMessage)
	values = append(values, e.Tags...)
	nested, ok := e.Details["nested"].(map[string]interface{})
	require.True(t, ok)
	values = append(values, nested["s"].(string))
	list, ok := e.Details["list"].([]interface{})
	require.True(t, ok)
	values = append(values, list[0].(string))
	require.NotNil(t, e.Changes)
	values = append(values, e.Changes.Before["a"].(string), e.Changes.After["b"].(string))
	for _, v := range values {
		assert.NotContains(t, v, "\r")
		assert.NotContains(t, v, "\n")
	}
	assert.Equal(t, float64(5), toFloat(nested["n"]), "non-string values must be unchanged")
	assert.Empty(t, manager.VerifyChain(entries))
}

func toFloat(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	}
	return -1
}
