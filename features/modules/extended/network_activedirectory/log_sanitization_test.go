// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// --- Minimal, self-contained BER encoding for a single LDAP SearchResultDone
// message, used to drive a real (non-mock) TCP peer that plays the part of a
// hostile/compromised directory server whose diagnosticMessage field is
// attacker-controlled. This exercises the real go-ldap client parsing path
// (ldap.GetLDAPError) rather than fabricating a Go error value, so the
// resulting error is a genuine artifact of the production code path under
// test, not a stand-in for one.

// berTLV encodes a single BER tag-length-value for content shorter than 128
// bytes (short-form length only) -- sufficient for the small fixed messages
// this test constructs.
func berTLV(tag byte, content []byte) []byte {
	if len(content) >= 128 {
		panic("berTLV: long-form length not implemented; keep test payloads short")
	}
	out := make([]byte, 0, len(content)+2)
	out = append(out, tag, byte(len(content)))
	out = append(out, content...)
	return out
}

// fakeSearchDoneMessage builds a full LDAPMessage carrying a SearchResultDone
// (protocolOp tag APPLICATION 5) with resultCode "other" (80) and the given
// (attacker-controlled) diagnosticMessage, matched to messageID.
func fakeSearchDoneMessage(messageID int64, diagnosticMessage string) []byte {
	resultCode := berTLV(0x0A, []byte{80}) // ENUMERATED: other(80)
	matchedDN := berTLV(0x04, nil)         // OCTET STRING: ""
	diag := berTLV(0x04, []byte(diagnosticMessage))

	ldapResult := append(append([]byte{}, resultCode...), matchedDN...)
	ldapResult = append(ldapResult, diag...)

	searchResDone := berTLV(0x65, ldapResult) // [APPLICATION 5] constructed

	msgID := berTLV(0x02, []byte{byte(messageID)}) // INTEGER

	body := append(append([]byte{}, msgID...), searchResDone...)
	return berTLV(0x30, body) // SEQUENCE (LDAPMessage)
}

// startFakeDirectoryServer starts a real TCP listener that accepts exactly
// one connection, reads whatever request the client sends, and replies with
// a SearchResultDone carrying diagnosticMessage as the server-supplied error
// text -- the shape of a rogue or compromised AD/LDAP peer. Returns the
// listener address.
func startFakeDirectoryServer(t *testing.T, diagnosticMessage string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write(fakeSearchDoneMessage(1, diagnosticMessage))
	}()

	return ln.Addr().String()
}

// TestGetConnectionStatus_SanitizesLDAPErrorInWarnLog forces a real LDAP
// search error -- carrying a CR/LF-laced diagnostic message supplied by a
// real (test-controlled) TCP peer standing in for a hostile/compromised
// directory server -- through getConnectionStatus's health-check path, and
// verifies the "error" field logged via Warn never contains a raw \r or \n.
// This is the log-injection defect CLAUDE.md names explicitly: an error
// returned from a directory-service call carries external content back out
// inside its message text, so it must be sanitized like any other logged
// value, not passed through raw.
func TestGetConnectionStatus_SanitizesLDAPErrorInWarnLog(t *testing.T) {
	diagnosticMessage := "boom\r\nFAKE-ADMIN-EVENT: privilege escalated\ninjected-line"
	addr := startFakeDirectoryServer(t, diagnosticMessage)

	conn, err := ldap.DialURL("ldap://" + addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	logger := pkgtesting.NewMockLogger(true)
	module := New(logger).(*activeDirectoryModule)
	module.config = &ADModuleConfig{Domain: "example.com", AuthMethod: "simple"}
	module.conn = conn

	ctx := context.Background()
	_, err = module.getConnectionStatus(ctx)
	require.NoError(t, err, "getConnectionStatus reports health via the returned status, not an error")

	warnLogs := logger.GetLogs("warn")
	require.Len(t, warnLogs, 1, "expected exactly one Warn call from the failed health check")
	assert.Equal(t, "AD health check failed", warnLogs[0].Message)

	errVal := findLoggedValue(t, warnLogs[0].Data, "error")
	require.NotEmpty(t, errVal, "the error field must be logged as a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error value must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error value must not carry a raw LF")
	// The server-supplied content must still have reached the log (proving
	// the fix sanitizes rather than discards it) -- just with control
	// characters neutralized.
	assert.Contains(t, errVal, "FAKE-ADMIN-EVENT", "sanitization must neutralize control characters, not the whole message")
}

// findLoggedValue extracts the value associated with key from a flattened
// key/value log-argument slice, asserting it is a string (never a raw error
// or other unsanitized type) so callers can inspect its contents directly.
func findLoggedValue(t *testing.T, kv []interface{}, key string) string {
	t.Helper()
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok || k != key {
			continue
		}
		s, ok := kv[i+1].(string)
		require.True(t, ok, "logged value for key %q must be a string (sanitized), got %T", key, kv[i+1])
		return s
	}
	return ""
}

// TestGet_SanitizesResourceIDInDebugLog verifies that Get's very first log
// call -- which echoes the caller-supplied resourceID before it has been
// parsed or validated -- never lets a CR/LF-laced resourceID reach the log
// raw. resourceID is directly caller-controlled (the module's public
// entrypoint), the same shape of risk CLAUDE.md calls out for HTTP params
// and URL paths.
func TestGet_SanitizesResourceIDInDebugLog(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	module := New(logger)

	maliciousResourceID := "query:user:john.doe\r\nFAKE-LOG-LINE admin escalated privileges\n"

	ctx := context.Background()
	_, err := module.Get(ctx, maliciousResourceID)
	require.Error(t, err, "module is not configured, so Get must fail -- the log call happens before that failure")

	debugLogs := logger.GetLogs("debug")
	require.NotEmpty(t, debugLogs, "expected at least one Debug call from Get")

	found := false
	for _, entry := range debugLogs {
		if entry.Message != "Getting AD object" {
			continue
		}
		found = true
		val := findLoggedValue(t, entry.Data, "resource_id")
		require.NotEmpty(t, val)
		assert.NotContains(t, val, "\r", "sanitized resource_id must not carry a raw CR")
		assert.NotContains(t, val, "\n", "sanitized resource_id must not carry a raw LF")
	}
	assert.True(t, found, "expected a \"Getting AD object\" Debug log entry")
}
