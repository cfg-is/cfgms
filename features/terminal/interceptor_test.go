// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newInterceptorTestAuditManager(t *testing.T) (*audit.Manager, *interfaces.StorageManager) {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(
		tmpDir+"/flatfile", tmpDir+"/cfgms.db",
	)
	require.NoError(t, err)

	m, err := audit.NewManager(storageManager.GetAuditStore(), "terminal-test")
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
		_ = storageManager.Close()
	})
	return m, storageManager
}

func newTestCommandFilter(t *testing.T) *terminal.CommandFilter {
	t.Helper()
	userR, userW := io.Pipe()
	shellR, shellW := io.Pipe()
	t.Cleanup(func() {
		_ = userR.Close()
		_ = userW.Close()
		_ = shellR.Close()
		_ = shellW.Close()
	})
	validator := terminal.NewSecurityValidator(nil)
	secCtx := &terminal.SessionSecurityContext{
		SessionID: "test-session",
		UserID:    "test-user",
		StewardID: "test-steward",
		TenantID:  "test-tenant",
	}
	return terminal.NewCommandFilter(validator, secCtx, userR, userW, shellW, shellR)
}

// TestInterceptOutput_RedactsSensitivePatterns verifies that sensitive key=value and
// key: value patterns are scrubbed from terminal output.
func TestInterceptOutput_RedactsSensitivePatterns(t *testing.T) {
	interceptor := terminal.NewCommandInterceptor(nil, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		contains string
		absent   string
	}{
		{
			name:     "password equals sign",
			input:    "password=hunter2pass",
			contains: "password=[REDACTED]",
			absent:   "hunter2pass",
		},
		{
			name:     "password colon separator",
			input:    "password: mysecretpass",
			contains: "password: [REDACTED]",
			absent:   "mysecretpass",
		},
		{
			name:     "token equals sign",
			input:    "token=abc123def456",
			contains: "token=[REDACTED]",
			absent:   "abc123def456",
		},
		{
			name:     "api_key equals sign",
			input:    "api_key=myapikey12345",
			contains: "api_key=[REDACTED]",
			absent:   "myapikey12345",
		},
		{
			name:     "apikey equals sign",
			input:    "apikey=longapikey9876",
			contains: "apikey=[REDACTED]",
			absent:   "longapikey9876",
		},
		{
			name:     "secret colon separator",
			input:    "secret: topsecret1234",
			contains: "secret: [REDACTED]",
			absent:   "topsecret1234",
		},
		{
			name:     "access_key equals sign",
			input:    "access_key=AKIAIOSFODNN7EXAMPLE",
			contains: "access_key=[REDACTED]",
			absent:   "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "private_key equals sign",
			input:    "private_key=supersecretkey123",
			contains: "private_key=[REDACTED]",
			absent:   "supersecretkey123",
		},
		{
			name:     "credential colon separator",
			input:    "credential: admin:password123",
			contains: "credential: [REDACTED]",
			absent:   "admin:password123",
		},
		{
			name:     "case insensitive PASSWORD",
			input:    "PASSWORD=MyPass1234",
			contains: "PASSWORD=[REDACTED]",
			absent:   "MyPass1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := interceptor.InterceptOutput(ctx, []byte(tt.input))
			require.NoError(t, err)
			assert.Contains(t, string(out), tt.contains)
			assert.NotContains(t, string(out), tt.absent)
		})
	}
}

// TestInterceptOutput_RedactsJWTTokens verifies that JWT-format bearer tokens are scrubbed.
func TestInterceptOutput_RedactsJWTTokens(t *testing.T) {
	interceptor := terminal.NewCommandInterceptor(nil, nil, nil)
	ctx := context.Background()

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	input := "Authorization header: " + jwt

	out, err := interceptor.InterceptOutput(ctx, []byte(input))
	require.NoError(t, err)
	assert.Contains(t, string(out), "[REDACTED]")
	assert.NotContains(t, string(out), jwt)
}

// TestInterceptOutput_PreservesNonSensitiveOutput verifies that ordinary terminal
// output passes through without modification.
func TestInterceptOutput_PreservesNonSensitiveOutput(t *testing.T) {
	interceptor := terminal.NewCommandInterceptor(nil, nil, nil)
	ctx := context.Background()

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "ls output",
			input: "total 48\ndrwxr-xr-x 5 user group 4096 Jan 1 12:00 .\n",
		},
		{
			name:  "kubectl output",
			input: "NAME                 READY   STATUS    RESTARTS   AGE\nnginx-deployment     1/1     Running   0          5d\n",
		},
		{
			name:  "nginx log line",
			input: "192.168.1.1 - - [20/May/2026:10:00:00 +0000] \"GET /health HTTP/1.1\" 200 -\n",
		},
		{
			name:  "ping output",
			input: "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=116 time=12.3 ms\n",
		},
		{
			name:  "empty output",
			input: "",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out, err := interceptor.InterceptOutput(ctx, []byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.input, string(out))
		})
	}
}

// TestInterceptOutput_PreservesANSICodes verifies that ANSI escape sequences in
// non-sensitive output are not corrupted by the scrubber.
func TestInterceptOutput_PreservesANSICodes(t *testing.T) {
	interceptor := terminal.NewCommandInterceptor(nil, nil, nil)
	ctx := context.Background()

	// ANSI colored shell prompt with non-sensitive text.
	ansiOutput := "\x1b[32muser@host\x1b[0m:\x1b[34m/home/user\x1b[0m$ ls -la\r\n"
	out, err := interceptor.InterceptOutput(ctx, []byte(ansiOutput))
	require.NoError(t, err)
	assert.Equal(t, ansiOutput, string(out))
}

// TestInterceptOutput_MixedSensitiveAndNonSensitive verifies that scrubbing only
// redacts the sensitive portions of multi-line output.
func TestInterceptOutput_MixedSensitiveAndNonSensitive(t *testing.T) {
	interceptor := terminal.NewCommandInterceptor(nil, nil, nil)
	ctx := context.Background()

	input := "user=alice\npassword=s3cr3tpass\nrole=admin\n"
	out, err := interceptor.InterceptOutput(ctx, []byte(input))
	require.NoError(t, err)

	result := string(out)
	assert.Contains(t, result, "user=alice")
	assert.Contains(t, result, "role=admin")
	assert.Contains(t, result, "password=[REDACTED]")
	assert.NotContains(t, result, "s3cr3tpass")
}

// TestHandleAuditCommand_DeliversToAuditStore verifies that handleAuditCommand
// delivers an audit event to the centralized audit log pipeline.
func TestHandleAuditCommand_DeliversToAuditStore(t *testing.T) {
	auditMgr, _ := newInterceptorTestAuditManager(t)

	filter := newTestCommandFilter(t)
	filter.SetAuditManager(auditMgr)

	event := &terminal.CommandAuditEvent{
		SessionID: "session-abc123",
		UserID:    "user-def456",
		StewardID: "steward-ghi789",
		TenantID:  "tenant-001",
		Command:   "sudo systemctl status nginx",
		Action:    terminal.FilterActionAudit,
		Severity:  terminal.FilterSeverityHigh,
		Timestamp: time.Now(),
	}

	err := terminal.HandleAuditCommand(filter, event)
	require.NoError(t, err)

	// Flush to guarantee the event reaches durable storage before querying.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(ctx))

	// Verify the event appears in the audit store with correct metadata.
	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID:      "tenant-001",
		ResourceTypes: []string{"terminal"},
		ResourceIDs:   []string{"session-abc123"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "expected audit entry in store after handleAuditCommand")
	assert.Equal(t, "user-def456", entries[0].UserID)
	assert.Equal(t, "terminal.command.executed", entries[0].Action)
	assert.Equal(t, "session-abc123", entries[0].SessionID)
}

// TestHandleAuditCommand_SeverityMapping verifies that FilterSeverity values are
// correctly mapped to business.AuditSeverity in the delivered event.
func TestHandleAuditCommand_SeverityMapping(t *testing.T) {
	tests := []struct {
		name             string
		filterSeverity   terminal.FilterSeverity
		expectedSeverity business.AuditSeverity
	}{
		{"critical", terminal.FilterSeverityCritical, business.AuditSeverityCritical},
		{"high", terminal.FilterSeverityHigh, business.AuditSeverityHigh},
		{"medium", terminal.FilterSeverityMedium, business.AuditSeverityMedium},
		{"low", terminal.FilterSeverityLow, business.AuditSeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditMgr, _ := newInterceptorTestAuditManager(t)
			filter := newTestCommandFilter(t)
			filter.SetAuditManager(auditMgr)

			event := &terminal.CommandAuditEvent{
				SessionID: "session-sev-test",
				UserID:    "user-sev",
				TenantID:  "tenant-sev",
				Command:   "ls",
				Action:    terminal.FilterActionAudit,
				Severity:  tt.filterSeverity,
			}

			err := terminal.HandleAuditCommand(filter, event)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, auditMgr.Flush(ctx))

			entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
				TenantID:      "tenant-sev",
				ResourceTypes: []string{"terminal"},
				ResourceIDs:   []string{"session-sev-test"},
			})
			require.NoError(t, err)
			require.NotEmpty(t, entries)
			assert.Equal(t, tt.expectedSeverity, entries[0].Severity)
		})
	}
}

// TestHandleAuditCommand_NilManager_NoError verifies that handleAuditCommand returns
// nil when no audit manager is wired (graceful no-op).
func TestHandleAuditCommand_NilManager_NoError(t *testing.T) {
	filter := newTestCommandFilter(t)
	// No SetAuditManager call — manager is nil.

	event := &terminal.CommandAuditEvent{
		SessionID: "session-abc123",
		UserID:    "user-def456",
		TenantID:  "tenant-001",
		Command:   "ls -la",
		Action:    terminal.FilterActionAudit,
	}

	err := terminal.HandleAuditCommand(filter, event)
	assert.NoError(t, err)
}

// TestHandleAuditCommand_PropagatesAuditError verifies that handleAuditCommand returns
// an error when the underlying audit pipeline rejects the event (e.g. manager stopped).
func TestHandleAuditCommand_PropagatesAuditError(t *testing.T) {
	auditMgr, _ := newInterceptorTestAuditManager(t)

	// Stop the manager before calling handleAuditCommand so RecordEvent returns an error.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	require.NoError(t, auditMgr.Stop(stopCtx))

	filter := newTestCommandFilter(t)
	filter.SetAuditManager(auditMgr)

	event := &terminal.CommandAuditEvent{
		SessionID: "session-err",
		UserID:    "user-err",
		TenantID:  "tenant-err",
		Command:   "ls -la",
		Action:    terminal.FilterActionAudit,
	}

	err := terminal.HandleAuditCommand(filter, event)
	assert.Error(t, err, "expected error when audit manager is stopped")
}

// TestHandleAuditCommand_ScrubbedCommandInStore verifies that a command containing
// inline credentials is scrubbed before being stored in the audit log.
func TestHandleAuditCommand_ScrubbedCommandInStore(t *testing.T) {
	auditMgr, _ := newInterceptorTestAuditManager(t)
	filter := newTestCommandFilter(t)
	filter.SetAuditManager(auditMgr)

	event := &terminal.CommandAuditEvent{
		SessionID: "session-scrub",
		UserID:    "user-scrub",
		TenantID:  "tenant-scrub",
		Command:   "mysql -h db.example.com --password=mysecretword123 -u root",
		Action:    terminal.FilterActionAudit,
		Severity:  terminal.FilterSeverityHigh,
	}

	err := terminal.HandleAuditCommand(filter, event)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(ctx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID:      "tenant-scrub",
		ResourceTypes: []string{"terminal"},
		ResourceIDs:   []string{"session-scrub"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	cmd, _ := entries[0].Details["command"].(string)
	assert.NotContains(t, cmd, "mysecretword123", "password must be scrubbed from audit store")
	assert.Contains(t, cmd, "[REDACTED]")
}
