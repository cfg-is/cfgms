// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"

	// Register the file provider so NewLoggingManager("file") works in tests.
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
)

// ---------------------------------------------------------------------------
// Test double for grpc.ClientStreamingServer[LogEntry, LogStreamResponse]
// ---------------------------------------------------------------------------

type testLogStream struct {
	entries []*transportpb.LogEntry
	pos     int
	resp    *transportpb.LogStreamResponse
	ctx     context.Context
	recvErr error
}

func newTestLogStream(ctx context.Context, entries ...*transportpb.LogEntry) *testLogStream {
	return &testLogStream{entries: entries, ctx: ctx}
}

func (s *testLogStream) Recv() (*transportpb.LogEntry, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	if s.pos >= len(s.entries) {
		return nil, io.EOF
	}
	e := s.entries[s.pos]
	s.pos++
	return e, nil
}

func (s *testLogStream) SendAndClose(resp *transportpb.LogStreamResponse) error {
	s.resp = resp
	return nil
}

func (s *testLogStream) SetHeader(metadata.MD) error  { return nil }
func (s *testLogStream) SendHeader(metadata.MD) error { return nil }
func (s *testLogStream) SetTrailer(metadata.MD)       {}
func (s *testLogStream) Context() context.Context     { return s.ctx }
func (s *testLogStream) SendMsg(interface{}) error    { return nil }
func (s *testLogStream) RecvMsg(interface{}) error    { return nil }

// Compile-time check.
var _ grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse] = (*testLogStream)(nil)

// ---------------------------------------------------------------------------
// Test helper: file-backed LoggingManager
// ---------------------------------------------------------------------------

func newTestLoggingManager(t *testing.T) *logging.LoggingManager {
	t.Helper()
	cfg := &logging.LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        t.TempDir(),
			"file_prefix":      "log-stream-test",
			"max_file_size":    1024 * 1024,
			"retention_days":   1,
			"compress_rotated": false,
		},
		Level:       "DEBUG",
		ServiceName: "cfgms",
		Component:   "log-stream-handler-test",
		BatchSize:   1,
		AsyncWrites: false,
	}
	m, err := logging.NewLoggingManager(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if closeErr := m.Close(); closeErr != nil {
			t.Logf("LoggingManager.Close() error: %v", closeErr)
		}
	})
	return m
}

// queryAllEntries flushes and returns every log entry written to the manager.
func queryAllEntries(t *testing.T, m *logging.LoggingManager) []loggingInterfaces.LogEntry {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, m.Flush(ctx))
	entries, err := m.QueryTimeRange(ctx, loggingInterfaces.TimeRangeQuery{
		StartTime: time.Unix(0, 0),
		EndTime:   time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	return entries
}

// ---------------------------------------------------------------------------
// Acceptance-criteria tests (Issue #2140)
// ---------------------------------------------------------------------------

// TestLogStreamHandler_CNMismatch_Rejected verifies that a LogEntry whose
// StewardID differs from the mTLS peer CN is rejected with PermissionDenied
// and the error message does not disclose the peer CN.
func TestLogStreamHandler_CNMismatch_Rejected(t *testing.T) {
	ca := newTestCA(t)
	h := NewLogStreamHandler(nil, nil, logging.NewNoopLogger(), DefaultLogStreamConfig())

	// Peer authenticates as "steward-alice".
	ctx := peerContextWithCA(t, ca, "steward-alice")

	// Entry claims to be from "steward-bob" — deliberate mismatch.
	stream := newTestLogStream(ctx, &transportpb.LogEntry{
		StewardId: "steward-bob",
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "hello",
		Timestamp: timestamppb.Now(),
	})

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	msg := status.Convert(err).Message()
	assert.NotContains(t, msg, "steward-alice", "error must not disclose the peer CN")
	assert.NotContains(t, msg, "steward-bob", "error must not disclose the wire steward ID")
}

// TestLogStreamHandler_EmptyCN_FailsClosed verifies that a stream authenticated
// with no or blank CN is rejected (never treated as a wildcard or pass-through).
func TestLogStreamHandler_EmptyCN_FailsClosed(t *testing.T) {
	h := NewLogStreamHandler(nil, nil, logging.NewNoopLogger(), DefaultLogStreamConfig())

	// context.Background() carries no peer info at all.
	stream := newTestLogStream(context.Background(), &transportpb.LogEntry{
		StewardId: "steward-xyz",
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "test",
		Timestamp: timestamppb.Now(),
	})

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestLogStreamHandler_RateLimit_DropWithCounter verifies that entries above
// the per-steward rate limit are dropped (non-blocking) with the drop counter
// incremented, while accepted entries are persisted via WriteEntry.
func TestLogStreamHandler_RateLimit_DropWithCounter(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestLoggingManager(t)

	const stewardID = "steward-rate"
	// Set rate limit to 1 so the second entry is always dropped.
	cfg := LogStreamConfig{RateLimitPerSteward: 1}
	h := NewLogStreamHandler(mgr, nil, logging.NewNoopLogger(), cfg)

	ctx := peerContextWithCA(t, ca, stewardID)

	// Exhaust the bucket's single token by sending 3 entries.
	entries := []*transportpb.LogEntry{
		{StewardId: stewardID, Level: transportpb.Severity_SEVERITY_INFO, Message: "entry-1", Timestamp: timestamppb.Now()},
		{StewardId: stewardID, Level: transportpb.Severity_SEVERITY_INFO, Message: "entry-2", Timestamp: timestamppb.Now()},
		{StewardId: stewardID, Level: transportpb.Severity_SEVERITY_INFO, Message: "entry-3", Timestamp: timestamppb.Now()},
	}
	stream := newTestLogStream(ctx, entries...)

	err := h.HandleGRPC(stream)
	require.NoError(t, err)
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAcknowledged())

	// At least one entry must have been dropped (bucket started at capacity=1,
	// so entries 2 and 3 are both candidates for dropping).
	drops := h.GetDropCount(stewardID)
	assert.Greater(t, drops, int64(0), "drop counter must be positive")

	// Accepted entries (received count) + drops must equal total sent.
	received := stream.resp.GetEntriesReceived()
	assert.Equal(t, int64(3), received+drops, "received + drops must equal total sent")

	// At least the first accepted entry must be retrievable from storage.
	persisted := queryAllEntries(t, mgr)
	assert.NotEmpty(t, persisted, "at least one entry must be persisted")
}

// TestLogStreamHandler_TenantDerivedServerSide verifies that a LogEntry whose
// fields["tenant_id"] claims a foreign tenant is persisted under the steward's
// registry tenant, not the claimed one.
func TestLogStreamHandler_TenantDerivedServerSide(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestLoggingManager(t)

	const stewardID = "steward-tenant"
	const registryTenant = "tenant-registry"
	const claimedTenant = "tenant-foreign"

	cs := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, cs.RegisterSteward(stewardID, registryTenant, "", "active"))

	h := NewLogStreamHandler(mgr, cs, logging.NewNoopLogger(), DefaultLogStreamConfig())
	ctx := peerContextWithCA(t, ca, stewardID)

	stream := newTestLogStream(ctx, &transportpb.LogEntry{
		StewardId: stewardID,
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "tenant-test",
		Timestamp: timestamppb.Now(),
		Fields:    map[string]string{"tenant_id": claimedTenant},
	})

	err := h.HandleGRPC(stream)
	require.NoError(t, err)

	entries := queryAllEntries(t, mgr)
	require.NotEmpty(t, entries)
	assert.Equal(t, registryTenant, entries[0].TenantID,
		"persisted entry must use the server-derived tenant, not the wire value")
}

// TestLogStreamHandler_StampsCNVerifiedStewardID verifies that the persisted
// entry's Fields["steward_id"] equals the CN-verified peer identity (not any
// wire-supplied value), ensuring events are attributable per steward.
func TestLogStreamHandler_StampsCNVerifiedStewardID(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestLoggingManager(t)

	const peerCN = "steward-verified"
	h := NewLogStreamHandler(mgr, nil, logging.NewNoopLogger(), DefaultLogStreamConfig())
	ctx := peerContextWithCA(t, ca, peerCN)

	// Wire payload supplies a different steward_id in fields — must be overridden.
	stream := newTestLogStream(ctx, &transportpb.LogEntry{
		StewardId: peerCN,
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "stamp-test",
		Timestamp: timestamppb.Now(),
		Fields:    map[string]string{"steward_id": "some-other-steward"},
	})

	err := h.HandleGRPC(stream)
	require.NoError(t, err)

	entries := queryAllEntries(t, mgr)
	require.NotEmpty(t, entries)
	sid, ok := entries[0].Fields["steward_id"]
	require.True(t, ok, "steward_id must be present in persisted entry fields")
	assert.Equal(t, peerCN, sid,
		"persisted steward_id must be CN-verified peer identity, not the wire value")
}

// ---------------------------------------------------------------------------
// Error-path tests
// ---------------------------------------------------------------------------

// TestLogStreamHandler_RecvError verifies that a mid-stream Recv() error
// (not EOF) propagates from HandleGRPC.
func TestLogStreamHandler_RecvError(t *testing.T) {
	ca := newTestCA(t)
	h := NewLogStreamHandler(nil, nil, logging.NewNoopLogger(), DefaultLogStreamConfig())

	ctx := peerContextWithCA(t, ca, "steward-recv-err")
	injected := errors.New("simulated network failure")
	stream := &testLogStream{ctx: ctx, recvErr: injected}

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.True(t, errors.Is(err, injected), "error must wrap the injected recv error")
}

// ---------------------------------------------------------------------------
// Severity mapping unit tests
// ---------------------------------------------------------------------------

// TestMapSeverityToLevel verifies that all proto Severity values map to the
// expected logging level strings.
func TestMapSeverityToLevel(t *testing.T) {
	cases := []struct {
		severity transportpb.Severity
		want     string
	}{
		{transportpb.Severity_SEVERITY_UNSPECIFIED, "INFO"},
		{transportpb.Severity_SEVERITY_INFO, "INFO"},
		{transportpb.Severity_SEVERITY_WARNING, "WARN"},
		{transportpb.Severity_SEVERITY_ERROR, "ERROR"},
		{transportpb.Severity_SEVERITY_CRITICAL, "ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.severity.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, mapSeverityToLevel(tc.severity))
		})
	}
}
