// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/osquery"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// makeScript creates an executable shell script in a temp dir and returns its path.
func makeScript(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fake-osquery-*")
	require.NoError(t, err)
	_, err = f.WriteString("#!/bin/sh\n" + body)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chmod(f.Name(), 0o700))
	return f.Name()
}

// makeBatch creates a Windows batch script in a temp dir and returns its path.
func makeBatch(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fake-osquery-*.bat")
	require.NoError(t, err)
	_, err = f.WriteString("@echo off\n" + body)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// newFakeOsquery returns a platform-appropriate fake osquery binary.
func newFakeOsquery(t *testing.T, posixBody, windowsBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return makeBatch(t, windowsBody)
	}
	return makeScript(t, posixBody)
}

// TestOsqueryHandler_UnrecognizedCatalogID_Rejected is the REQUIRED TEST for
// AC3 (Issue #3566): an unrecognised catalog ID must be rejected before any
// runQuery call. The fake binary would panic if called; the test verifies the
// binary is never reached.
func TestOsqueryHandler_UnrecognizedCatalogID_Rejected(t *testing.T) {
	// Use a non-existent path: if runQuery were called, it would fail with a
	// start-failure error, not an InvalidArgument gRPC status. We verify the
	// returned error IS InvalidArgument, proving admission ran before execution.
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/should-never-be-called")

	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "this-id-does-not-exist-in-the-catalog",
	}
	rows, err := h.Execute(context.Background(), req)

	require.Error(t, err, "unknown catalog ID must be rejected")
	assert.Nil(t, rows, "no rows must be returned on admission failure")

	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"unknown catalog ID must produce InvalidArgument, not Internal or another code")
	assert.Contains(t, st.Message(), "unknown query id",
		"error message must identify the unknown-catalog-id rejection")
}

// TestOsqueryHandler_SQLMetacharacters_Rejected is the REQUIRED TEST for AC4
// (Issue #3566): a parameter value containing SQL metacharacters must be
// rejected for a template whose declared parameter type does not allow it.
// The test covers the four metacharacter patterns from CLAUDE.md.
func TestOsqueryHandler_SQLMetacharacters_Rejected(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/should-never-be-called")

	// "file_info" uses a charset-typed "path" parameter — SQL metacharacters are
	// always blocked for charset params regardless of the character whitelist.
	tests := []struct {
		name  string
		value string
	}{
		{"single_quote", "' OR 1=1 --"},
		{"double_dash", "/etc/passwd--"},
		{"semicolon", "/etc/passwd;DROP TABLE"},
		{"UNION", "/etc/passwd UNION SELECT 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &transportpb.OsqueryQueryRequest{
				CatalogId: "file_info",
				Params:    map[string]string{"path": tt.value},
			}
			rows, err := h.Execute(context.Background(), req)

			require.Error(t, err, "SQL metacharacter in param value must be rejected")
			assert.Nil(t, rows)

			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code(),
				"metacharacter rejection must produce InvalidArgument")
		})
	}
}

// TestOsqueryHandler_AdmissionBeforeRunQuery is the REQUIRED TEST for AC5
// (Issue #3566): catalog-ID lookup and parameter validation both happen in one
// admission step before runQuery is called. The test verifies this by using a
// binPath that does not exist: if runQuery were reached, it would return an
// execution error (not InvalidArgument), making the assertion trivially fail.
func TestOsqueryHandler_AdmissionBeforeRunQuery(t *testing.T) {
	// binPath does not exist — if runQuery is called, Execute would return
	// codes.Internal ("osquery execution failed"), not codes.InvalidArgument.
	// A codes.InvalidArgument result proves the admission step fired first.
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/no-such-binary-for-admission-test")

	tests := []struct {
		name    string
		req     *transportpb.OsqueryQueryRequest
		wantMsg string
	}{
		{
			name:    "unknown_catalog_id_rejected_before_run",
			req:     &transportpb.OsqueryQueryRequest{CatalogId: "not-in-catalog"},
			wantMsg: "unknown query id",
		},
		{
			name: "bad_param_value_rejected_before_run",
			req: &transportpb.OsqueryQueryRequest{
				CatalogId: "file_info",
				Params:    map[string]string{"path": "'; DROP TABLE stewards; --"},
			},
			wantMsg: "SQL metacharacter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := h.Execute(context.Background(), tt.req)

			require.Error(t, err)
			assert.Nil(t, rows)

			st, ok := status.FromError(err)
			require.True(t, ok, "error must be a gRPC status error")
			assert.Equal(t, codes.InvalidArgument, st.Code(),
				"admission failure must produce InvalidArgument — Internal would mean runQuery was reached")
			assert.Contains(t, strings.ToLower(st.Message()), strings.ToLower(tt.wantMsg),
				"error message must identify the admission rejection reason")
		})
	}
}

// TestOsqueryHandler_ValidRequest_CallsRunQuery verifies the happy path: a valid
// catalog ID with valid parameters reaches runQuery. Uses a fake binary that
// returns a known JSON row to confirm the full path without a real osquery install.
func TestOsqueryHandler_ValidRequest_CallsRunQuery(t *testing.T) {
	bin := newFakeOsquery(t,
		`echo '[{"hostname":"test-host","os_name":"linux","platform":"ubuntu","platform_like":"debian","version":"22.04","build":"","kernel_version":"5.15.0","arch":"x86_64"}]'`,
		"echo [{\"hostname\":\"test-host\",\"os_name\":\"linux\",\"platform\":\"ubuntu\",\"platform_like\":\"debian\",\"version\":\"22.04\",\"build\":\"\",\"kernel_version\":\"5.15.0\",\"arch\":\"x86_64\"}]\n",
	)

	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), bin)
	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "host_info",
	}
	rows, err := h.Execute(context.Background(), req)

	require.NoError(t, err, "valid catalog query must succeed with the fake binary")
	require.Len(t, rows, 1, "fake binary returns one row")
	assert.Equal(t, "test-host", rows[0].GetColumns()["hostname"])
}

// TestOsqueryHandler_EnumParam_ValidValue verifies that an enum-typed parameter
// with a declared allowed value passes admission and reaches runQuery.
func TestOsqueryHandler_EnumParam_ValidValue(t *testing.T) {
	bin := newFakeOsquery(t, `echo '[]'`, "echo []\n")

	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), bin)
	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "process_list",
		Params:    map[string]string{"name_prefix": "cfgms"},
	}
	rows, err := h.Execute(context.Background(), req)

	require.NoError(t, err, "valid enum param must pass admission and reach runQuery")
	assert.Empty(t, rows)
}

// TestOsqueryHandler_EnumParam_InvalidValue verifies that an enum-typed parameter
// with an unlisted value is rejected at admission (not passed to runQuery).
func TestOsqueryHandler_EnumParam_InvalidValue(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/should-not-run")

	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "process_list",
		Params:    map[string]string{"name_prefix": "bash"},
	}
	rows, err := h.Execute(context.Background(), req)

	require.Error(t, err, "unlisted enum value must be rejected at admission")
	assert.Nil(t, rows)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestOsqueryHandler_MissingRequiredParam rejects a request that omits a
// parameter declared as required by the catalog entry.
func TestOsqueryHandler_MissingRequiredParam(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/should-not-run")

	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "file_info",
		Params:    map[string]string{}, // "path" is required
	}
	rows, err := h.Execute(context.Background(), req)

	require.Error(t, err, "missing required parameter must be rejected at admission")
	assert.Nil(t, rows)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestOsqueryHandler_UndeclaredParam rejects a request that supplies a parameter
// not declared in the catalog entry's schema.
func TestOsqueryHandler_UndeclaredParam(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/tmp/should-not-run")

	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "host_info",                                  // host_info has no declared params
		Params:    map[string]string{"injected": "extra-value"}, // not declared
	}
	rows, err := h.Execute(context.Background(), req)

	require.Error(t, err, "undeclared parameter must be rejected at admission")
	assert.Nil(t, rows)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestOsqueryHandler_CharsetParam_ValidPath verifies that a charset-typed "path"
// parameter with only safe characters passes admission.
func TestOsqueryHandler_CharsetParam_ValidPath(t *testing.T) {
	bin := newFakeOsquery(t, `echo '[]'`, "echo []\n")

	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), bin)
	req := &transportpb.OsqueryQueryRequest{
		CatalogId: "file_info",
		Params:    map[string]string{"path": "/etc/os-release"},
	}
	rows, err := h.Execute(context.Background(), req)

	require.NoError(t, err, "safe absolute path must pass charset validation")
	assert.Empty(t, rows)
}

// TestOsqueryHandler_SanitizeLogValue_InErrorPath verifies that the handler
// wraps err.Error() with logging.SanitizeLogValue in log entries. An error
// value returned from RunQuery, ValidateParams, or LookupCatalogEntry carries
// tainted input inside its message text; logging it unwrapped violates the
// CLAUDE.md rule ("error values: logging.SanitizeLogValue(err.Error()), never err").
// This source-scan asserts the specific call form, not merely symbol presence.
func TestOsqueryHandler_SanitizeLogValue_InErrorPath(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	require.NoError(t, err, "handler.go must be readable")

	content := string(src)
	if !strings.Contains(content, "logging.SanitizeLogValue(err.Error())") {
		t.Error("handler.go must wrap err.Error() with logging.SanitizeLogValue in log entries — " +
			"error values from RunQuery/ValidateParams carry tainted input per CLAUDE.md")
	}
}

// TestOsqueryHandler_NoRawSQLOnWire verifies that the handler never logs or
// uses the raw SQL query text from the wire. SQL text is resolved from the
// catalog internally; only the catalog_id is accepted from the wire.
func TestOsqueryHandler_NoRawSQLOnWire(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	require.NoError(t, err)

	// The handler must not reference any "sql" or "query_text" field from the
	// OsqueryQueryRequest proto — those fields do not exist; the check guards
	// against accidental future additions of a raw-SQL wire field.
	content := string(src)
	for _, forbidden := range []string{"GetSql(", "GetQueryText(", "GetRawSql("} {
		assert.NotContains(t, content, forbidden,
			fmt.Sprintf("handler.go must not access raw SQL from the wire request (%s would indicate a wire SQL field)", forbidden))
	}
}

// ---------------------------------------------------------------------------
// HandleGRPC stream recv loop tests (finding: recv loop had zero coverage)
// ---------------------------------------------------------------------------

// newTestCA creates an in-memory CA for generating mTLS test certificates.
func newTestCA(t *testing.T) *cfgcert.CA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Osquery Handler Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	return ca
}

// newMTLSContext returns a context carrying a real x509 peer certificate with
// the given Common Name, satisfying quictransport.PeerStewardID's requirements.
func newMTLSContext(t *testing.T, ca *cfgcert.CA, cn string) context.Context {
	t.Helper()
	cert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   cn,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	block, _ := pem.Decode(cert.CertificatePEM)
	require.NotNil(t, block, "PEM decode must succeed")
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates:  []*x509.Certificate{x509Cert},
				VerifiedChains:    [][]*x509.Certificate{{x509Cert}},
				HandshakeComplete: true,
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// recvStream implements grpc.BidiStreamingServer for HandleGRPC recv loop tests.
// Recv returns msgs in order then io.EOF; if errOnRecv is set, Recv returns it
// immediately (simulating a non-EOF stream error).
type recvStream struct {
	msgs      []*transportpb.OsqueryQueryResponse
	idx       int
	errOnRecv error
	ctx       context.Context
}

func (s *recvStream) Recv() (*transportpb.OsqueryQueryResponse, error) {
	if s.errOnRecv != nil {
		return nil, s.errOnRecv
	}
	if s.idx >= len(s.msgs) {
		return nil, io.EOF
	}
	msg := s.msgs[s.idx]
	s.idx++
	return msg, nil
}
func (s *recvStream) Send(*transportpb.OsqueryQueryRequest) error { return nil }
func (s *recvStream) SetHeader(metadata.MD) error                 { return nil }
func (s *recvStream) SendHeader(metadata.MD) error                { return nil }
func (s *recvStream) SetTrailer(metadata.MD)                      {}
func (s *recvStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *recvStream) SendMsg(interface{}) error { return nil }
func (s *recvStream) RecvMsg(interface{}) error { return nil }

var _ grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest] = (*recvStream)(nil)

// TestOsqueryHandler_HandleGRPC_RecvLoop_EOF verifies that HandleGRPC processes
// OsqueryQueryResponse frames from the steward and returns nil on clean EOF.
// This exercises the recv loop body (lines ~176–190 of handler.go) that was
// previously uncovered.
func TestOsqueryHandler_HandleGRPC_RecvLoop_EOF(t *testing.T) {
	ca := newTestCA(t)
	peerCtx := newMTLSContext(t, ca, "steward-test-recv-001")

	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream := &recvStream{
		msgs: []*transportpb.OsqueryQueryResponse{
			{
				StewardId: "steward-test-recv-001",
				CatalogId: "host_info",
				Rows: []*transportpb.OsqueryRow{
					{Columns: map[string]string{"hostname": "test-host"}},
				},
			},
		},
		ctx: peerCtx,
	}

	err := h.HandleGRPC(stream)
	require.NoError(t, err, "HandleGRPC must return nil after receiving rows and hitting EOF")
}

// TestOsqueryHandler_HandleGRPC_RecvLoop_NonEOFError verifies that HandleGRPC
// propagates a non-EOF error from Recv wrapped with "osquery stream recv".
// This exercises the error-propagation branch (handler.go ~line 182).
func TestOsqueryHandler_HandleGRPC_RecvLoop_NonEOFError(t *testing.T) {
	ca := newTestCA(t)
	peerCtx := newMTLSContext(t, ca, "steward-test-recv-002")

	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream := &recvStream{
		errOnRecv: fmt.Errorf("simulated stream interruption"),
		ctx:       peerCtx,
	}

	err := h.HandleGRPC(stream)
	require.Error(t, err, "HandleGRPC must propagate non-EOF recv errors")
	assert.Contains(t, err.Error(), "osquery stream recv",
		"non-EOF recv error must be wrapped with 'osquery stream recv'")
}

// ---------------------------------------------------------------------------
// QuerySteward controller-side dispatch tests (Issue #3569)
// ---------------------------------------------------------------------------

// loopbackStream is a real in-process bidi stream (not a mock — it has no
// expectations and no generated behaviour): Send publishes the controller's
// request on sent, and Recv delivers whatever the test publishes on incoming.
// Closing incoming ends the stream with io.EOF, the same way a steward
// disconnect does.
//
// registered is closed on the first Recv call. HandleGRPC registers the stream
// entry before entering its recv loop, so observing that close is a deterministic
// happens-after signal that QuerySteward can find the steward — no sleeps.
type loopbackStream struct {
	ctx      context.Context
	sent     chan *transportpb.OsqueryQueryRequest
	incoming chan *transportpb.OsqueryQueryResponse
	sendErr  error

	registered chan struct{}
	once       sync.Once
	closeOnce  sync.Once
}

// end closes the stream from the steward side; Recv then returns io.EOF, which is
// what HandleGRPC sees when a steward disconnects. Safe to call more than once.
func (s *loopbackStream) end() {
	s.closeOnce.Do(func() { close(s.incoming) })
}

func newLoopbackStream(ctx context.Context) *loopbackStream {
	return &loopbackStream{
		ctx:        ctx,
		sent:       make(chan *transportpb.OsqueryQueryRequest, 4),
		incoming:   make(chan *transportpb.OsqueryQueryResponse, 4),
		registered: make(chan struct{}),
	}
}

func (s *loopbackStream) Recv() (*transportpb.OsqueryQueryResponse, error) {
	s.once.Do(func() { close(s.registered) })
	resp, ok := <-s.incoming
	if !ok {
		return nil, io.EOF
	}
	return resp, nil
}

func (s *loopbackStream) Send(req *transportpb.OsqueryQueryRequest) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent <- req
	return nil
}

func (s *loopbackStream) SetHeader(metadata.MD) error  { return nil }
func (s *loopbackStream) SendHeader(metadata.MD) error { return nil }
func (s *loopbackStream) SetTrailer(metadata.MD)       {}
func (s *loopbackStream) Context() context.Context     { return s.ctx }
func (s *loopbackStream) SendMsg(interface{}) error    { return nil }
func (s *loopbackStream) RecvMsg(interface{}) error    { return nil }

var _ grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest] = (*loopbackStream)(nil)

// startStewardStream runs HandleGRPC for stewardID on a loopback stream and
// blocks until the stream is registered. The returned closer ends the stream and
// waits for HandleGRPC to return, asserting its result.
func startStewardStream(t *testing.T, h *osquery.OsqueryHandler, stewardID string) (*loopbackStream, func()) {
	t.Helper()
	ca := newTestCA(t)
	stream := newLoopbackStream(newMTLSContext(t, ca, stewardID))

	errCh := make(chan error, 1)
	go func() { errCh <- h.HandleGRPC(stream) }()

	select {
	case <-stream.registered:
	case err := <-errCh:
		t.Fatalf("HandleGRPC returned before registering the stream: %v", err)
	}

	return stream, func() {
		stream.end()
		select {
		case err := <-errCh:
			require.NoError(t, err, "HandleGRPC must return nil on clean stream end")
		case <-time.After(5 * time.Second):
			t.Fatal("HandleGRPC did not return after the stream ended")
		}
	}
}

// TestQuerySteward_SuccessfulDispatch verifies the happy path: QuerySteward sends
// an OsqueryQueryRequest carrying the steward ID, catalog ID and params on the
// steward's open stream, and returns the rows from the response HandleGRPC routes
// back to it.
func TestQuerySteward_SuccessfulDispatch(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream, stop := startStewardStream(t, h, "steward-dispatch-001")
	defer stop()

	// Respond to the request the moment it lands on the wire.
	go func() {
		req := <-stream.sent
		stream.incoming <- &transportpb.OsqueryQueryResponse{
			StewardId: req.GetStewardId(),
			CatalogId: req.GetCatalogId(),
			Rows: []*transportpb.OsqueryRow{
				{Columns: map[string]string{"hostname": "host-a", "path": req.GetParams()["path"]}},
			},
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := h.QuerySteward(ctx, "steward-dispatch-001", "file_info",
		map[string]string{"path": "/etc/os-release"})

	require.NoError(t, err, "dispatch to a connected steward must succeed")
	require.Len(t, rows, 1, "the steward's response rows must be returned to the caller")
	assert.Equal(t, "host-a", rows[0].GetColumns()["hostname"])
	assert.Equal(t, "/etc/os-release", rows[0].GetColumns()["path"],
		"catalog params must reach the steward unchanged")
}

// TestQuerySteward_NotConnected verifies that dispatching to a steward with no
// open OsqueryQuery stream returns ErrStewardNotConnected rather than blocking.
func TestQuerySteward_NotConnected(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")

	rows, err := h.QuerySteward(context.Background(), "steward-never-connected", "host_info", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, osquery.ErrStewardNotConnected,
		"an unconnected steward must produce ErrStewardNotConnected so the REST layer can report it per-steward")
	assert.Nil(t, rows)
}

// TestQuerySteward_QueryAlreadyInFlight verifies the v1 one-query-per-steward
// constraint: a second concurrent dispatch to the same steward is rejected
// immediately rather than queued or blocked.
func TestQuerySteward_QueryAlreadyInFlight(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream, stop := startStewardStream(t, h, "steward-inflight-001")
	defer stop()

	firstDone := make(chan error, 1)
	go func() {
		_, err := h.QuerySteward(context.Background(), "steward-inflight-001", "host_info", nil)
		firstDone <- err
	}()

	// Receiving the request proves the first call has registered its waiting
	// channel (QuerySteward sets entry.waiting before calling Send).
	var first *transportpb.OsqueryQueryRequest
	select {
	case first = <-stream.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("first query never reached the steward stream")
	}

	rows, err := h.QuerySteward(context.Background(), "steward-inflight-001", "process_list", nil)
	require.Error(t, err, "a second concurrent query for the same steward must be rejected")
	assert.Contains(t, err.Error(), "already in-flight")
	assert.Nil(t, rows)
	assert.NotErrorIs(t, err, osquery.ErrStewardNotConnected,
		"an in-flight rejection must be distinguishable from a disconnected steward")

	// Release the first query and confirm it completes normally.
	stream.incoming <- &transportpb.OsqueryQueryResponse{
		StewardId: first.GetStewardId(),
		CatalogId: first.GetCatalogId(),
	}
	select {
	case err := <-firstDone:
		require.NoError(t, err, "the first in-flight query must still complete")
	case <-time.After(5 * time.Second):
		t.Fatal("first query did not complete after its response was delivered")
	}
}

// TestQuerySteward_ContextCancelled verifies that cancelling the caller's context
// while the steward has not yet responded returns ctx.Err() and clears the
// in-flight slot, so a later query for the same steward is not permanently locked out.
func TestQuerySteward_ContextCancelled(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream, stop := startStewardStream(t, h, "steward-cancel-001")
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())

	resultCh := make(chan error, 1)
	go func() {
		_, err := h.QuerySteward(ctx, "steward-cancel-001", "host_info", nil)
		resultCh <- err
	}()

	select {
	case <-stream.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("query never reached the steward stream")
	}

	cancel()

	select {
	case err := <-resultCh:
		require.Error(t, err, "a cancelled caller must not block waiting for the steward")
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("QuerySteward did not return after context cancellation")
	}

	// The in-flight slot must have been released: a subsequent query succeeds.
	go func() {
		req := <-stream.sent
		stream.incoming <- &transportpb.OsqueryQueryResponse{
			StewardId: req.GetStewardId(),
			CatalogId: req.GetCatalogId(),
			Rows:      []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "after-cancel"}}},
		}
	}()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	rows, err := h.QuerySteward(ctx2, "steward-cancel-001", "host_info", nil)
	require.NoError(t, err, "cancellation must release the in-flight slot for the next query")
	require.Len(t, rows, 1)
	assert.Equal(t, "after-cancel", rows[0].GetColumns()["hostname"])
}

// TestQuerySteward_StewardDisconnectsDuringQuery verifies that when the steward's
// stream ends while a query is waiting, the caller is released with a disconnect
// error instead of hanging until its own context expires.
func TestQuerySteward_StewardDisconnectsDuringQuery(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream, stop := startStewardStream(t, h, "steward-disconnect-001")
	defer stop()

	resultCh := make(chan error, 1)
	go func() {
		_, err := h.QuerySteward(context.Background(), "steward-disconnect-001", "host_info", nil)
		resultCh <- err
	}()

	select {
	case <-stream.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("query never reached the steward stream")
	}

	// End the stream: HandleGRPC unregisters the entry and closes entry.done.
	stream.end()

	select {
	case err := <-resultCh:
		require.Error(t, err, "a waiting caller must be released when the steward disconnects")
		assert.Contains(t, err.Error(), "steward disconnected during query")
	case <-time.After(5 * time.Second):
		t.Fatal("QuerySteward did not return after the steward disconnected")
	}

	// After the disconnect the steward is no longer registered.
	_, err := h.QuerySteward(context.Background(), "steward-disconnect-001", "host_info", nil)
	assert.ErrorIs(t, err, osquery.ErrStewardNotConnected,
		"a disconnected steward must be deregistered from the stream registry")
}

// TestQuerySteward_SendFailureReleasesSlot verifies that a stream Send failure is
// reported to the caller and does not leave the steward permanently marked as
// having a query in flight.
func TestQuerySteward_SendFailureReleasesSlot(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")
	stream, stop := startStewardStream(t, h, "steward-senderr-001")
	defer stop()

	stream.sendErr = fmt.Errorf("simulated transport failure")

	rows, err := h.QuerySteward(context.Background(), "steward-senderr-001", "host_info", nil)
	require.Error(t, err, "a Send failure must be surfaced to the caller")
	assert.Contains(t, err.Error(), "sending request to steward")
	assert.Nil(t, rows)

	// The in-flight slot must be free again — otherwise one transport blip would
	// wedge the steward for the lifetime of the stream.
	stream.sendErr = nil
	go func() {
		req := <-stream.sent
		stream.incoming <- &transportpb.OsqueryQueryResponse{
			StewardId: req.GetStewardId(),
			CatalogId: req.GetCatalogId(),
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = h.QuerySteward(ctx, "steward-senderr-001", "host_info", nil)
	require.NoError(t, err, "a failed Send must release the in-flight slot")
}

// TestQuerySteward_ConcurrentStewardsIsolated verifies that dispatches to
// different stewards proceed independently — the one-query-per-steward lock is
// per stream entry, not global. Run under -race to cover the registry locking.
func TestQuerySteward_ConcurrentStewardsIsolated(t *testing.T) {
	h := osquery.NewOsqueryHandler(logging.NewNoopLogger(), "/dev/null")

	const stewardCount = 4
	streams := make([]*loopbackStream, stewardCount)
	ids := make([]string, stewardCount)
	for i := 0; i < stewardCount; i++ {
		ids[i] = fmt.Sprintf("steward-concurrent-%03d", i)
		stream, stop := startStewardStream(t, h, ids[i])
		defer stop()
		streams[i] = stream

		go func(s *loopbackStream, id string) {
			req := <-s.sent
			s.incoming <- &transportpb.OsqueryQueryResponse{
				StewardId: req.GetStewardId(),
				CatalogId: req.GetCatalogId(),
				Rows:      []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": id}}},
			}
		}(stream, ids[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make([]string, stewardCount)
	errs := make([]error, stewardCount)
	for i := 0; i < stewardCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rows, err := h.QuerySteward(ctx, ids[idx], "host_info", nil)
			errs[idx] = err
			if len(rows) == 1 {
				results[idx] = rows[0].GetColumns()["hostname"]
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < stewardCount; i++ {
		require.NoError(t, errs[i], "concurrent dispatch to distinct stewards must not interfere")
		assert.Equal(t, ids[i], results[i],
			"each steward's response must be routed back to its own caller")
	}
}
