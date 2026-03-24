// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// otherAuthInfo is a credentials.AuthInfo that is not TLS, used to simulate
// a peer connected without TLS.
type otherAuthInfo struct{}

func (o otherAuthInfo) AuthType() string { return "other" }

// peerContextWithCN returns a context carrying a gRPC peer whose TLS state
// contains a single peer certificate with the given Common Name.
func peerContextWithCN(cn string) context.Context {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
	}
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// peerContextNoTLS returns a context with a peer that has non-TLS auth info.
func peerContextNoTLS() context.Context {
	p := &peer.Peer{AuthInfo: otherAuthInfo{}}
	return peer.NewContext(context.Background(), p)
}

// peerContextEmptyCN returns a context with a TLS peer whose certificate CN is empty.
func peerContextEmptyCN() context.Context {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: ""},
	}
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// mockStream is a minimal grpc.ServerStream whose Context() is controllable.
type mockStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockStream) Context() context.Context { return m.ctx }

// noopUnaryHandler is a grpc.UnaryHandler that succeeds without side effects.
func noopUnaryHandler(_ context.Context, _ interface{}) (interface{}, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Message types for ControlChannelValidator tests
// (No proto imports — duck typing via local test structs)
// ---------------------------------------------------------------------------

// testEvent satisfies stewardMessage (has GetStewardId).
type testEvent struct{ stewardID string }

func (e *testEvent) GetStewardId() string { return e.stewardID }

// testHeartbeat satisfies stewardMessage.
type testHeartbeat struct{ stewardID string }

func (h *testHeartbeat) GetStewardId() string { return h.stewardID }

// testResponse satisfies stewardMessage.
type testResponse struct{ stewardID string }

func (r *testResponse) GetStewardId() string { return r.stewardID }

// testCommand satisfies both commandMessage (GetPriority) and stewardMessage.
// A steward sending a testCommand must be rejected regardless of the steward ID.
type testCommand struct {
	stewardID string
	priority  int32
}

func (c *testCommand) GetStewardId() string { return c.stewardID }
func (c *testCommand) GetPriority() int32   { return c.priority }

// unknownMessage satisfies neither commandMessage nor stewardMessage.
type unknownMessage struct{ data string }

// ---------------------------------------------------------------------------
// Identity extraction — UnaryIdentityInterceptor
// ---------------------------------------------------------------------------

// TestUnaryIdentityInterceptor_ValidCert verifies that a request with a valid
// TLS peer certificate stores the steward identity in the handler context and
// calls the handler exactly once.
func TestUnaryIdentityInterceptor_ValidCert(t *testing.T) {
	ctx := peerContextWithCN("steward-abc")

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		identity, ok := StewardIDFromContext(ctx)
		require.True(t, ok, "StewardIdentity must be present in handler context")
		assert.Equal(t, "steward-abc", identity.StewardID)
		return nil, nil
	}

	interceptor := UnaryIdentityInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.NoError(t, err)
	assert.True(t, handlerCalled, "handler must be called for valid cert")
}

// TestUnaryIdentityInterceptor_NoPeer verifies that a request with no peer
// in context returns Unauthenticated and does not call the handler.
func TestUnaryIdentityInterceptor_NoPeer(t *testing.T) {
	ctx := context.Background() // no peer

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return nil, nil
	}

	interceptor := UnaryIdentityInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handlerCalled, "handler must not be called when peer is absent")
}

// TestUnaryIdentityInterceptor_NoTLS verifies that a peer with non-TLS auth
// info returns Unauthenticated.
func TestUnaryIdentityInterceptor_NoTLS(t *testing.T) {
	ctx := peerContextNoTLS()

	interceptor := UnaryIdentityInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestUnaryIdentityInterceptor_EmptyCN verifies that a TLS peer whose
// certificate has an empty Common Name returns Unauthenticated.
func TestUnaryIdentityInterceptor_EmptyCN(t *testing.T) {
	ctx := peerContextEmptyCN()

	interceptor := UnaryIdentityInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// Identity extraction — StreamIdentityInterceptor
// ---------------------------------------------------------------------------

// TestStreamIdentityInterceptor_ValidCert verifies that a stream with a valid
// TLS peer certificate stores the steward identity in the wrapped stream context.
func TestStreamIdentityInterceptor_ValidCert(t *testing.T) {
	ss := &mockStream{ctx: peerContextWithCN("steward-xyz")}

	var capturedCtx context.Context
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		capturedCtx = stream.Context()
		return nil
	}

	interceptor := StreamIdentityInterceptor()
	err := interceptor(nil, ss, &grpc.StreamServerInfo{}, handler)

	require.NoError(t, err)
	require.NotNil(t, capturedCtx)

	identity, ok := StewardIDFromContext(capturedCtx)
	require.True(t, ok, "StewardIdentity must be present in stream context")
	assert.Equal(t, "steward-xyz", identity.StewardID)
}

// TestStreamIdentityInterceptor_NoPeer verifies that a stream with no peer
// in context returns Unauthenticated and does not invoke the handler.
func TestStreamIdentityInterceptor_NoPeer(t *testing.T) {
	ss := &mockStream{ctx: context.Background()} // no peer

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	interceptor := StreamIdentityInterceptor()
	err := interceptor(nil, ss, &grpc.StreamServerInfo{}, handler)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handlerCalled, "handler must not be called when peer is absent")
}

// ---------------------------------------------------------------------------
// Context propagation — StewardIDFromContext
// ---------------------------------------------------------------------------

// TestStewardIDFromContext_Present verifies that a stored identity is retrieved
// correctly and the boolean return is true.
func TestStewardIDFromContext_Present(t *testing.T) {
	expected := StewardIdentity{StewardID: "steward-present"}
	ctx := context.WithValue(context.Background(), stewardIDKey{}, expected)

	got, ok := StewardIDFromContext(ctx)

	assert.True(t, ok)
	assert.Equal(t, expected, got)
}

// TestStewardIDFromContext_Missing verifies that when no identity is stored the
// function returns false and a zero-value StewardIdentity.
func TestStewardIDFromContext_Missing(t *testing.T) {
	ctx := context.Background()

	got, ok := StewardIDFromContext(ctx)

	assert.False(t, ok)
	assert.Equal(t, StewardIdentity{}, got)
}

// ---------------------------------------------------------------------------
// Message validation — ControlChannelValidator
// ---------------------------------------------------------------------------

// TestControlChannelValidator_EventMatchingID verifies that an Event whose
// steward_id matches the authenticated identity is allowed.
func TestControlChannelValidator_EventMatchingID(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-1"}
	validator := ControlChannelValidator()

	err := validator(identity, &testEvent{stewardID: "steward-1"})
	assert.NoError(t, err)
}

// TestControlChannelValidator_EventMismatchID verifies that an Event whose
// steward_id differs from the authenticated identity is rejected.
func TestControlChannelValidator_EventMismatchID(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-1"}
	validator := ControlChannelValidator()

	err := validator(identity, &testEvent{stewardID: "steward-2"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestControlChannelValidator_HeartbeatMatchingID verifies that a Heartbeat
// with a matching steward_id is allowed.
func TestControlChannelValidator_HeartbeatMatchingID(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-hb"}
	validator := ControlChannelValidator()

	err := validator(identity, &testHeartbeat{stewardID: "steward-hb"})
	assert.NoError(t, err)
}

// TestControlChannelValidator_HeartbeatMismatchID verifies that a Heartbeat
// with a mismatched steward_id is rejected.
func TestControlChannelValidator_HeartbeatMismatchID(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-hb"}
	validator := ControlChannelValidator()

	err := validator(identity, &testHeartbeat{stewardID: "impostor"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestControlChannelValidator_ResponseMatchingID verifies that a Response with
// a matching steward_id is allowed.
func TestControlChannelValidator_ResponseMatchingID(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-resp"}
	validator := ControlChannelValidator()

	err := validator(identity, &testResponse{stewardID: "steward-resp"})
	assert.NoError(t, err)
}

// TestControlChannelValidator_CommandFromSteward verifies that any Command
// message sent by a steward is rejected regardless of the steward_id field,
// because commands flow controller → steward, never the reverse.
func TestControlChannelValidator_CommandFromSteward(t *testing.T) {
	// Even if the steward_id in the command matches the authenticated identity,
	// stewards are not permitted to send Command messages.
	identity := StewardIdentity{StewardID: "steward-cmd"}
	validator := ControlChannelValidator()

	err := validator(identity, &testCommand{stewardID: "steward-cmd", priority: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestControlChannelValidator_UnknownType verifies that an unrecognised message
// type is allowed for forward compatibility.
func TestControlChannelValidator_UnknownType(t *testing.T) {
	identity := StewardIdentity{StewardID: "steward-1"}
	validator := ControlChannelValidator()

	err := validator(identity, &unknownMessage{data: "future-field"})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Security: error messages must not leak steward IDs
// ---------------------------------------------------------------------------

// TestErrorMessages_NoStewardIDLeaked verifies that all error messages
// produced by the interceptors and validators do not contain any steward ID
// string, preventing information disclosure to an attacker.
func TestErrorMessages_NoStewardIDLeaked(t *testing.T) {
	const authenticatedID = "secret-steward-id"
	const messageID = "other-secret-id"

	identity := StewardIdentity{StewardID: authenticatedID}
	validator := ControlChannelValidator()

	tests := []struct {
		name string
		msg  interface{}
	}{
		{
			name: "event_mismatch",
			msg:  &testEvent{stewardID: messageID},
		},
		{
			name: "heartbeat_mismatch",
			msg:  &testHeartbeat{stewardID: messageID},
		},
		{
			name: "response_mismatch",
			msg:  &testResponse{stewardID: messageID},
		},
		{
			name: "command_from_steward",
			msg:  &testCommand{stewardID: authenticatedID, priority: 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validator(identity, tc.msg)
			require.Error(t, err)

			msg := err.Error()
			assert.NotContains(t, msg, authenticatedID,
				"error must not leak the authenticated steward ID")
			assert.NotContains(t, msg, messageID,
				"error must not leak the message steward ID")
		})
	}

	// Also verify interceptor errors don't leak.
	t.Run("unauthenticated_no_peer", func(t *testing.T) {
		interceptor := UnaryIdentityInterceptor()
		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), authenticatedID)
	})
}
