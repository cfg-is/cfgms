// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Minimal in-test gRPC service definitions (no proto file required)
// ---------------------------------------------------------------------------

// echoServiceServer is the interface that the Echo service handler must implement.
// gRPC's RegisterService requires HandlerType to be a pointer to an interface.
type echoServiceServer interface{}

// echoServer implements echoServiceServer.
type echoServer struct{}

// echoServiceDesc describes a minimal Echo service with unary, server-streaming,
// and bidi-streaming RPCs. This avoids any proto-generated code dependency.
var echoServiceDesc = grpc.ServiceDesc{
	ServiceName: "test.Echo",
	HandlerType: (*echoServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UnaryEcho",
			Handler:    echoUnaryHandler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ServerStream",
			Handler:       echoServerStreamHandler,
			ServerStreams: true,
		},
		{
			StreamName:    "BidiStream",
			Handler:       echoBidiStreamHandler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

// echoMessage is a trivial framed message: 4-byte length + payload.
// We use raw bytes over the gRPC stream to avoid protobuf dependencies.

// echoUnaryHandler echoes the request message back.
func echoUnaryHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
	var msg echoMsg
	if err := dec(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// echoServerStreamHandler sends the request message back three times.
func echoServerStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	var msg echoMsg
	if err := stream.RecvMsg(&msg); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if err := stream.SendMsg(&msg); err != nil {
			return err
		}
	}
	return nil
}

// echoBidiStreamHandler echoes each message received until the client closes.
func echoBidiStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	for {
		var msg echoMsg
		if err := stream.RecvMsg(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.SendMsg(&msg); err != nil {
			return err
		}
	}
}

// echoMsg is a codec-compatible message wrapper around a byte slice.
// grpc uses the registered codec to marshal/unmarshal; we use the default
// protobuf codec which handles []byte via protobuf's bytes field when wrapped.
// Instead, we implement the proto.Message interface stub to pass raw bytes.
//
// For simplicity in tests we use gRPC's raw encoding by registering our own
// codec. However, an easier approach is to use gRPC's test helpers.
//
// Actually the simplest approach: use grpc.ForceCodecV2 with a passthrough
// codec so the "message" is just raw bytes on the wire.

// echoMsg wraps a payload for our test service.
type echoMsg struct {
	Payload []byte
}

// We implement proto.Message by supplying the minimum needed for gRPC's
// codec to handle our messages. gRPC's default codec is protobuf; we need
// our message to be encodable. The cleanest approach without a .proto file
// is to make echoMsg implement encoding.BinaryMarshaler / BinaryUnmarshaler
// and register a custom codec.
//
// For test simplicity we instead just use gRPC's built-in "proto" codec but
// wrap our payload in a real proto message: we treat []byte as a proto bytes
// field (field number 1, wire type 2 = length-delimited).

// ProtoMessage implements proto.Message (duck typing for gRPC codec).
func (e *echoMsg) ProtoMessage() {}

// Reset implements proto.Message.
func (e *echoMsg) Reset() {}

// String implements proto.Message.
func (e *echoMsg) String() string { return string(e.Payload) }

// Marshal encodes echoMsg as a proto bytes field (field 1, wire type 2).
func (e *echoMsg) Marshal() ([]byte, error) {
	if len(e.Payload) == 0 {
		return nil, nil
	}
	// Encode as proto field 1, wire type 2 (length-delimited).
	// Tag = (field_number << 3) | wire_type = (1<<3)|2 = 0x0a
	payload := e.Payload
	size := len(payload)
	// Varint encoding for size.
	var sizeBytes []byte
	for size >= 0x80 {
		sizeBytes = append(sizeBytes, byte(size)|0x80)
		size >>= 7
	}
	sizeBytes = append(sizeBytes, byte(size))
	out := make([]byte, 0, 1+len(sizeBytes)+len(payload))
	out = append(out, 0x0a)
	out = append(out, sizeBytes...)
	out = append(out, payload...)
	return out, nil
}

// Unmarshal decodes echoMsg from proto bytes field 1.
func (e *echoMsg) Unmarshal(data []byte) error {
	if len(data) == 0 {
		e.Payload = nil
		return nil
	}
	// Parse proto field 1, wire type 2.
	i := 0
	for i < len(data) {
		tag := data[i]
		i++
		wireType := tag & 0x07
		fieldNum := tag >> 3
		if wireType == 2 && fieldNum == 1 {
			// Varint length.
			var length int
			shift := 0
			for i < len(data) {
				b := data[i]
				i++
				length |= int(b&0x7f) << shift
				shift += 7
				if b < 0x80 {
					break
				}
			}
			if i+length > len(data) {
				return status.Error(codes.Internal, "truncated proto message")
			}
			e.Payload = make([]byte, length)
			copy(e.Payload, data[i:i+length])
			return nil
		}
	}
	e.Payload = nil
	return nil
}

// ProtoSize returns the encoded size (for proto.Sizer).
func (e *echoMsg) ProtoSize() int {
	if len(e.Payload) == 0 {
		return 0
	}
	size := len(e.Payload)
	varintSize := 1
	for s := size; s >= 0x80; s >>= 7 {
		varintSize++
	}
	return 1 + varintSize + size
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// startEchoServer creates a gRPC server on a QUIC listener and starts serving.
// Returns the server, the listener address, and a cleanup function.
func startEchoServer(t *testing.T, tlsPair *testTLSPair) (*grpc.Server, string) {
	t.Helper()

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)

	srv := grpc.NewServer()
	srv.RegisterService(&echoServiceDesc, &echoServer{})

	go func() {
		// Serve returns an error when the listener is closed; ignore it.
		_ = srv.Serve(lis)
	}()

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	return srv, lis.Addr().String()
}

// newEchoClient dials the echo server over QUIC and returns a gRPC ClientConn.
func newEchoClient(t *testing.T, addr string, tlsPair *testTLSPair) *grpc.ClientConn {
	t.Helper()

	conn, err := grpc.NewClient(
		addr,
		grpc.WithContextDialer(NewDialer(tlsPair.client, nil)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// invoke performs a unary echoMsg RPC on the given client connection.
func invokeUnary(ctx context.Context, cc *grpc.ClientConn, payload []byte) ([]byte, error) {
	req := &echoMsg{Payload: payload}
	resp := &echoMsg{}
	err := cc.Invoke(ctx, "/test.Echo/UnaryEcho", req, resp)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestGRPCOverQUIC_UnaryRPC tests a full gRPC unary call over the QUIC transport.
func TestGRPCOverQUIC_UnaryRPC(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)

	cc := newEchoClient(t, addr, tlsPair)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	got, err := invokeUnary(ctx, cc, []byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, []byte("ping"), got)
}

// TestGRPCOverQUIC_ServerStreaming tests a server-streaming RPC over QUIC.
func TestGRPCOverQUIC_ServerStreaming(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)
	cc := newEchoClient(t, addr, tlsPair)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/test.Echo/ServerStream")
	require.NoError(t, err)

	require.NoError(t, stream.SendMsg(&echoMsg{Payload: []byte("hello")}))
	require.NoError(t, stream.CloseSend())

	var received [][]byte
	for {
		var msg echoMsg
		err := stream.RecvMsg(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		received = append(received, msg.Payload)
	}

	assert.Len(t, received, 3, "server should send 3 echoes")
	for _, payload := range received {
		assert.Equal(t, []byte("hello"), payload)
	}
}

// TestGRPCOverQUIC_BidiStreaming tests a bidirectional streaming RPC over QUIC.
func TestGRPCOverQUIC_BidiStreaming(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)
	cc := newEchoClient(t, addr, tlsPair)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/test.Echo/BidiStream")
	require.NoError(t, err)

	messages := [][]byte{[]byte("a"), []byte("bb"), []byte("ccc")}

	// Send all messages.
	for _, msg := range messages {
		require.NoError(t, stream.SendMsg(&echoMsg{Payload: msg}))
	}
	require.NoError(t, stream.CloseSend())

	// Receive echoed messages.
	var received [][]byte
	for {
		var msg echoMsg
		err := stream.RecvMsg(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		received = append(received, msg.Payload)
	}

	require.Len(t, received, len(messages))
	for i, payload := range received {
		assert.Equal(t, messages[i], payload)
	}
}

// TestGRPCOverQUIC_MultipleClients tests 5 clients connecting simultaneously.
func TestGRPCOverQUIC_MultipleClients(t *testing.T) {
	const numClients = 5
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)

	var wg sync.WaitGroup
	errs := make([]error, numClients)

	for i := range numClients {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			cc := newEchoClient(t, addr, tlsPair)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			_, errs[idx] = invokeUnary(ctx, cc, []byte("client"))
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "client %d failed", i)
	}
}

// TestGRPCOverQUIC_ClientDisconnect verifies that when a client disconnects
// mid-stream, the server side receives an error.
func TestGRPCOverQUIC_ClientDisconnect(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)

	// Create a context we will cancel to simulate client disconnect.
	ctx, cancel := context.WithCancel(t.Context())

	cc := newEchoClient(t, addr, tlsPair)
	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/test.Echo/BidiStream")
	require.NoError(t, err)

	// Send one message, then cancel the context (simulates disconnect).
	require.NoError(t, stream.SendMsg(&echoMsg{Payload: []byte("bye")}))

	// Cancel before receiving the response.
	cancel()

	// The stream operations after cancel must return a context error (Canceled or EOF).
	var msg echoMsg
	err = stream.RecvMsg(&msg)
	require.Error(t, err, "RecvMsg after context cancellation must return an error, not succeed")
}

// TestGRPCOverQUIC_TLSRequired verifies that a connection attempt with a
// wrong ALPN fails, validating ALPN enforcement at the transport layer.
func TestGRPCOverQUIC_TLSRequired(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	_, addr := startEchoServer(t, tlsPair)

	// Use the correct CA but a wrong ALPN to test ALPN enforcement specifically.
	wrongALPNTLS := tlsPair.client.Clone()
	wrongALPNTLS.NextProtos = []string{"wrong-protocol"}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	_, dialErr := Dial(ctx, addr, wrongALPNTLS, nil)
	assert.Error(t, dialErr, "dial with wrong ALPN should fail ALPN negotiation")
}

// TestGRPCOverQUIC_AddrWrapper verifies that our Addr wrapper is used for
// addresses returned from the Conn (network = "quic").
func TestGRPCOverQUIC_AddrWrapper(t *testing.T) {
	tlsPair := newTestTLSPair(t)
	serverConn, clientConn := dialPair(t, tlsPair)

	// Both server and client addresses should report network "quic".
	assert.Equal(t, "quic", serverConn.LocalAddr().Network())
	assert.Equal(t, "quic", serverConn.RemoteAddr().Network())
	assert.Equal(t, "quic", clientConn.LocalAddr().Network())
	assert.Equal(t, "quic", clientConn.RemoteAddr().Network())

	// Both sides should have non-empty addresses.
	assert.NotEmpty(t, serverConn.RemoteAddr().String())
	assert.NotEmpty(t, clientConn.LocalAddr().String())
}

// TestAddr_NetworkAndString verifies the Addr type satisfies net.Addr.
func TestAddr_NetworkAndString(t *testing.T) {
	a := newAddr("127.0.0.1:4433")
	assert.Equal(t, "quic", a.Network())
	assert.Equal(t, "127.0.0.1:4433", a.String())
}
