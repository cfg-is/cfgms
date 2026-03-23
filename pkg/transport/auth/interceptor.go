// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportquic "github.com/cfgis/cfgms/pkg/transport/quic"
)

// StewardIdentity holds the authenticated identity extracted from mTLS.
type StewardIdentity struct {
	StewardID string
}

// stewardIDKey is the context key for the authenticated steward identity.
type stewardIDKey struct{}

// StewardIDFromContext extracts the authenticated steward identity from context.
// Returns the identity and true if present, zero value and false if not.
func StewardIDFromContext(ctx context.Context) (StewardIdentity, bool) {
	id, ok := ctx.Value(stewardIDKey{}).(StewardIdentity)
	return id, ok
}

// extractIdentity extracts the steward identity from the gRPC peer TLS state in ctx.
// Returns a gRPC status error on failure so callers can return it directly.
func extractIdentity(ctx context.Context) (StewardIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return StewardIdentity{}, status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return StewardIdentity{}, status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	id, err := transportquic.PeerStewardID(tlsInfo.State)
	if err != nil {
		return StewardIdentity{}, status.Error(codes.Unauthenticated, "steward identity not found in certificate")
	}

	return StewardIdentity{StewardID: id}, nil
}

// UnaryIdentityInterceptor returns a gRPC unary server interceptor that:
//  1. Extracts the peer certificate from the TLS connection
//  2. Reads the steward ID from the certificate CN
//  3. Stores the StewardIdentity in the context for downstream handlers
//  4. Rejects requests with no valid peer certificate
func UnaryIdentityInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		identity, err := extractIdentity(ctx)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, stewardIDKey{}, identity)
		return handler(ctx, req)
	}
}

// wrappedStream injects a replacement context into a grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the injected context, overriding the embedded stream's context.
func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

// StreamIdentityInterceptor returns a gRPC stream server interceptor that:
//  1. Extracts the peer certificate from the TLS connection
//  2. Reads the steward ID from the certificate CN
//  3. Wraps the stream to include StewardIdentity in the context
//  4. Rejects streams with no valid peer certificate
func StreamIdentityInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		identity, err := extractIdentity(ss.Context())
		if err != nil {
			return err
		}
		ctx := context.WithValue(ss.Context(), stewardIDKey{}, identity)
		return handler(srv, &wrappedStream{ss, ctx})
	}
}

// MessageValidator is a function that checks whether a message is authorized
// for the given steward identity. Return nil to allow, non-nil error to reject.
type MessageValidator func(identity StewardIdentity, msg interface{}) error

// commandMessage is implemented by Command proto messages. Command is unique
// among ControlMessage payloads in carrying a priority field; this interface
// allows detection without importing the proto package.
type commandMessage interface {
	GetPriority() int32
}

// stewardMessage is implemented by Event, Heartbeat, and Response proto messages,
// all of which carry a steward_id that must be validated against the TLS identity.
type stewardMessage interface {
	GetStewardId() string
}

// ControlChannelValidator returns a MessageValidator for ControlChannel messages.
//
// Rules:
//   - Commands: REJECTED — only controllers send commands, never stewards
//   - Events: event.steward_id must match authenticated identity
//   - Heartbeats: heartbeat.steward_id must match authenticated identity
//   - Responses: response.steward_id must match authenticated identity
//   - Unknown types: allowed for forward compatibility
//
// The validator accepts interface{} to stay proto-version-agnostic and uses
// structural type assertions (duck typing) to detect message types. This keeps
// tests free of generated proto code.
func ControlChannelValidator() MessageValidator {
	return func(identity StewardIdentity, msg interface{}) error {
		// Commands are controller-only. Stewards receiving a command message
		// type on an inbound stream indicates a protocol violation.
		if _, ok := msg.(commandMessage); ok {
			return status.Error(codes.PermissionDenied, "stewards cannot send commands")
		}

		// Events, Heartbeats, and Responses must carry the authenticated steward ID.
		if m, ok := msg.(stewardMessage); ok {
			if m.GetStewardId() != identity.StewardID {
				return status.Error(codes.PermissionDenied, "steward ID in message does not match authenticated identity")
			}
			return nil
		}

		// Unknown message types are allowed for forward compatibility.
		return nil
	}
}
