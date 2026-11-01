// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/modules"
)

// credentialRequestTimeout bounds one IssueInitialCredential call.
const credentialRequestTimeout = 15 * time.Second

var (
	// ErrCredentialUnavailable means there is no live controller connection or
	// the call failed in transit. Nothing was queued; the caller may try again on
	// its next convergence run.
	ErrCredentialUnavailable = errors.New("initial credential unavailable")
	// ErrCredentialRefused means the controller refused the request (resource not
	// declared in this steward's configuration, rate limit, or cap).
	ErrCredentialRefused = errors.New("initial credential request refused")
	// ErrCredentialAlreadyIssued means the password was already revealed and the
	// account exists.
	ErrCredentialAlreadyIssued = errors.New("initial credential already issued")
)

// CredentialClient requests controller-issued one-time initial passwords over
// the unary IssueInitialCredential RPC on the steward's transport connection.
//
// A password is a secret, so this client has no queue, no retry file and no
// cache: the value is returned in memory to the caller and nowhere else. On any
// failure nothing is written to disk. Errors carry a fixed description and the
// gRPC status code class only, never the server's message text.
type CredentialClient struct {
	clientSrc func() transportpb.StewardTransportClient
	timeout   time.Duration
}

var _ modules.CredentialClient = (*CredentialClient)(nil)

// NewCredentialClient builds a client. clientSrc returns the current
// StewardTransport client (the control-plane provider's TransportClient), or nil
// while disconnected.
func NewCredentialClient(clientSrc func() transportpb.StewardTransportClient) *CredentialClient {
	return &CredentialClient{clientSrc: clientSrc, timeout: credentialRequestTimeout}
}

// IssueInitialCredential implements modules.CredentialClient.
func (c *CredentialClient) IssueInitialCredential(ctx context.Context, resourceID, kind string) (string, error) {
	if c == nil || c.clientSrc == nil {
		return "", ErrCredentialUnavailable
	}
	cl := c.clientSrc()
	if cl == nil {
		return "", ErrCredentialUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := cl.IssueInitialCredential(callCtx, &transportpb.IssueInitialCredentialRequest{
		ResourceId: resourceID,
		Kind:       kind,
	})
	if err != nil {
		return "", credentialError(err)
	}
	if resp.GetPassword() == "" {
		return "", ErrCredentialUnavailable
	}
	return resp.GetPassword(), nil
}

// credentialError maps a transport error to a sentinel. The server's message is
// deliberately dropped.
func credentialError(err error) error {
	switch status.Code(err) {
	case codes.FailedPrecondition:
		return ErrCredentialAlreadyIssued
	case codes.PermissionDenied, codes.ResourceExhausted, codes.NotFound, codes.InvalidArgument, codes.Unauthenticated:
		return ErrCredentialRefused
	default:
		return ErrCredentialUnavailable
	}
}
