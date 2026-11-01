// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
)

// credentialServer is a StewardTransport server whose IssueInitialCredential
// returns whatever the test configures.
type credentialServer struct {
	transportpb.UnimplementedStewardTransportServer
	resp *transportpb.IssueInitialCredentialResponse
	err  error
	got  *transportpb.IssueInitialCredentialRequest
}

func (s *credentialServer) IssueInitialCredential(_ context.Context, req *transportpb.IssueInitialCredentialRequest) (*transportpb.IssueInitialCredentialResponse, error) {
	s.got = req
	return s.resp, s.err
}

func startCredentialServer(t *testing.T, srv *credentialServer) transportpb.StewardTransportClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	transportpb.RegisterStewardTransportServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return transportpb.NewStewardTransportClient(conn)
}

func TestCredentialClient_ReturnsPasswordInMemory(t *testing.T) {
	srv := &credentialServer{resp: &transportpb.IssueInitialCredentialResponse{Password: "Pa55-from-controller"}}
	tc := startCredentialServer(t, srv)
	c := NewCredentialClient(func() transportpb.StewardTransportClient { return tc })

	pw, err := c.IssueInitialCredential(context.Background(), "user-jdoe", "activedirectory.user")
	require.NoError(t, err)
	assert.Equal(t, "Pa55-from-controller", pw)
	assert.Equal(t, "user-jdoe", srv.got.GetResourceId())
	assert.Equal(t, "activedirectory.user", srv.got.GetKind())
}

func TestCredentialClient_FailureWritesNothingToDisk(t *testing.T) {
	work := t.TempDir()
	tmp := t.TempDir()
	home := t.TempDir()
	t.Chdir(work)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	cases := map[string]func() transportpb.StewardTransportClient{
		"no connection": func() transportpb.StewardTransportClient { return nil },
		"server error": func() transportpb.StewardTransportClient {
			return startCredentialServer(t, &credentialServer{err: status.Error(codes.Unavailable, "controller down")})
		},
		"refused": func() transportpb.StewardTransportClient {
			return startCredentialServer(t, &credentialServer{err: status.Error(codes.PermissionDenied, "credential request refused")})
		},
		"already issued": func() transportpb.StewardTransportClient {
			return startCredentialServer(t, &credentialServer{err: status.Error(codes.FailedPrecondition, "already issued")})
		},
	}
	for name, src := range cases {
		tc := src()
		c := NewCredentialClient(func() transportpb.StewardTransportClient { return tc })
		pw, err := c.IssueInitialCredential(context.Background(), "user-jdoe", "activedirectory.user")
		require.Error(t, err, name)
		assert.Empty(t, pw, name)
	}

	// A call that exceeds its deadline fails and writes nothing either.
	slow := startCredentialServer(t, &credentialServer{resp: &transportpb.IssueInitialCredentialResponse{Password: "x"}})
	c := NewCredentialClient(func() transportpb.StewardTransportClient { return slow })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.IssueInitialCredential(ctx, "user-jdoe", "activedirectory.user")
	require.Error(t, err)

	for _, dir := range []string{work, tmp, home} {
		entries, derr := os.ReadDir(dir)
		require.NoError(t, derr)
		assert.Empty(t, entries, "nothing may be written under %s", dir)
	}
}

func TestCredentialClient_ErrorHasNoSecret(t *testing.T) {
	const leaked = "Sup3r-S3cret-Pa55word!"
	for _, code := range []codes.Code{codes.Internal, codes.Unavailable, codes.PermissionDenied, codes.FailedPrecondition, codes.ResourceExhausted, codes.Unknown} {
		// A hostile or buggy server puts the password in the error text and in a
		// response that also fails: neither may reach the caller's error.
		srv := &credentialServer{err: status.Error(code, "password="+leaked)}
		tc := startCredentialServer(t, srv)
		c := NewCredentialClient(func() transportpb.StewardTransportClient { return tc })
		pw, err := c.IssueInitialCredential(context.Background(), "user-jdoe", "activedirectory.user")
		require.Error(t, err)
		assert.Empty(t, pw)
		assert.NotContains(t, err.Error(), leaked, code.String())
		for e := err; e != nil; e = errors.Unwrap(e) {
			assert.NotContains(t, e.Error(), leaked)
		}
	}

	_, err := (*CredentialClient)(nil).IssueInitialCredential(context.Background(), "r", "k")
	require.ErrorIs(t, err, ErrCredentialUnavailable)

	srv := &credentialServer{err: status.Error(codes.FailedPrecondition, "already issued")}
	tc := startCredentialServer(t, srv)
	c := NewCredentialClient(func() transportpb.StewardTransportClient { return tc })
	_, err = c.IssueInitialCredential(context.Background(), "r", "k")
	require.ErrorIs(t, err, ErrCredentialAlreadyIssued)
}

func TestCredentialClient_DeadlineBounded(t *testing.T) {
	c := NewCredentialClient(func() transportpb.StewardTransportClient { return nil })
	assert.Equal(t, 15*time.Second, c.timeout)
}
