// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sequenceResolver answers each successive lookup from answers; the last repeats.
type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]net.IPAddr
	calls   int
}

func (s *sequenceResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.calls
	if i >= len(s.answers) {
		i = len(s.answers) - 1
	}
	s.calls++
	return s.answers[i], nil
}

// hostResolver answers per host name.
type hostResolver map[string][]net.IPAddr

func (h hostResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if a, ok := h[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

type countingServer struct {
	*httptest.Server
	requests atomic.Int32
	port     int
}

func newCountingServer(t *testing.T, h http.HandlerFunc) *countingServer {
	t.Helper()
	cs := &countingServer{}
	cs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.requests.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	t.Cleanup(cs.Close)
	cs.port = cs.Listener.Addr().(*net.TCPAddr).Port
	return cs
}

func guardedTestClient() *http.Client {
	tr := newGuardedHTTPTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- httptest self-signed server
	return &http.Client{Transport: tr}
}

func TestGuardedDial_RebindingRefusedAtDial(t *testing.T) {
	srv := newCountingServer(t, nil)
	res := &sequenceResolver{answers: [][]net.IPAddr{ipAddrs("203.0.113.10"), ipAddrs("127.0.0.1")}}
	t.Cleanup(UseHostResolverForTesting(res))

	v := NewDefaultMountPointValidator(WithInsecureSkipTLS())
	err := v.ValidateMountPoint(context.Background(),
		&ConfigSourceInfo{Type: ConfigSourceTypeGit, URL: fmt.Sprintf("https://git.cfgms.local:%d/repo", srv.port)}, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "127.0.0.1")
	assert.Zero(t, srv.requests.Load(), "no connection may reach the server")
	assert.GreaterOrEqual(t, res.calls, 2, "admission and dial must each resolve")
}

func TestGuardedDial_RedirectToBlockedAddressRefused(t *testing.T) {
	t.Cleanup(AllowLoopbackForTesting())
	var target string
	first := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
	target = fmt.Sprintf("https://internal.cfgms.local:%d/secret", first.port)
	t.Cleanup(UseHostResolverForTesting(hostResolver{
		"allowed.cfgms.local":  ipAddrs("127.0.0.1"),
		"internal.cfgms.local": ipAddrs("10.9.8.7"),
	}))

	_, err := guardedTestClient().Get(fmt.Sprintf("https://allowed.cfgms.local:%d/", first.port))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockedAddress)
	assert.NotContains(t, err.Error(), "10.9.8.7")
	assert.Equal(t, int32(1), first.requests.Load(), "only the first hop may connect")
}

func TestGuardedDial_FailClosed(t *testing.T) {
	srv := newCountingServer(t, nil)
	addr := fmt.Sprintf("x.cfgms.local:%d", srv.port)
	cases := map[string]HostResolver{
		"resolver error": &fakeResolver{err: errors.New("boom 10.0.0.1")},
		"empty answer":   &fakeResolver{},
		"loopback":       &fakeResolver{addrs: ipAddrs("127.0.0.1")},
		"mixed":          &fakeResolver{addrs: ipAddrs("203.0.113.10", "169.254.169.254")},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(UseHostResolverForTesting(r))
			conn, err := guardedDialContext(context.Background(), "tcp", addr)
			require.Error(t, err)
			assert.Nil(t, conn)
			for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "203.0.113.10"} {
				assert.NotContains(t, err.Error(), ip)
			}
		})
	}
	assert.Zero(t, srv.requests.Load())
}

func TestGuardedDial_IPLiteralChecked(t *testing.T) {
	_, err := guardedDialContext(context.Background(), "tcp", "127.0.0.1:1")
	assert.ErrorIs(t, err, ErrBlockedAddress)
}

func TestGuardedDial_AllowLoopbackAdmitsOnlyLoopback(t *testing.T) {
	srv := newCountingServer(t, nil)
	t.Cleanup(AllowLoopbackForTesting())
	t.Cleanup(UseHostResolverForTesting(hostResolver{
		"lo.cfgms.local":   ipAddrs("127.0.0.1"),
		"priv.cfgms.local": ipAddrs("192.168.1.1"),
	}))
	resp, err := guardedTestClient().Get(fmt.Sprintf("https://lo.cfgms.local:%d/", srv.port))
	require.NoError(t, err)
	_ = resp.Body.Close()
	_, err = guardedDialContext(context.Background(), "tcp", fmt.Sprintf("priv.cfgms.local:%d", srv.port))
	assert.ErrorIs(t, err, ErrBlockedAddress)
}

func TestAllowLoopbackForTesting_RestoresAndPanicsOutsideTests(t *testing.T) {
	restore := AllowLoopbackForTesting()
	assert.True(t, allowLoopback.Load())
	restore()
	assert.False(t, allowLoopback.Load())
	assert.Panics(t, func() { allowLoopbackForTesting(false) })
	assert.False(t, allowLoopback.Load())
}

func TestEnsureGuardedGitTransport(t *testing.T) {
	prev := gitclient.Protocols["https"]
	t.Cleanup(func() { gitclient.InstallProtocol("https", prev) })

	gitclient.InstallProtocol("https", goGitDefaultHTTPS)
	EnsureGuardedGitTransport()
	assert.Same(t, guardedGitClient, gitclient.Protocols["https"], "default is replaced by the guarded client")
	EnsureGuardedGitTransport()
	assert.Same(t, guardedGitClient, gitclient.Protocols["https"], "idempotent")

	other := newGuardedGitClient()
	gitclient.InstallProtocol("https", other)
	EnsureGuardedGitTransport()
	assert.Same(t, other, gitclient.Protocols["https"], "another replacement is not clobbered")

	gitclient.InstallProtocol("https", goGitDefaultHTTPS)
	EnsureGuardedGitTransport()
	assert.Same(t, guardedGitClient, gitclient.Protocols["https"], "evaluated on every call")
}
