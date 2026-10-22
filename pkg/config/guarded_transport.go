// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// ErrBlockedAddress is returned (wrapped) when a connect-time address check refuses a dial.
var ErrBlockedAddress = errors.New("SSRF guard: connection refused: host resolves to a blocked address")

// guardedDialTimeout bounds each individual TCP connect attempt.
const guardedDialTimeout = 10 * time.Second

// goGitDefaultHTTPS is go-git's unmodified default https client, captured once at init.
var goGitDefaultHTTPS = gitclient.Protocols["https"]

var (
	guardedGitMu     sync.Mutex
	guardedGitClient = newGuardedGitClient()
	allowLoopback    atomic.Bool
)

// newGuardedHTTPTransport builds an http.Transport whose every connection — including
// redirect and retry hops — is vetted by guardedDialContext. Proxy is nil so environment
// proxies are never used. It must stay a *http.Transport: go-git clones it per request.
func newGuardedHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           guardedDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func newGuardedGitClient() gittransport.Transport {
	return githttp.NewClient(&http.Client{Transport: newGuardedHTTPTransport()})
}

// EnsureGuardedGitTransport installs the connect-time-checking https transport into
// go-git's process-global protocol table. It installs only when the current https entry
// is go-git's unmodified default; an already-installed guarded client, or any other
// replacement (for example a test's in-memory transport), is left alone. It is evaluated
// on every call and is safe for concurrent use.
func EnsureGuardedGitTransport() {
	guardedGitMu.Lock()
	defer guardedGitMu.Unlock()
	if gitclient.Protocols["https"] == goGitDefaultHTTPS {
		gitclient.InstallProtocol("https", guardedGitClient)
	}
}

// guardedDialContext resolves the target host through the package resolver, checks every
// address with checkSSRF, and dials the vetted IP literal so no second lookup can occur.
// It fails closed; errors never contain a resolved address.
func guardedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("SSRF guard: invalid dial address")
	}
	var ips []net.IP
	if lit := net.ParseIP(host); lit != nil {
		ips = []net.IP{lit}
	} else {
		addrs, lerr := defaultHostResolver.LookupIPAddr(ctx, host)
		if lerr != nil {
			return nil, fmt.Errorf("SSRF guard: host %q could not be resolved", host)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("SSRF guard: host %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if allowLoopback.Load() && ip.IsLoopback() {
			continue
		}
		if checkSSRF(ip) != nil {
			return nil, fmt.Errorf("%w: host %q", ErrBlockedAddress, host)
		}
	}
	d := net.Dialer{Timeout: guardedDialTimeout}
	var lastErr error
	for _, ip := range ips {
		conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("SSRF guard: could not connect to host %q: %w", host, sanitizeDialErr(lastErr))
}

// sanitizeDialErr drops the net.OpError text, which embeds the dialled address.
func sanitizeDialErr(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return errors.New("connection failed")
}

// AllowLoopbackForTesting makes the connect-time check admit loopback addresses only;
// admission checks are unchanged. FOR TESTS ONLY — it panics outside a test binary.
func AllowLoopbackForTesting() (restore func()) {
	return allowLoopbackForTesting(testing.Testing())
}

func allowLoopbackForTesting(inTest bool) (restore func()) {
	if !inTest {
		panic("config: AllowLoopbackForTesting called outside a test binary")
	}
	prev := allowLoopback.Swap(true)
	return func() { allowLoopback.Store(prev) }
}
