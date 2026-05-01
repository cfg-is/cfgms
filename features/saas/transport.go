// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package saas transport provides the HTTP client factory for Microsoft Graph API calls.
// Graph API uses Microsoft's public CA infrastructure, so http.DefaultTransport
// (system root CAs) is appropriate here — pkg/cert mTLS is for CFGMS-internal gRPC only.
package saas

import (
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// rateLimitedTransport wraps an http.RoundTripper with a token-bucket rate limiter.
// A single limiter is shared across all tenants in the process (per-process, not
// per-tenant). Per-tenant limiting is a future optimization.
type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *rate.Limiter
}

// RoundTrip implements http.RoundTripper. It blocks until the rate limiter grants
// a token before forwarding the request to the underlying transport.
func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// NewGraphHTTPClient returns an *http.Client suitable for Microsoft Graph API calls.
// It wraps http.DefaultTransport (system root CAs, standard TLS) with a per-process
// token-bucket rate limiter.
//
// rps is the sustained request rate (requests per second); burst is the maximum
// number of requests that may exceed the rate in a short window. Defaults are
// 10 req/s and burst 20.
func NewGraphHTTPClient(rps float64, burst int) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &rateLimitedTransport{
			base:    http.DefaultTransport,
			limiter: rate.NewLimiter(rate.Limit(rps), burst),
		},
	}
}
