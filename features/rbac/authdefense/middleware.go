// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// statusCapture wraps http.ResponseWriter to capture the response status code
type statusCapture struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
}

func (sc *statusCapture) WriteHeader(code int) {
	if sc.wroteHeader {
		return
	}
	sc.wroteHeader = true
	sc.code = code
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Write(data []byte) (int, error) {
	if !sc.wroteHeader {
		sc.WriteHeader(http.StatusOK)
	}
	return sc.ResponseWriter.Write(data)
}

// Unwrap allows net/http.ResponseController to discover optional interfaces on
// the underlying writer.
func (sc *statusCapture) Unwrap() http.ResponseWriter {
	return sc.ResponseWriter
}

// Hijack preserves WebSocket and other HTTP upgrade support.
func (sc *statusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := sc.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

// Flush preserves streaming response support.
func (sc *statusCapture) Flush() {
	if !sc.wroteHeader {
		sc.WriteHeader(http.StatusOK)
	}
	if flusher, ok := sc.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Push preserves HTTP/2 server push support where the underlying writer has it.
func (sc *statusCapture) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := sc.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// ReadFrom keeps io.Copy on the underlying optimized path while recording the
// implicit success status.
func (sc *statusCapture) ReadFrom(src io.Reader) (int64, error) {
	if !sc.wroteHeader {
		sc.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := sc.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(src)
	}
	return io.Copy(sc.ResponseWriter, src)
}

// Middleware returns an HTTP middleware that enforces the three-tier defense.
// It should be inserted BEFORE the authentication middleware so that rate
// limiting blocks requests before the expensive secret-store key lookup.
func (d *AuthDefenseSystem) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := d.ipExtractor.Extract(r)

		// Pre-auth check: tenant ID not yet known
		allowed, reason := d.CheckRequest(ip, "")
		if !allowed {
			retryAfter := d.retryAfterSeconds(reason)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)

			if d.ShouldLog() {
				d.logger.Warn("Auth defense blocked request",
					"ip", logging.SanitizeLogValue(ip),
					"reason", reason,
				)
			}
			return
		}

		// Wrap response writer to capture status code
		sc := &statusCapture{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sc, r)

		// Post-auth: record result based on status code
		success := sc.code != http.StatusUnauthorized && sc.code != http.StatusForbidden
		tenantID := ""
		if d.tenantExtract != nil {
			tenantID = d.tenantExtract(r)
		}
		d.RecordResult(ip, tenantID, success)
	})
}

// retryAfterSeconds returns the appropriate Retry-After value based on the block reason
func (d *AuthDefenseSystem) retryAfterSeconds(reason string) int {
	switch reason {
	case "ip_rate_limited":
		return int(d.config.IPRateWindow / time.Second)
	case "tenant_circuit_open":
		return int(d.config.TenantRecoveryTime / time.Second)
	case "global_circuit_open":
		return int(d.config.GlobalRecoveryTime / time.Second)
	default:
		return 60
	}
}
