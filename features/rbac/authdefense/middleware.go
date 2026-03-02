// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package authdefense

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// statusCapture wraps http.ResponseWriter to capture the response status code
type statusCapture struct {
	http.ResponseWriter
	code int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.code = code
	sc.ResponseWriter.WriteHeader(code)
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
