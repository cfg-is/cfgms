// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/logging"
)

// API request signals (Issue #6055). The controller exports request latency and
// request counts per route class so a deploy gate can compare revisions. They are
// recorded in the service-level signal registry (Issue #6054) and scraped from the
// private metrics listener.
//
// Both signals carry two labels only. route_class is a member of a closed set: the
// first path segment after /api/v1 when it is in apiRouteClassAllowlist, "static"
// for the SPA fallback route, and "other" for everything else. status_class is the
// status code's hundreds digit. The raw request path, and therefore any tenant,
// steward or credential segment in it, is never a label value.
const (
	apiRequestDurationMetric = "cfgms_api_request_duration_seconds"
	apiRequestsTotalMetric   = "cfgms_api_requests_total"

	routeClassLabel  = "route_class"
	statusClassLabel = "status_class"

	routeClassStatic = "static"
	routeClassOther  = "other"

	apiPathPrefix = "/api/v1"
)

// apiRouteClassAllowlist is the set of first path segments after /api/v1 that are
// reported as their own route class. A segment outside it, including any path
// parameter, is reported as "other", which bounds the series count by this list
// rather than by request input. Adding an API area adds it here.
var apiRouteClassAllowlist = []string{
	"accounts", "alerts", "api-keys", "audit", "automation", "billing", "cases",
	"certificates", "cli-login", "cli-presence", "cluster", "clusters", "commands",
	"compliance", "config", "configs", "credential-renewal", "credential-requests",
	"directory", "enrolment-tokens", "entities", "fleet", "ha", "health", "hyperv",
	"installer", "jobs", "modules", "monitoring", "notifications", "operator-payload",
	"osquery", "public", "rbac", "ready", "register", "registration", "reports",
	"rollback", "roles", "rollout", "runs", "scripts", "sessions", "signing-credential",
	"stewards", "tenant-crossings", "tenants", "terminal", "triggers", "web",
	"webauthn", "webhooks", "workflows",
}

// apiStatusClasses are the status_class label values, in status-code order.
var apiStatusClasses = []string{"2xx", "3xx", "4xx", "5xx"}

// apiLatencyBuckets are the duration histogram's upper bounds in seconds.
var apiLatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

var apiRouteClassSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(apiRouteClassAllowlist))
	for _, seg := range apiRouteClassAllowlist {
		set[seg] = struct{}{}
	}
	return set
}()

// routeClassFromTemplate maps a matched mux route path template to its route
// class. The template, never the request path, is the input: "/api/v1/stewards/{id}"
// is "stewards" for every steward ID.
func routeClassFromTemplate(template string) string {
	if template == "/" {
		return routeClassStatic
	}
	rest, ok := strings.CutPrefix(template, apiPathPrefix+"/")
	if !ok {
		return routeClassOther
	}
	segment, _, _ := strings.Cut(rest, "/")
	if _, allowed := apiRouteClassSet[segment]; allowed {
		return segment
	}
	return routeClassOther
}

// routeClassOfRequest returns the route class of the route mux matched for r.
func routeClassOfRequest(r *http.Request) string {
	route := mux.CurrentRoute(r)
	if route == nil {
		return routeClassOther
	}
	template, err := route.GetPathTemplate()
	if err != nil {
		return routeClassOther
	}
	return routeClassFromTemplate(template)
}

// statusClassOf returns the status_class label for an HTTP status code and false
// for a code outside 200-599, which has no class.
func statusClassOf(status int) (string, bool) {
	if status < 200 || status > 599 {
		return "", false
	}
	return apiStatusClasses[status/100-2], true
}

// apiSignalInstruments are the registered API request instruments of one health
// collector.
type apiSignalInstruments struct {
	duration *health.Histogram
	requests *health.Counter
}

// apiSignals holds the API request instruments of a Server. They are registered on
// first use of a collector, not at construction, because a Server's collector can
// be assigned after its router is built.
type apiSignals struct {
	mu          sync.Mutex
	collector   *health.Collector
	instruments *apiSignalInstruments // nil when registration on collector failed
}

// instrumentsFor returns the instruments registered on collector, registering them
// on first use, or nil for a nil collector or a failed registration. The logger is
// used once per collector, on a registration failure.
func (a *apiSignals) instrumentsFor(collector *health.Collector, logger logging.Logger) *apiSignalInstruments {
	if collector == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.collector == collector {
		return a.instruments
	}
	a.collector = collector
	a.instruments = nil

	classes := make([]string, 0, len(apiRouteClassAllowlist)+2)
	classes = append(classes, apiRouteClassAllowlist...)
	classes = append(classes, routeClassStatic, routeClassOther)
	labels := map[string][]string{routeClassLabel: classes, statusClassLabel: apiStatusClasses}

	duration, err := collector.Signals().RegisterHistogram(apiRequestDurationMetric,
		"API request duration in seconds by route class and status class.", apiLatencyBuckets, labels)
	if err != nil {
		logger.Warn("API request signals disabled: duration histogram registration failed",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	requests, err := collector.Signals().RegisterCounter(apiRequestsTotalMetric,
		"API requests by route class and status class.", labels)
	if err != nil {
		logger.Warn("API request signals disabled: request counter registration failed",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	a.instruments = &apiSignalInstruments{duration: duration, requests: requests}
	return a.instruments
}

// record counts one finished request and, unless its connection was hijacked,
// observes its duration. A hijacked connection (a WebSocket) lives for as long as
// the session does, so its duration is not a request latency. A status outside
// 200-599 has no class and records nothing.
func (i *apiSignalInstruments) record(logger logging.Logger, routeClass string, status int, elapsed time.Duration, hijacked bool) {
	statusClass, ok := statusClassOf(status)
	if !ok {
		return
	}
	labels := map[string]string{routeClassLabel: routeClass, statusClassLabel: statusClass}
	if err := i.requests.Inc(labels); err != nil {
		logger.Warn("API request signal rejected", "error", logging.SanitizeLogValue(err.Error()))
	}
	if hijacked {
		return
	}
	if err := i.duration.Observe(elapsed.Seconds(), labels); err != nil {
		logger.Warn("API request signal rejected", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// serveWithSignals serves next through a status-capturing responseWriter and
// records the request under routeClass. It serves next unwrapped when the server
// has no health collector.
func (s *Server) serveWithSignals(w http.ResponseWriter, r *http.Request, routeClass string, next http.Handler) {
	instruments := s.apiSignals.instrumentsFor(s.healthCollector, s.logger)
	if instruments == nil {
		next.ServeHTTP(w, r)
		return
	}
	start := time.Now()
	wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	next.ServeHTTP(wrapped, r)
	instruments.record(s.logger, routeClass, wrapped.statusCode, time.Since(start), wrapped.hijacked)
}

// signalsMiddleware records API request latency and count by route class. It is
// registered on the public router ahead of authenticationMiddleware, so refused
// requests (401, 403) count, and on the private metrics router. A server without
// a health collector passes requests through untouched.
//
// gorilla/mux skips Use() middleware for unmatched routes and method mismatches,
// so those are recorded by notFoundHandler and methodNotAllowedHandler instead.
func (s *Server) signalsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveWithSignals(w, r, routeClassOfRequest(r), next)
	})
}
