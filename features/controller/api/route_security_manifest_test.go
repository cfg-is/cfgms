// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"testing"

	"github.com/gorilla/mux"
)

// routeSecurityPolicy is the machine-checked security matrix for an HTTP
// entrypoint. Authenticated API routes inherit the policy from the /api/v1
// subrouter; every route outside that subrouter must be explicitly allowlisted.
type routeSecurityPolicy struct {
	Exposure         string
	Authentication   string
	Permission       string
	Assurance        string
	TenantDerivation string
	CSRF             string
	Limits           string
	SideEffects      string
	Audit            string
}

var publicRouteSecurityPolicies = map[string]routeSecurityPolicy{
	"GET /api/v1/health":                                              publicReadPolicy("none", "liveness"),
	"OPTIONS /api/v1/health":                                          publicReadPolicy("none", "CORS preflight"),
	"GET /api/v1/ready":                                               publicReadPolicy("none", "readiness"),
	"OPTIONS /api/v1/ready":                                           publicReadPolicy("none", "CORS preflight"),
	"POST /api/v1/register":                                           publicWritePolicy("single-use registration token", "registration.requested"),
	"OPTIONS /api/v1/register":                                        publicReadPolicy("none", "CORS preflight"),
	"GET /api/v1/registration/status/{pending_id}":                    publicReadPolicy("registration token", "registration status"),
	"POST /api/v1/stewards/{device_id}/refresh/challenge":             publicWritePolicy("device proof-of-possession", "refresh.challenge"),
	"OPTIONS /api/v1/stewards/{device_id}/refresh/challenge":          publicReadPolicy("none", "CORS preflight"),
	"POST /api/v1/stewards/{device_id}/refresh/complete":              publicWritePolicy("device proof-of-possession", "refresh.complete"),
	"OPTIONS /api/v1/stewards/{device_id}/refresh/complete":           publicReadPolicy("none", "CORS preflight"),
	"GET /api/v1/web/csrf":                                            publicReadPolicy("none", "pre-session CSRF issuance"),
	"POST /api/v1/web/passkey/enroll/begin":                           publicWritePolicy("enrollment magic-link token (single-use, TTL-bounded)", "web.passkey.enroll.begin"),
	"POST /api/v1/web/passkey/enroll/finish":                          publicWritePolicy("enrollment magic-link token plus WebAuthn attestation", "web.passkey.enroll.finish"),
	"POST /api/v1/web/passkey/login/begin":                            publicWritePolicy("pre-session CSRF plus passkey ceremony", "web.passkey.login.begin"),
	"POST /api/v1/web/passkey/login/finish":                           publicWritePolicy("passkey assertion plus ceremony cookie", "web.passkey.login.finish"),
	"POST /api/v1/web/logout":                                         publicWritePolicy("web session plus session CSRF", "web.logout"),
	"GET /api/v1/installer/download/{platform}/{arch}":                publicReadPolicy("none", "signed installer download"),
	"GET /api/v1/public/steward-binaries/{version}/{platform}/{arch}": publicReadPolicy("none", "signed binary download"),
	// The webhook handler enforces the signature for every matched binding and
	// fails closed: a binding without a webhook secret is rejected with 401 rather
	// than synced unauthenticated (pkg/gitsync/webhook.go).
	"POST /api/v1/webhooks/git-push": publicWritePolicy("mandatory HMAC-SHA256 request signature per matched binding", "webhook.git-push"),
	// Lodge (Issue #3717): the enrolling machine holds no API key or mTLS credential —
	// only the pre-shared, single-use enrolment token as a bearer value, resolved and
	// validated before any store write (handleLodgeCredentialRequest).
	"POST /api/v1/credential-requests/lodge": publicWritePolicy("single-use enrolment token (bearer)", "credential_request.lodged"),
	// Collect (Issue #3719): the enrolling machine holds no API key or mTLS credential —
	// only the single-use collect secret returned exactly once at lodge time, compared
	// in constant time against its stored hash before anything is disclosed or minted
	// (handleCollectCredentialRequest).
	"POST /api/v1/credential-requests/{id}/collect": publicWritePolicy("single-use collect secret (bearer)", "credential_request.collected"),
	// Lodge (Issue #3721): the operator holds no API key or mTLS credential yet — this is
	// the bootstrap path. No pre-shared secret gates lodge itself (unlike credential-
	// request lodge); the CLI-generated verifier is established here and never disclosed
	// again until collect (handleLodgeCliLoginRequest).
	"POST /api/v1/cli-login/lodge": publicWritePolicy("none — bootstrap path; CLI-generated verifier established here", "cli_login.lodged"),
	// Collect (Issue #3721): the CLI holds no API key or mTLS credential — only the
	// verifier it generated locally and never transmitted until now, compared in
	// constant time against its stored hash before the minted session token is disclosed
	// (handleCollectCliLoginRequest).
	"POST /api/v1/cli-login/{id}/collect": publicWritePolicy("single-use CLI-generated verifier (bearer)", "cli_login.collected"),
}

func publicReadPolicy(authentication, event string) routeSecurityPolicy {
	return routeSecurityPolicy{
		Exposure:         "public",
		Authentication:   authentication,
		Permission:       "endpoint protocol",
		Assurance:        "endpoint protocol",
		TenantDerivation: "server-side token/path validation",
		CSRF:             "safe method or not cookie-authenticated",
		Limits:           "global source rate, header, and request-body budgets",
		SideEffects:      "none",
		Audit:            event,
	}
}

func publicWritePolicy(authentication, event string) routeSecurityPolicy {
	policy := publicReadPolicy(authentication, event)
	policy.CSRF = "endpoint-specific token/proof"
	policy.SideEffects = "state-changing"
	return policy
}

func authenticatedRoutePolicy(method string) routeSecurityPolicy {
	sideEffects := "none"
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		sideEffects = "state-changing"
	}
	return routeSecurityPolicy{
		Exposure:         "public",
		Authentication:   "API key, mTLS admin, or web session",
		Permission:       "route-declared RBAC permission",
		Assurance:        "route-declared minimum assurance",
		TenantDerivation: "authenticated principal plus validated same/child target",
		CSRF:             "session-bound token for unsafe cookie-auth requests",
		Limits:           "global source rate, principal defense, header, and request-body budgets",
		SideEffects:      sideEffects,
		Audit:            "authorization decision plus handler event",
	}
}

func validateRoutePolicy(policy routeSecurityPolicy) error {
	if policy.Exposure == "" || policy.Authentication == "" || policy.Permission == "" ||
		policy.Assurance == "" || policy.TenantDerivation == "" || policy.CSRF == "" ||
		policy.Limits == "" || policy.SideEffects == "" || policy.Audit == "" {
		return fmt.Errorf("one or more required security fields are empty")
	}
	return nil
}

func TestEveryHTTPRouteHasSecurityClassification(t *testing.T) {
	s := setupRouteTestServer(t)
	router := s.router

	err := router.Walk(func(route *mux.Route, _ *mux.Router, ancestors []*mux.Route) error {
		path, pathErr := route.GetPathTemplate()
		if pathErr != nil {
			return nil
		}
		methods, methodErr := route.GetMethods()
		if methodErr != nil || len(methods) == 0 {
			// Subrouter prefixes and the SPA fallback are not HTTP entrypoints.
			return nil
		}

		protected := false
		for _, ancestor := range ancestors {
			if prefix, prefixErr := ancestor.GetPathTemplate(); prefixErr == nil && prefix == "/api/v1" {
				protected = true
				break
			}
		}

		for _, method := range methods {
			key := method + " " + path
			var policy routeSecurityPolicy
			if protected {
				policy = authenticatedRoutePolicy(method)
			} else {
				var ok bool
				policy, ok = publicRouteSecurityPolicies[key]
				if !ok {
					return fmt.Errorf("route outside authenticated subrouter lacks explicit policy: %s", key)
				}
			}
			if policyErr := validateRoutePolicy(policy); policyErr != nil {
				return fmt.Errorf("%s: %w", key, policyErr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The private mTLS-only internal listener carried the Raft message route
	// before Issue #3763 deleted the Raft transport it delegated to; it
	// currently serves no HTTP routes of its own (the internal delivery
	// service registered on the same listener is gRPC, not HTTP).
	internalEntries := walkRoutes(t, s.internalRouter)
	if len(internalEntries) != 0 {
		t.Fatalf("unexpected private listener route set: %v", internalEntries)
	}

	metricsEntries := walkRoutes(t, s.metricsRouter)
	wantMetricsEntries := []string{
		"* /api/v1",
		"* /api/v1/monitoring",
		"GET /api/v1/monitoring/components/{component}/metrics",
		"GET /api/v1/monitoring/metrics",
	}
	if len(metricsEntries) != len(wantMetricsEntries) {
		t.Fatalf("unexpected private metrics route set: %v", metricsEntries)
	}
	for i, want := range wantMetricsEntries {
		if metricsEntries[i].String() != want {
			t.Fatalf("private metrics route %d = %q, want %q", i, metricsEntries[i].String(), want)
		}
	}
}
