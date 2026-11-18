// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGatherDiagnosticsReportsEverySection proves the stalled-state capture
// returns the evidence it can get and names what it cannot: a failing collector
// and a collector that never returns each appear in the output, and neither stops
// the sections after it. It needs no Docker or controller.
func TestGatherDiagnosticsReportsEverySection(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	sections := []diagnosticsSection{
		{"first", func(context.Context) (string, error) { return "evidence-one\n", nil }},
		{"failing", func(context.Context) (string, error) { return "", fmt.Errorf("docker: no such container") }},
		{"stalled", func(context.Context) (string, error) { <-release; return "never", nil }},
		{"last", func(context.Context) (string, error) { return "evidence-two", nil }},
	}

	start := time.Now()
	out := gatherDiagnostics(100*time.Millisecond, sections)
	require.Less(t, time.Since(start), 5*time.Second, "a hung collector must be abandoned at its timeout")

	require.Contains(t, out, "── first ──\nevidence-one\n")
	require.Contains(t, out, "── failing ──\n(unavailable: docker: no such container)")
	require.Contains(t, out, "── stalled ──\n(timed out after 100ms)")
	require.NotContains(t, out, "never")
	require.Contains(t, out, "── last ──\nevidence-two", "a section after a stalled one must still be captured")
}

// TestFetchDiagnosticsBodyKeepsRefusalBody proves an error response is returned as
// evidence rather than dropped, and that a server that never answers is bounded by
// the caller's context.
func TestFetchDiagnosticsBodyKeepsRefusalBody(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/refused", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "steward not found", http.StatusNotFound)
	})
	mux.HandleFunc("/hang", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { close(release); srv.Close() })

	out, err := fetchDiagnosticsBody(context.Background(), srv.Client(), srv.URL+"/refused")
	require.NoError(t, err)
	require.Equal(t, "HTTP 404\nsteward not found", out)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = fetchDiagnosticsBody(ctx, srv.Client(), srv.URL+"/hang")
	require.ErrorIs(t, err, context.DeadlineExceeded)

	_, err = fetchDiagnosticsBody(context.Background(), srv.Client(), "://bad url")
	require.Error(t, err)
}

// TestFilterLogLinesKeepsRelevantTail proves the controller-log filter keeps lines
// naming the steward or a stall keyword and bounds the result to the newest lines.
func TestFilterLogLinesKeepsRelevantTail(t *testing.T) {
	log := strings.Join([]string{
		`{"msg":"heartbeat ok"}`,
		`{"msg":"steward connected to ControlChannel","steward_id":"abc"}`,
		`{"msg":"unrelated"}`,
		`{"msg":"command push_signing_cert timed out"}`,
		`{"msg":"sync_dna failed","error":"DeadlineExceeded"}`,
	}, "\n")

	got := filterLogLines(log, 10, append([]string{"abc"}, diagnosticsLogKeywords...)...)
	require.Equal(t, strings.Join([]string{
		`{"msg":"steward connected to ControlChannel","steward_id":"abc"}`,
		`{"msg":"command push_signing_cert timed out"}`,
		`{"msg":"sync_dna failed","error":"DeadlineExceeded"}`,
	}, "\n"), got)

	got = filterLogLines(log, 1, "ControlChannel", "timed out", "DeadlineExceeded")
	require.Equal(t, `{"msg":"sync_dna failed","error":"DeadlineExceeded"}`, got)

	require.Empty(t, filterLogLines(log, 10, ""), "an empty needle (no steward ID) must not match every line")
}

// testCertPEM generates a client certificate at test time (never a committed
// fixture) and returns its PEM and serial.
func testCertPEM(t *testing.T, notAfter time.Time) (string, *big.Int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial := big.NewInt(0xBEEF42)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fleet-steward-test"},
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serial
}

const privateKeyMarker = "PRIVATE-KEY-MATERIAL-MUST-NOT-APPEAR"

// storedIdentityJSON is a steward-identity.json carrying key-like fields next to
// the three the diagnostics may print.
func storedIdentityJSON(stewardID string) string {
	return `{"steward_id":"` + stewardID + `","device_id":"dev-0123","overlap_expires_at":"2026-12-01T00:00:00Z",` +
		`"identity_key_pub":"` + privateKeyMarker + `","signing_cert_pems":["` + privateKeyMarker + `"]}`
}

// TestStewardDiagnosticsSectionsReportEverySection proves the restart-failure
// capture reports the stored-identity, certificate and steward-log sections, the
// controller's view of BOTH the previous and the newly read ID, and the session
// table; that a failing source does not suppress the others; and that no
// identity-file field beyond steward_id, device_id and overlap_expires_at is
// printed. It needs no Docker or controller.
func TestStewardDiagnosticsSectionsReportEverySection(t *testing.T) {
	const prevID = "steward-1795021278065063387-ca4fc9cef72f8308"
	const newID = "steward-…"
	certPEM, serial := testCertPEM(t, time.Now().Add(-time.Hour))
	stewardLog := strings.Join([]string{
		`{"msg":"heartbeat ok"}`,
		`{"msg":"Stored-identity reconnect failed; requesting re-admission with the device key","error":"x509: certificate has expired"}`,
		`{"msg":"Reconnected to controller via stored identity","steward_id":"` + prevID + `"}`,
		`{"msg":"Subscribing to commands","steward_id":"steward-…"}`,
	}, "\n")

	var execCalls []string
	src := diagnosticsSources{
		httpGet: func(_ context.Context, path string) (string, error) {
			if strings.Contains(path, url.PathEscape(newID)) {
				return "", fmt.Errorf("HTTP 404 for %s", path)
			}
			return "body of " + path, nil
		},
		controllerLog: func(context.Context) (string, error) {
			return `{"msg":"GET /api/v1/stewards/steward-…"}` + "\n" + `{"msg":"unrelated"}`, nil
		},
		containerExec: func(_ context.Context, container string, args ...string) (string, error) {
			execCalls = append(execCalls, container+" "+strings.Join(args, " "))
			switch {
			case args[0] == "cat":
				return storedIdentityJSON(prevID), nil
			case strings.Contains(args[len(args)-1], "cert.pem"):
				return "== /var/lib/cfgms/steward/certs/beef42/cert.pem\n" + certPEM, nil
			default:
				return stewardLog, nil
			}
		},
	}

	sections := append(controllerDiagnosticsSections(src, []string{prevID, newID, prevID, ""}),
		stewardDiagnosticsSections(src, "fleet-steward-2")...)
	out := gatherDiagnostics(time.Second, sections)

	for _, title := range []string{
		"── controller steward record " + prevID + " ──",
		"── controller session " + prevID + " ──",
		"── controller steward record " + newID + " ──",
		"── controller session " + newID + " ──",
		"── controller session table ──",
		"── controller log (sessions, timeouts, refusals) ──",
		"── steward stored identity fleet-steward-2 ──",
		"── steward client certificates fleet-steward-2 ──",
		"── steward log: reconnect path fleet-steward-2 ──",
		"── steward log: last steward_id fields fleet-steward-2 ──",
	} {
		require.Contains(t, out, title)
	}
	require.Equal(t, 1, strings.Count(out, "── controller steward record "+prevID+" ──"), "a repeated ID is reported once")

	// A failing section is named in place and does not stop the sections after it.
	require.Contains(t, out, "── controller steward record steward-… ──\n(unavailable: HTTP 404")
	require.Contains(t, out, "body of /api/v1/stewards/connections/all")

	// Stored identity and certificate values.
	require.Contains(t, out, "steward_id: "+prevID)
	require.Contains(t, out, "device_id: dev-0123")
	require.Contains(t, out, "overlap_expires_at: 2026-12-01T00:00:00Z")
	require.Contains(t, out, "serial="+serial.Text(16))
	require.Contains(t, out, "expired=true")
	require.NotContains(t, out, privateKeyMarker)

	// Reconnect-path lines are kept; unrelated lines are not.
	require.Contains(t, out, "requesting re-admission with the device key")
	require.NotContains(t, out, "heartbeat ok")
	require.NotContains(t, out, `{"msg":"unrelated"}`)

	// Only the fixed commands run, and never against key files.
	require.NotEmpty(t, execCalls)
	for _, c := range execCalls {
		require.NotContains(t, c, "key.pem")
	}
}

// TestStewardDiagnosticsSectionsSurviveUnreachableContainer covers the error path:
// when the container cannot be exec'd into, every steward section says so and the
// controller sections are still produced.
func TestStewardDiagnosticsSectionsSurviveUnreachableContainer(t *testing.T) {
	src := diagnosticsSources{
		httpGet:       func(_ context.Context, path string) (string, error) { return "ok " + path, nil },
		controllerLog: func(context.Context) (string, error) { return "", fmt.Errorf("docker: no such container") },
		containerExec: func(context.Context, string, ...string) (string, error) {
			return "", fmt.Errorf("container is not running")
		},
	}
	sections := append(controllerDiagnosticsSections(src, []string{"steward-a"}), stewardDiagnosticsSections(src, "fleet-steward-1")...)
	out := gatherDiagnostics(time.Second, sections)

	require.Contains(t, out, "ok /api/v1/stewards/connections/all")
	require.Contains(t, out, "── controller log (sessions, timeouts, refusals) ──\n(unavailable: docker: no such container)")
	require.Contains(t, out, "── steward stored identity fleet-steward-1 ──\n(unavailable: container is not running)\nno stored identity readable at "+stewardIdentityFile)
	require.Equal(t, 4, strings.Count(out, "(unavailable: container is not running)"))
}

func TestFormatStoredIdentityRejectsInvalidJSON(t *testing.T) {
	_, err := formatStoredIdentity("not json")
	require.Error(t, err)

	out, err := formatStoredIdentity(`{"steward_id":"s","device_id":"d"}`)
	require.NoError(t, err)
	require.Contains(t, out, "overlap_expires_at: (none)")
}

func TestFormatStoredCertsHandlesAbsentAndBadCerts(t *testing.T) {
	now := time.Now()
	require.Contains(t, formatStoredCerts("", now), "no certificate present")

	out := formatStoredCerts("== /certs/a/cert.pem\nnot a pem\n", now)
	require.Contains(t, out, "/certs/a/cert.pem: no PEM certificate")

	valid, _ := testCertPEM(t, now.Add(24*time.Hour))
	out = formatStoredCerts("== /certs/b/cert.pem\n"+valid, now)
	require.Contains(t, out, "expired=false")
	require.Contains(t, out, `subject="CN=fleet-steward-test"`)
}

// TestDiagnosticsSourcesRefuseNonFleetContainers proves the live channels keep the
// fleet allowlist: a name outside it is refused before docker is run.
func TestDiagnosticsSourcesRefuseNonFleetContainers(t *testing.T) {
	s := &FleetTestSuite{}
	_, err := s.diagnosticsSources().containerExec(context.Background(), "not-a-fleet-container", "cat", "/etc/passwd")
	require.ErrorContains(t, err, "not in fleet allowlist")
}

// TestPollStewardIDKeepsPollingPastRedactedIDs proves the poll loop does not return
// at the first non-empty steward_id: it waits out reads whose last steward_id is
// redacted (or that fail) and returns the complete ID once one appears.
func TestPollStewardIDKeepsPollingPastRedactedIDs(t *testing.T) {
	const full = "steward-1795021278065063387-ca4fc9cef72f8308"
	reads := []struct {
		log string
		err error
	}{
		{log: `{"msg":"Subscribing to commands","steward_id":"steward-…"}`},
		{err: fmt.Errorf("docker exec failed")},
		{log: `{"msg":"x","steward_id":"` + full + `"}` + "\n" + `{"msg":"y","steward_id":"steward-…"}`},
	}
	calls := 0
	id, err := pollStewardID(t, "fleet-steward-2", 10, time.Millisecond, func() (string, error) {
		r := reads[min(calls, len(reads)-1)]
		calls++
		return r.log, r.err
	})
	require.NoError(t, err)
	require.Equal(t, full, id)
	require.Equal(t, 3, calls, "the loop must poll past the redacted and failed reads")
}

func TestPollStewardIDFailsWhenOnlyRedactedIDsAppear(t *testing.T) {
	calls := 0
	id, err := pollStewardID(t, "fleet-steward-2", 4, time.Millisecond, func() (string, error) {
		calls++
		return `{"steward_id":"steward-…"}`, nil
	})
	require.Error(t, err)
	require.Empty(t, id)
	require.Equal(t, 4, calls)
	require.Contains(t, err.Error(), "complete steward ID not found")
}
