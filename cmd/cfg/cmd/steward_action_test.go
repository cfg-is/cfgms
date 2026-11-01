// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// actionCall is one POST to an action endpoint as the fake controller saw it.
type actionCall struct {
	Path string
	Raw  []byte
	Body map[string]interface{}
}

// fakeActionController is a minimal controller for the action verbs: resolve, the two
// action endpoints, run polling and run jobs. Behaviour is injected per test.
type fakeActionController struct {
	t        *testing.T
	stewards []StewardInfo
	// results maps steward id to the result code its job reports.
	results map[string]string
	// onAction, when non-nil, may refuse a request: return a status != 0 to answer with
	// that status and error code instead of accepting.
	onAction func(n int, c actionCall) (status int, code string)

	mu    sync.Mutex
	calls []actionCall
}

func (f *fakeActionController) Calls() []actionCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]actionCall(nil), f.calls...)
}

func (f *fakeActionController) handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/fleet/resolve":
		writeRunAPIResponse(w, f.stewards)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actions"):
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		require.NoError(f.t, json.Unmarshal(raw, &body))
		c := actionCall{Path: r.URL.Path, Raw: raw, Body: body}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		n := len(f.calls)
		f.mu.Unlock()
		if f.onAction != nil {
			if status, code := f.onAction(n, c); status != 0 {
				if status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required"`)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": code, "message": "refused"}})
				return
			}
		}
		id := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/stewards/"), "/")[0]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"run_id": "run-" + id}})
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/jobs"):
		runID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/runs/"), "/jobs")
		id := strings.TrimPrefix(runID, "run-")
		writeRunAPIResponse(w, []map[string]interface{}{
			{"job_id": "j-" + id, "device_id": id, "status": "completed", "result_code": f.results[id]},
		})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/runs/"):
		writeRunAPIResponse(w, map[string]interface{}{
			"run_id": strings.TrimPrefix(r.URL.Path, "/api/v1/runs/"), "status": "completed",
			"job_count": 1, "completed_jobs": 1,
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newActionFixture(t *testing.T, f *fakeActionController) *APIClient {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	saveExecGlobals(t)
	stewardURL = srv.URL
	stewardTLSInsecure = true
	bundlePath = generateTestBundleWithRSA(t, t.TempDir())
	runWaitPollInterval = time.Millisecond
	client, err := getStewardClient()
	require.NoError(t, err)
	return client
}

func threeStewards() []StewardInfo {
	return []StewardInfo{
		{ID: "s1", DNA: &StewardInfoDNA{Hostname: "h1"}},
		{ID: "s2", DNA: &StewardInfoDNA{Hostname: "h2"}},
		{ID: "s3", DNA: &StewardInfoDNA{Hostname: "h3"}},
	}
}

func svcSpec(word string) stewardActionSpec {
	return stewardActionSpec{Kind: stewardActionKindService, Word: word, Name: "spooler", Justification: "test"}
}

func runAction(t *testing.T, client *APIClient, selector string, spec stewardActionSpec, opts stewardActionOpts) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	opts.Stdout = &buf
	opts.WaitTimeout = 5 * time.Second
	err := runStewardAction(t.Context(), client, selector, spec, opts)
	return buf.String(), err
}

func TestStewardAction_ZeroMatchesFailsFast(t *testing.T) {
	f := &fakeActionController{}
	client := newActionFixture(t, f)
	_, err := runAction(t, client, "nothing", svcSpec("start"), stewardActionOpts{Yes: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matched no stewards")
	assert.Empty(t, f.Calls())
}

func TestStewardAction_MultiHostDeclinedSendsNothing(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()}
	client := newActionFixture(t, f)
	origTerm := isTerminalFn
	t.Cleanup(func() { isTerminalFn = origTerm })
	isTerminalFn = func() bool { return false }

	// Without --yes on a non-interactive stdin the real gate fails closed after
	// printing the count and the matched list.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stderr
	os.Stderr = w
	_, runErr := runAction(t, client, "tag:x", svcSpec("start"), stewardActionOpts{})
	require.NoError(t, w.Close())
	os.Stderr = orig
	out, _ := io.ReadAll(r)

	require.Error(t, runErr)
	assert.Contains(t, string(out), "matched 3 stewards")
	for _, k := range []string{"h1#s1", "h2#s2", "h3#s3"} {
		assert.Contains(t, string(out), k)
	}
	assert.Empty(t, f.Calls(), "a declined confirmation must send no request")

	// A negative interactive answer is the same gate returning an error.
	actionConfirmFn = func([]StewardInfo, bool) error { return fmt.Errorf("aborted by operator") }
	t.Cleanup(func() { actionConfirmFn = confirmMultiHost })
	_, runErr = runAction(t, client, "tag:x", svcSpec("start"), stewardActionOpts{})
	require.Error(t, runErr)
	assert.Empty(t, f.Calls())
}

func TestStewardAction_YesSubmitsOnePerStewardWithSignedEnvelope(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards(), results: map[string]string{"s1": "ok", "s2": "ok", "s3": "ok"}}
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "tag:x", svcSpec("restart"), stewardActionOpts{Yes: true})
	require.NoError(t, err)
	calls := f.Calls()
	require.Len(t, calls, 3)

	nonces := map[string]bool{}
	for i, id := range []string{"s1", "s2", "s3"} {
		c := calls[i]
		assert.Equal(t, "/api/v1/stewards/"+id+"/services/spooler/actions", c.Path)
		assert.Equal(t, []interface{}{id}, c.Body["targets"], "targets must be exactly this steward")
		assert.Equal(t, "restart", c.Body["action"])
		assert.Equal(t, "test", c.Body["justification"])

		nonce := c.Body["nonce"].(string)
		assert.NotEmpty(t, nonce)
		nonces[nonce] = true

		expires, err := time.Parse(time.RFC3339, c.Body["expires_at"].(string))
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL), expires, 10*time.Second)
		assert.False(t, expires.After(time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL)))

		verifyActionSignature(t, c, svcSpec("restart").action(), id)
		assert.Contains(t, out, "h"+id[1:]+"#"+id+": ok")
	}
	assert.Len(t, nonces, 3, "every steward needs its own nonce")
}

// verifyActionSignature checks the body's signature over CanonicalBytes of the
// envelope rebuilt from ActionContent, as the controller's verifier does.
func verifyActionSignature(t *testing.T, c actionCall, action operatorpayload.Action, id string) {
	t.Helper()
	content, err := operatorpayload.ActionContent(action)
	require.NoError(t, err)
	expires, err := time.Parse(time.RFC3339, c.Body["expires_at"].(string))
	require.NoError(t, err)
	canon, err := operatorpayload.CanonicalBytes(operatorpayload.Envelope{
		Content: content, Shell: operatorpayload.ActionShell, Targets: []string{id},
		Nonce: c.Body["nonce"].(string), ExpiresAt: expires,
	})
	require.NoError(t, err)

	sigMap := c.Body["signature"].(map[string]interface{})
	require.Equal(t, "ecdsa-sha256", sigMap["algorithm"])
	sig, err := base64.StdEncoding.DecodeString(sigMap["value"].(string))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(sigMap["public_key"].(string)))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	digest := sha256.Sum256(canon)
	assert.True(t, ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], sig), "signature must verify over CanonicalBytes")
}

func TestStewardAction_ProcessBody(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:1], results: map[string]string{"s1": "ok"}}
	client := newActionFixture(t, f)
	spec := stewardActionSpec{Kind: stewardActionKindProcess, Word: "suspend", Name: "4120", Image: "notepad.exe", Justification: "j"}

	_, err := runAction(t, client, "h1", spec, stewardActionOpts{})
	require.NoError(t, err)
	calls := f.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, "/api/v1/stewards/s1/processes/4120/actions", calls[0].Path)
	assert.Equal(t, "notepad.exe", calls[0].Body["image"])
	verifyActionSignature(t, calls[0], spec.action(), "s1")
}

func TestStewardAction_SingleStopRequiresConfirmation(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:1], results: map[string]string{"s1": "ok"}}
	client := newActionFixture(t, f)
	origTerm := isTerminalFn
	t.Cleanup(func() { isTerminalFn = origTerm })
	isTerminalFn = func() bool { return false }

	_, err := runAction(t, client, "h1", svcSpec("stop"), stewardActionOpts{})
	require.Error(t, err)
	assert.Empty(t, f.Calls())

	_, err = runAction(t, client, "h1", svcSpec("stop"), stewardActionOpts{Yes: true})
	require.NoError(t, err)
	assert.Len(t, f.Calls(), 1)
}

func TestStewardAction_MixedOutcomes(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards(), results: map[string]string{"s1": "ok", "s2": "expired", "s3": "self_protect"}}
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "tag:x", svcSpec("start"), stewardActionOpts{Yes: true})
	require.Error(t, err, "any non-ok steward makes the exit code non-zero")
	assert.Contains(t, out, "h1#s1: ok")
	assert.Contains(t, out, "h2#s2: expired, not run")
	assert.Contains(t, out, "h3#s3: refused: the steward will not act on itself")
}

func TestStewardAction_ResultCodeText(t *testing.T) {
	cases := map[string]string{
		"ok":              "ok",
		"self_protect":    "refused: the steward will not act on itself",
		"process_changed": "refused: the process at that PID is not the one named",
		"unsupported":     "unsupported",
		"failed":          "failed",
		"expired":         "expired, not run",
		"no_result":       "sent, no result reported: the action may have run",
	}
	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			f := &fakeActionController{stewards: threeStewards()[:1], results: map[string]string{"s1": code}}
			client := newActionFixture(t, f)
			out, err := runAction(t, client, "h1", svcSpec("start"), stewardActionOpts{})
			if code == "ok" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assert.Contains(t, out, "h1#s1: "+want)
		})
	}
}

func TestStewardAction_StepUpDelayPastExpiryResignsOnce(t *testing.T) {
	var ceremonies int
	f := &fakeActionController{stewards: threeStewards()[:1], results: map[string]string{"s1": "ok"}}
	// Request sequence: 1 challenged, 2 retried with token -> refused expired, 3 challenged,
	// 4 retried with token -> accepted.
	f.onAction = func(n int, _ actionCall) (int, string) {
		switch n {
		case 1, 3:
			return http.StatusUnauthorized, "STEP_UP_REQUIRED"
		case 2:
			return http.StatusBadRequest, "ENVELOPE_EXPIRED"
		}
		return 0, ""
	}
	client := newActionFixture(t, f)
	client.onStepUpRequired = func(_, _, _ string, _ []byte) (string, error) {
		ceremonies++
		return "tok", nil
	}

	_, err := runAction(t, client, "h1", svcSpec("start"), stewardActionOpts{})
	require.NoError(t, err)
	calls := f.Calls()
	require.Len(t, calls, 4)
	assert.Equal(t, 2, ceremonies, "the fresh envelope runs a second step-up")
	assert.NotEqual(t, calls[1].Raw, calls[2].Raw, "the re-signed body must differ")
	assert.NotEqual(t, calls[1].Body["nonce"], calls[2].Body["nonce"])
	assert.Equal(t, calls[2].Raw, calls[3].Raw, "the post-ceremony retry reuses the final body")
}

func TestStewardAction_SecondExpiryFailsClearly(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:1]}
	f.onAction = func(int, actionCall) (int, string) { return http.StatusBadRequest, "ENVELOPE_EXPIRED" }
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "h1", svcSpec("start"), stewardActionOpts{})
	require.Error(t, err)
	assert.Len(t, f.Calls(), 2, "exactly one re-sign")
	assert.Contains(t, out, "signature expired during step-up; run the command again")
}

func TestStewardAction_UnrelatedBadRequestDoesNotResign(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:1]}
	f.onAction = func(int, actionCall) (int, string) { return http.StatusBadRequest, "INVALID_ACTION" }
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "h1", svcSpec("start"), stewardActionOpts{})
	require.Error(t, err)
	assert.Len(t, f.Calls(), 1)
	assert.Contains(t, out, "INVALID_ACTION")
}

func TestStewardAction_BudgetExceededStopsSubmitting(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards(), results: map[string]string{"s1": "ok"}}
	f.onAction = func(n int, _ actionCall) (int, string) {
		if n == 2 {
			return http.StatusTooManyRequests, "ACTION_BUDGET_EXCEEDED"
		}
		return 0, ""
	}
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "tag:x", svcSpec("start"), stewardActionOpts{Yes: true})
	require.Error(t, err)
	assert.Len(t, f.Calls(), 2, "no submit after the budget refusal")
	assert.Contains(t, out, "h1#s1: ok")
	assert.Contains(t, out, "h2#s2: not submitted")
	assert.Contains(t, out, "h3#s3: not submitted")
}

func TestStewardAction_JSONWritesOnlyResultToStdout(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:2], results: map[string]string{"s1": "ok", "s2": "no_result"}}
	client := newActionFixture(t, f)

	out, err := runAction(t, client, "tag:x", svcSpec("start"), stewardActionOpts{Yes: true, JSON: true})
	require.Error(t, err)
	var parsed map[string]actionOutcome
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "stdout must be pure JSON: %q", out)
	assert.Equal(t, "ok", parsed["h1#s1"].Code)
	assert.Equal(t, "no_result", parsed["h2#s2"].Code)
	assert.Equal(t, "sent, no result reported: the action may have run", parsed["h2#s2"].Detail)
}

func TestStewardAction_RejectsBadInputBeforeAnyRequest(t *testing.T) {
	f := &fakeActionController{stewards: threeStewards()[:1]}
	client := newActionFixture(t, f)

	_, err := runAction(t, client, "h1", svcSpec("end"), stewardActionOpts{Yes: true})
	require.Error(t, err)
	spec := svcSpec("start")
	spec.Justification = " "
	_, err = runAction(t, client, "h1", spec, stewardActionOpts{Yes: true})
	require.Error(t, err)
	assert.Empty(t, f.Calls())
}
