// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// recordingServiceController is a test implementation of ServiceController that
// records every OS-level call so tests can assert none happened.
type recordingServiceController struct {
	mu      sync.Mutex
	calls   []string
	self    map[string]bool
	selfErr error
	err     error
}

func (r *recordingServiceController) Control(_ context.Context, op ServiceOp, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, string(op)+":"+name)
	return r.err
}

func (r *recordingServiceController) IsStewardService(_ context.Context, name string) (bool, error) {
	return r.self[name], r.selfErr
}

func (r *recordingServiceController) callList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type actionFixture struct {
	h      *Handler
	ctrl   *recordingServiceController
	signer *cert.Certificate
	events *[]*cpTypes.Event
	mu     *sync.Mutex
}

func newActionFixture(t *testing.T) *actionFixture {
	t.Helper()
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	var mu sync.Mutex
	events := []*cpTypes.Event{}
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus: func(_ context.Context, e *cpTypes.Event) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, e)
		},
		Logger:            newTestLogger(t),
		ControllerCARoots: caPool,
	})
	require.NoError(t, err)
	ctrl := &recordingServiceController{self: map[string]bool{"cfgms-steward.service": true, "cfgms-steward": true}}
	h.registerStewardAction(ctrl)
	return &actionFixture{h: h, ctrl: ctrl, signer: signer, events: &events, mu: &mu}
}

// signedAction builds a steward_action command whose operator envelope signs exactly
// the supplied action.
func (f *actionFixture) signedAction(t *testing.T, verb, kind, name string, parameters map[string]string) *cpTypes.Command {
	t.Helper()
	content := testActionContent(t, operatorpayload.Action{Verb: verb, TargetKind: kind, TargetName: name, Parameters: parameters})
	params := signedActionParams(t, f.signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	params["execution_id"] = "exec-1"
	params["verb"] = verb
	params["target"] = map[string]interface{}{"kind": kind, "name": name}
	if parameters == nil {
		parameters = map[string]string{}
	}
	params["parameters"] = parameters
	return &cpTypes.Command{ID: "cmd-" + sigTestNonce(t), Type: cpTypes.CommandStewardAction, StewardID: "steward-test", Params: params}
}

func (f *actionFixture) run(cmd *cpTypes.Command) error {
	return f.h.handleStewardAction(context.Background(), cmd, f.ctrl)
}

func (f *actionFixture) lastEvent(t *testing.T) *cpTypes.Event {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, *f.events, "no event emitted")
	return (*f.events)[len(*f.events)-1]
}

func (f *actionFixture) eventCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(*f.events)
}

func TestStewardAction_ServiceVerbsCallController(t *testing.T) {
	for verb, op := range map[string]string{"service.start": "start", "service.stop": "stop", "service.restart": "restart"} {
		t.Run(verb, func(t *testing.T) {
			f := newActionFixture(t)
			require.NoError(t, f.run(f.signedAction(t, verb, "service", "nginx", nil)))
			assert.Equal(t, []string{op + ":nginx"}, f.ctrl.callList())

			ev := f.lastEvent(t)
			assert.Equal(t, cpTypes.EventScriptCompleted, ev.Type)
			assert.Equal(t, "exec-1", ev.Details["execution_id"])
			assert.Equal(t, 0, ev.Details["exit_code"])
			assert.Equal(t, "ok", ev.Details["result_code"])
		})
	}
}

func TestStewardAction_TargetAndParametersAsJSONStrings(t *testing.T) {
	f := newActionFixture(t)
	cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
	cmd.Params["target"] = `{"kind":"service","name":"nginx"}`
	cmd.Params["parameters"] = `{}`
	require.NoError(t, f.run(cmd))
	assert.Equal(t, []string{"start:nginx"}, f.ctrl.callList())
}

func TestStewardAction_SelfProtect(t *testing.T) {
	for _, verb := range []string{"service.stop", "service.restart"} {
		t.Run(verb, func(t *testing.T) {
			f := newActionFixture(t)
			require.NoError(t, f.run(f.signedAction(t, verb, "service", "cfgms-steward.service", nil)))
			assert.Empty(t, f.ctrl.callList(), "state must be unchanged")

			ev := f.lastEvent(t)
			assert.Equal(t, cpTypes.EventScriptCompleted, ev.Type)
			assert.Equal(t, "exec-1", ev.Details["execution_id"])
			assert.Equal(t, "self_protect", ev.Details["result_code"])
			assert.Equal(t, 1, ev.Details["exit_code"])
		})
	}
}

func TestStewardAction_SelfCheckFailureFailsClosed(t *testing.T) {
	f := newActionFixture(t)
	f.ctrl.selfErr = errors.New("bus down")
	require.NoError(t, f.run(f.signedAction(t, "service.stop", "service", "nginx", nil)))
	assert.Empty(t, f.ctrl.callList())
	assert.Equal(t, "failed", f.lastEvent(t).Details["result_code"])
}

func TestStewardAction_StartOfOwnServiceAllowed(t *testing.T) {
	f := newActionFixture(t)
	require.NoError(t, f.run(f.signedAction(t, "service.start", "service", "cfgms-steward.service", nil)))
	assert.Equal(t, []string{"start:cfgms-steward.service"}, f.ctrl.callList())
}

func TestStewardAction_UnsupportedAndNotFoundResultCodes(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"unsupported": {ErrServiceUnsupported, "unsupported"},
		"not_found":   {ErrServiceNotFound, "not_found"},
		"failed":      {errors.New("boom"), "failed"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newActionFixture(t)
			f.ctrl.err = tc.err
			require.NoError(t, f.run(f.signedAction(t, "service.start", "service", "nginx", nil)))
			ev := f.lastEvent(t)
			assert.Equal(t, cpTypes.EventScriptCompleted, ev.Type)
			assert.Equal(t, "exec-1", ev.Details["execution_id"])
			assert.Equal(t, tc.code, ev.Details["result_code"])
			assert.Equal(t, 1, ev.Details["exit_code"])
		})
	}
}

// Validation rejects before any OS call. The envelope signs the (invalid) values so
// the rejection is attributable to validation, not to the signature.
func TestStewardAction_InvalidRequestRejectedBeforeOSCall(t *testing.T) {
	cases := map[string]struct {
		verb, kind, name string
		parameters       map[string]string
	}{
		"unknown verb":          {"service.disable", "service", "nginx", nil},
		"process verb":          {"process.kill", "service", "nginx", nil},
		"wrong target kind":     {"service.start", "package", "nginx", nil},
		"name with space":       {"service.start", "service", "ng inx", nil},
		"name with slash":       {"service.start", "service", "../etc", nil},
		"name with semicolon":   {"service.start", "service", "a;b", nil},
		"name too long":         {"service.start", "service", strings.Repeat("a", 257), nil},
		"unexpected parameters": {"service.start", "service", "nginx", map[string]string{"force": "true"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newActionFixture(t)
			cmd := f.signedAction(t, tc.verb, tc.kind, tc.name, tc.parameters)
			require.Error(t, f.run(cmd))
			assert.Empty(t, f.ctrl.callList())
		})
	}
}

func TestStewardAction_UnexpectedParamKeyRejected(t *testing.T) {
	for _, key := range []string{"script_content", "shell", "command", "extra"} {
		t.Run(key, func(t *testing.T) {
			f := newActionFixture(t)
			cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
			cmd.Params[key] = "x"
			err := f.run(cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unexpected param")
			assert.Empty(t, f.ctrl.callList())
		})
	}
}

func TestStewardAction_MalformedTargetRejected(t *testing.T) {
	for name, target := range map[string]interface{}{
		"extra key":   map[string]interface{}{"kind": "service", "name": "nginx", "x": "y"},
		"missing key": map[string]interface{}{"kind": "service"},
		"bad json":    "{not json",
		"wrong type":  42,
	} {
		t.Run(name, func(t *testing.T) {
			f := newActionFixture(t)
			cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
			cmd.Params["target"] = target
			require.Error(t, f.run(cmd))
			assert.Empty(t, f.ctrl.callList())
		})
	}
}

func TestStewardAction_NoOperatorSignatureRejected(t *testing.T) {
	f := newActionFixture(t)
	cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
	for _, k := range []string{"signature_algorithm", "signature_value", "signature_public_key"} {
		delete(cmd.Params, k)
	}
	err := f.run(cmd)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Empty(t, f.ctrl.callList())
	assert.Zero(t, f.eventCount())
}

func TestStewardAction_ScriptEnvelopeRejected(t *testing.T) {
	f := newActionFixture(t)
	scriptContent := []byte(echoScriptBody("hi"))
	params := sigTestOperatorEnvelopeParams(t, f.signer.PrivateKeyPEM, string(f.signer.CertificatePEM), scriptContent, platformShell(), "steward-test")
	cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
	for _, k := range []string{"signature_algorithm", "signature_value", "signature_public_key", "targets", "nonce", "expires_at"} {
		cmd.Params[k] = params[k]
	}
	require.ErrorIs(t, f.run(cmd), ErrUnauthenticatedCommand)
	assert.Empty(t, f.ctrl.callList())
}

func TestStewardAction_ExpiryBeyondMaxTTLRejected(t *testing.T) {
	f := newActionFixture(t)
	content := testActionContent(t, operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "nginx", Parameters: map[string]string{}})
	cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
	params := signedActionParams(t, f.signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL+time.Hour))
	for _, k := range []string{"signature_algorithm", "signature_value", "signature_public_key", "targets", "nonce", "expires_at"} {
		cmd.Params[k] = params[k]
	}
	err := f.run(cmd)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Empty(t, f.ctrl.callList())
}

func TestStewardAction_AlteredAfterSigningRejected(t *testing.T) {
	mutations := map[string]func(*cpTypes.Command){
		"verb": func(c *cpTypes.Command) { c.Params["verb"] = "service.stop" },
		"target name": func(c *cpTypes.Command) {
			c.Params["target"] = map[string]interface{}{"kind": "service", "name": "sshd"}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newActionFixture(t)
			cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
			mutate(cmd)
			require.ErrorIs(t, f.run(cmd), ErrUnauthenticatedCommand)
			assert.Empty(t, f.ctrl.callList())
		})
	}
}

func TestStewardAction_ReplayAndExpiredRejected(t *testing.T) {
	t.Run("replayed nonce", func(t *testing.T) {
		f := newActionFixture(t)
		cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
		require.NoError(t, f.run(cmd))
		require.ErrorIs(t, f.run(cmd), ErrUnauthenticatedCommand)
		assert.Len(t, f.ctrl.callList(), 1)
	})
	t.Run("expired", func(t *testing.T) {
		f := newActionFixture(t)
		content := testActionContent(t, operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "nginx", Parameters: map[string]string{}})
		cmd := f.signedAction(t, "service.start", "service", "nginx", nil)
		params := signedActionParams(t, f.signer, content, []string{"steward-test"}, sigTestNonce(t), time.Now().Add(-time.Minute))
		for _, k := range []string{"signature_algorithm", "signature_value", "signature_public_key", "targets", "nonce", "expires_at"} {
			cmd.Params[k] = params[k]
		}
		require.ErrorIs(t, f.run(cmd), ErrUnauthenticatedCommand)
		assert.Empty(t, f.ctrl.callList())
	})
}

func TestStewardAction_RegisteredOnHandler(t *testing.T) {
	f := newActionFixture(t)
	f.h.mu.RLock()
	_, ok := f.h.handlers[cpTypes.CommandStewardAction]
	f.h.mu.RUnlock()
	assert.True(t, ok)

	h2, err := New(&Config{StewardID: "steward-test", OnStatus: noopStatus, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h2.RegisterStewardActionHandler()
	h2.mu.RLock()
	_, ok = h2.handlers[cpTypes.CommandStewardAction]
	h2.mu.RUnlock()
	assert.True(t, ok)
}

// Real-service tests: the platform controller drives a real OS service. They run only
// when CFGMS_TEST_SERVICE names a pre-provisioned, disposable service (systemd unit on
// Linux, SCM service on Windows) that the test runner may control.
func TestPlatformServiceController_RealService(t *testing.T) {
	name := os.Getenv("CFGMS_TEST_SERVICE")
	if name == "" {
		t.Skip("CFGMS_TEST_SERVICE not set: no disposable OS service provisioned on this runner")
	}
	ctrl := newPlatformServiceController()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	self, err := ctrl.IsStewardService(ctx, name)
	require.NoError(t, err)
	require.False(t, self, "test service must not be the test process's own service")
	require.NoError(t, ctrl.Control(ctx, ServiceOpStop, name))
	require.NoError(t, ctrl.Control(ctx, ServiceOpStart, name))
	require.NoError(t, ctrl.Control(ctx, ServiceOpRestart, name))
	require.ErrorIs(t, ctrl.Control(ctx, ServiceOpStart, "cfgms-no-such-service-xyz"), ErrServiceNotFound)
}

func TestPlatformServiceController_UnknownServiceNotFoundOrUnsupported(t *testing.T) {
	ctrl := newPlatformServiceController()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := ctrl.Control(ctx, ServiceOpStart, "cfgms-no-such-service-xyz")
	require.Error(t, err)
	if runtime.GOOS == "darwin" {
		assert.ErrorIs(t, err, ErrServiceUnsupported)
		return
	}
	// Elsewhere: not found when the manager is reachable, unsupported when it is not.
	assert.True(t, errors.Is(err, ErrServiceNotFound) || errors.Is(err, ErrServiceUnsupported), "got %v", err)
}

// The new files must not shell out.
func TestStewardActionFilesDoNotShellOut(t *testing.T) {
	files, err := filepath.Glob("service_control*.go")
	require.NoError(t, err)
	files = append(files, "steward_action.go")
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		src := string(b)
		for _, banned := range []string{"exec.Command", "\"os/exec\"", "systemctl", "sc.exe", "net stop"} {
			// Only code, not comments, may not reference these; the files carry none.
			for _, line := range strings.Split(src, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "//") {
					continue
				}
				assert.NotContains(t, line, banned, f)
			}
		}
	}
}
