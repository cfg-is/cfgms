// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package smtp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/notification/interfaces"
	"github.com/cfgis/cfgms/pkg/notification/interfaces/contracttest"
)

func cfgFor(s *testServer, security string, extra map[string]interface{}) map[string]interface{} {
	c := map[string]interface{}{
		"host": s.Host, "port": s.Port, "security": security,
		"from": "cfgms@example.com", "username": s.user, "password": s.pass,
		"root_ca_pem": string(s.CAPEM), "timeout": "5s",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func newNotifier(t *testing.T, cfg map[string]interface{}) interfaces.Notifier {
	t.Helper()
	n, err := (&Provider{}).CreateNotifier(cfg)
	require.NoError(t, err)
	return n
}

func TestRegisteredViaInit(t *testing.T) {
	p, err := interfaces.GetNotifierProvider(ProviderName)
	require.NoError(t, err)
	assert.Equal(t, "smtp", p.Name())
}

func TestContract(t *testing.T) {
	for _, mode := range []string{SecurityStartTLS, SecurityImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, mode == SecurityImplicitTLS, func(s *testServer) {
				s.rejectRcpt["rejected@example.com"] = true
			})
			contracttest.Run(t, contracttest.Harness{
				Notifier:        newNotifier(t, cfgFor(s, mode, nil)),
				GoodAddress:     "good@example.com",
				RejectedAddress: "rejected@example.com",
				Sent:            s.Conns,
			})
		})
	}
}

func TestDeliveryTLSBeforeAuthAndData(t *testing.T) {
	for _, mode := range []string{SecurityStartTLS, SecurityImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, mode == SecurityImplicitTLS, nil)
			n := newNotifier(t, cfgFor(s, mode, nil))
			res, err := n.Send(context.Background(), interfaces.Message{
				To: []string{"a@example.com"}, Subject: "héllo", Body: "line1\n.dot line\n",
			})
			require.NoError(t, err)
			assert.Equal(t, []string{"a@example.com"}, res.Accepted())

			assert.Equal(t, []string{"tls", "auth", "data"}, s.Events())
			assert.False(t, s.PlainAuthSeen())
			msgs := s.Messages()
			require.Len(t, msgs, 1)
			assert.Contains(t, msgs[0], "To: <a@example.com>")
			assert.Contains(t, msgs[0], "Content-Type: text/plain")
			assert.Contains(t, msgs[0], "..dot line")
		})
	}
}

func TestUntrustedCertificateFailsWithoutCredentials(t *testing.T) {
	for _, mode := range []string{SecurityStartTLS, SecurityImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, mode == SecurityImplicitTLS, nil)
			cfg := cfgFor(s, mode, nil)
			delete(cfg, "root_ca_pem") // server CA is not trusted
			n := newNotifier(t, cfg)
			res, err := n.Send(context.Background(), interfaces.Message{
				To: []string{"a@example.com"}, Subject: "s", Body: "b",
			})
			require.Error(t, err)
			assert.Nil(t, res)
			assert.Contains(t, err.Error(), "certificate verification failed")
			assert.NotContains(t, s.Events(), "auth")
			assert.NotContains(t, s.Events(), "data")
			assert.NotContains(t, s.Raw(), "AUTH")
		})
	}
}

func TestValidationBeforeNetwork(t *testing.T) {
	s := newTestServer(t, false, nil)
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, nil))
	for name, msg := range map[string]interfaces.Message{
		"subject CR": {To: []string{"a@example.com"}, Subject: "x\ry"},
		"subject LF": {To: []string{"a@example.com"}, Subject: "x\ny"},
		"addr CR":    {To: []string{"a@example.com\rBcc: b@example.com"}},
		"addr LF":    {To: []string{"a@example.com\nBcc: b@example.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := n.Send(context.Background(), msg)
			require.Error(t, err)
		})
	}
	assert.Zero(t, s.Conns())
}

func TestPartialRecipientRejection(t *testing.T) {
	s := newTestServer(t, false, func(s *testServer) { s.rejectRcpt["bad@example.com"] = true })
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, nil))
	res, err := n.Send(context.Background(), interfaces.Message{
		To:      []string{"one@example.com", "bad@example.com", "three@example.com"},
		Subject: "s", Body: "b",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, []string{"one@example.com", "three@example.com"}, res.Accepted())
	require.Len(t, res.Failed(), 1)
	assert.Equal(t, "bad@example.com", res.Failed()[0].Address)
	assert.Equal(t, "rejected by server (code 550)", res.Failed()[0].Reason)
	assert.Len(t, s.Messages(), 1)
}

func TestAllRecipientsRejectedSendsNoBody(t *testing.T) {
	s := newTestServer(t, false, func(s *testServer) { s.rejectRcpt["bad@example.com"] = true })
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, nil))
	res, err := n.Send(context.Background(), interfaces.Message{To: []string{"bad@example.com"}, Subject: "s", Body: "b"})
	require.NoError(t, err)
	assert.Empty(t, res.Accepted())
	assert.Empty(t, s.Messages())
}

func TestAuthFailureErrorLeaksNothing(t *testing.T) {
	s := newTestServer(t, false, nil)
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, map[string]interface{}{"password": "wrong-password-xyz"}))
	_, err := n.Send(context.Background(), interfaces.Message{To: []string{"victim@example.com"}, Subject: "s", Body: "b"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
	assertClean(t, err, "wrong-password-xyz", "victim@example.com", s.pass)
}

func TestTimeoutErrorLeaksNothing(t *testing.T) {
	s := newTestServer(t, false, func(s *testServer) { s.stall = true })
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, map[string]interface{}{"timeout": "300ms"}))
	start := time.Now()
	_, err := n.Send(context.Background(), interfaces.Message{To: []string{"victim@example.com"}, Subject: "s", Body: "b"})
	require.Error(t, err)
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.Contains(t, err.Error(), "timed out")
	assertClean(t, err, s.pass, "victim@example.com")
}

func assertClean(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, sec := range secrets {
		assert.False(t, strings.Contains(err.Error(), sec), "error leaked %q", sec)
	}
}

func TestCreateNotifierRejectsPlaintextAndBadConfig(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{"host": "mail.example.com", "from": "a@example.com"}
	}
	good, err := (&Provider{}).CreateNotifier(base())
	require.NoError(t, err)
	assert.Equal(t, 587, good.(*notifier).port)
	assert.Equal(t, SecurityStartTLS, good.(*notifier).security)

	bad := map[string]map[string]interface{}{
		"security none":      {"security": "none"},
		"security plaintext": {"security": "plaintext"},
		"security tls":       {"security": "tls"},
		"insecure key":       {"insecure": true},
		"skip verify key":    {"insecure_skip_verify": true},
		"tls false":          {"tls": false},
		"plaintext key":      {"plaintext": true},
		"bad port":           {"port": 70000},
		"bad timeout":        {"timeout": "-1s"},
		"password w/o user":  {"password": "x"},
		"bad from":           {"from": "nope"},
		"crlf from":          {"from": "a@example.com\r\nBcc: x@y.z"},
		"bad ca":             {"root_ca_pem": "not pem"},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			for k, v := range extra {
				cfg[k] = v
			}
			_, err := (&Provider{}).CreateNotifier(cfg)
			require.Error(t, err)
		})
	}
	_, err = (&Provider{}).CreateNotifier(map[string]interface{}{"from": "a@example.com"})
	require.Error(t, err, "host required")
}

func TestStartTLSRequiredWhenNotOffered(t *testing.T) {
	// An implicit-TLS server spoken to as STARTTLS fails the handshake/greeting;
	// the send must fail rather than fall back to plaintext.
	s := newTestServer(t, true, nil)
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, nil))
	_, err := n.Send(context.Background(), interfaces.Message{To: []string{"a@example.com"}, Subject: "s", Body: "b"})
	require.Error(t, err)
	assert.False(t, s.PlainAuthSeen())
}

func TestPasswordNotPrinted(t *testing.T) {
	s := newTestServer(t, false, nil)
	n := newNotifier(t, cfgFor(s, SecurityStartTLS, nil))
	out := strings.Join([]string{
		fmtV(n), fmtV(*n.(*notifier)),
	}, " ")
	assert.NotContains(t, out, s.pass)
}

func fmtV(v interface{}) string {
	return fmt.Sprintf("%v %+v %#v", v, v, v)
}
