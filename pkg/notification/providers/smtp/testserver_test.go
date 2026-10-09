// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package smtp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
)

// testServer is an in-process SMTP server that records the order of events so
// tests can prove TLS was established before AUTH and DATA.
type testServer struct {
	t        *testing.T
	ln       net.Listener
	implicit bool
	tlsCfg   *tls.Config

	user, pass string
	rejectRcpt map[string]bool
	stall      bool // accept the connection then never speak

	CAPEM []byte
	Host  string
	Port  int

	mu        sync.Mutex
	conns     int
	events    []string
	plainAuth bool // AUTH or DATA seen outside TLS
	raw       strings.Builder
	messages  []string
	rcptsSeen []string
}

func newTestServer(t *testing.T, implicit bool, mutate func(*testServer)) *testServer {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "notification-test", ValidityDays: 1})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 1,
	})
	require.NoError(t, err)
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	pair, err := cert.LoadTLSCertificate(sc.CertificatePEM, sc.PrivateKeyPEM)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &testServer{
		t: t, ln: ln, implicit: implicit, CAPEM: caPEM, Host: "localhost",
		Port:   ln.Addr().(*net.TCPAddr).Port,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		user:   "mailer", pass: "s3cret-pw-value", rejectRcpt: map[string]bool{},
	}
	if mutate != nil {
		mutate(s)
	}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *testServer) record(ev string) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *testServer) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *testServer) Events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

func (s *testServer) PlainAuthSeen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plainAuth
}

func (s *testServer) Raw() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raw.String()
}

func (s *testServer) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.messages...)
}

func (s *testServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *testServer) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if s.stall {
		time.Sleep(5 * time.Second)
		return
	}
	inTLS := false
	if s.implicit {
		tc := tls.Server(c, s.tlsCfg)
		if err := tc.Handshake(); err != nil {
			s.record("tls-handshake-failed")
			return
		}
		s.record("tls")
		c, inTLS = tc, true
	}
	r := bufio.NewReader(c)
	w := func(line string) { _, _ = c.Write([]byte(line + "\r\n")) }
	w("220 localhost ready")
	var rcpts []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		s.mu.Lock()
		if verb == "AUTH" {
			s.raw.WriteString("AUTH-LINE\n")
		}
		s.mu.Unlock()
		switch verb {
		case "EHLO", "HELO":
			w("250-localhost")
			if !inTLS {
				w("250-STARTTLS")
			}
			w("250 AUTH PLAIN")
		case "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(c, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				s.record("tls-handshake-failed")
				return
			}
			s.record("tls")
			c, inTLS = tc, true
			r = bufio.NewReader(c)
		case "AUTH":
			s.record("auth")
			s.mu.Lock()
			s.raw.WriteString(line + "\n")
			if !inTLS {
				s.plainAuth = true
			}
			s.mu.Unlock()
			parts := strings.Fields(line)
			var blob string
			if len(parts) == 3 {
				blob = parts[2]
			}
			dec, _ := base64.StdEncoding.DecodeString(blob)
			f := strings.Split(string(dec), "\x00")
			if len(f) == 3 && f[1] == s.user && f[2] == s.pass {
				w("235 ok")
			} else {
				w("535 authentication failed")
			}
		case "MAIL":
			w("250 ok")
		case "RCPT":
			addr := strings.Trim(line[strings.Index(line, ":")+1:], "<> ")
			s.mu.Lock()
			s.rcptsSeen = append(s.rcptsSeen, addr)
			s.mu.Unlock()
			if s.rejectRcpt[addr] {
				w("550 no such user " + addr)
			} else {
				rcpts = append(rcpts, addr)
				w("250 ok")
			}
		case "DATA":
			s.record("data")
			if !inTLS {
				s.mu.Lock()
				s.plainAuth = true
				s.mu.Unlock()
			}
			w("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(l)
			}
			s.mu.Lock()
			s.messages = append(s.messages, sb.String())
			s.mu.Unlock()
			w("250 queued " + strconv.Itoa(len(rcpts)))
		case "RSET":
			rcpts = nil
			w("250 ok")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 unsupported")
		}
	}
}
