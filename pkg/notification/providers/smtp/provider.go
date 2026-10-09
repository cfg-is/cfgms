// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package smtp is the SMTP notification provider. TLS is mandatory: the
// connection is either upgraded with STARTTLS before any credential or message
// byte is sent, or wrapped in TLS from the first byte (implicit TLS). There is
// no plaintext mode and server certificate verification cannot be disabled.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/notification/interfaces"
)

const (
	// ProviderName is the registry name of this provider.
	ProviderName = "smtp"

	// SecurityStartTLS upgrades a plaintext greeting with STARTTLS (default).
	SecurityStartTLS = "starttls"
	// SecurityImplicitTLS wraps the connection in TLS from the first byte.
	SecurityImplicitTLS = "implicit_tls"

	defaultTimeout = 30 * time.Second
)

func init() {
	interfaces.RegisterNotifierProvider(&Provider{})
}

// Provider creates SMTP notifiers.
type Provider struct{}

// Name implements interfaces.NotifierProvider.
func (*Provider) Name() string { return ProviderName }

// Description implements interfaces.NotifierProvider.
func (*Provider) Description() string {
	return "SMTP email delivery with mandatory TLS (STARTTLS or implicit TLS)"
}

// secret holds a credential and refuses to print itself.
type secret string

func (secret) String() string   { return "[REDACTED]" }
func (secret) GoString() string { return "[REDACTED]" }

type notifier struct {
	host     string
	port     int
	security string
	from     *mail.Address
	username string
	password secret
	timeout  time.Duration
	tlsCfg   *tls.Config
}

var allowedKeys = map[string]bool{
	"host": true, "port": true, "security": true, "from": true,
	"username": true, "password": true, "timeout": true, "root_ca_pem": true,
}

// CreateNotifier implements interfaces.NotifierProvider.
//
// Keys: host (required), port, security ("starttls" default | "implicit_tls"),
// from (required), username, password (resolved values), timeout (duration
// string, default 30s), root_ca_pem (extra trusted roots, PEM contents).
// Any other key — including anything asking for plaintext or for skipping
// certificate verification — is rejected.
func (*Provider) CreateNotifier(config map[string]interface{}) (interfaces.Notifier, error) {
	for k := range config {
		if !allowedKeys[k] {
			return nil, fmt.Errorf("smtp: unsupported config key %q (TLS is mandatory; no plaintext or verification-bypass options exist)", k)
		}
	}
	n := &notifier{security: SecurityStartTLS, timeout: defaultTimeout}

	host, err := stringKey(config, "host")
	if err != nil || host == "" {
		return nil, errors.New("smtp: host is required")
	}
	if strings.ContainsAny(host, " \r\n/") {
		return nil, errors.New("smtp: invalid host")
	}
	n.host = host

	if v, err := stringKey(config, "security"); err != nil {
		return nil, err
	} else if v != "" {
		n.security = v
	}
	switch n.security {
	case SecurityStartTLS:
		n.port = 587
	case SecurityImplicitTLS:
		n.port = 465
	default:
		return nil, fmt.Errorf("smtp: security must be %q or %q", SecurityStartTLS, SecurityImplicitTLS)
	}

	if raw, ok := config["port"]; ok {
		p, err := intValue(raw)
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("smtp: port must be an integer in 1-65535")
		}
		n.port = p
	}

	from, err := stringKey(config, "from")
	if err != nil || from == "" {
		return nil, errors.New("smtp: from is required")
	}
	if n.from, err = parseAddress(from); err != nil {
		return nil, errors.New("smtp: from is not a valid address")
	}

	if n.username, err = stringKey(config, "username"); err != nil {
		return nil, err
	}
	pw, err := stringKey(config, "password")
	if err != nil {
		return nil, err
	}
	n.password = secret(pw)
	if n.username == "" && pw != "" {
		return nil, errors.New("smtp: password given without username")
	}
	if strings.ContainsAny(n.username, "\r\n\x00") || strings.ContainsAny(pw, "\r\n\x00") {
		return nil, errors.New("smtp: credentials contain forbidden characters")
	}

	if raw, ok := config["timeout"]; ok {
		s, isStr := raw.(string)
		if !isStr {
			return nil, errors.New("smtp: timeout must be a duration string")
		}
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return nil, errors.New("smtp: timeout must be a positive duration")
		}
		n.timeout = d
	}

	ca, err := stringKey(config, "root_ca_pem")
	if err != nil {
		return nil, err
	}
	tlsCfg, err := cert.CreatePublicClientTLSConfig(host, []byte(ca), tls.VersionTLS12)
	if err != nil {
		return nil, errors.New("smtp: root_ca_pem contains no valid certificate")
	}
	n.tlsCfg = tlsCfg
	return n, nil
}

func stringKey(config map[string]interface{}, key string) (string, error) {
	raw, ok := config[key]
	if !ok || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("smtp: %s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

func intValue(v interface{}) (int, error) {
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		if x == float64(int(x)) {
			return int(x), nil
		}
	case string:
		return strconv.Atoi(x)
	}
	return 0, errors.New("not an integer")
}

// parseAddress rejects control characters and anything net/mail cannot parse.
func parseAddress(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return nil, errors.New("forbidden characters")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(a.Address, "\r\n\x00<>") {
		return nil, errors.New("forbidden characters")
	}
	return a, nil
}

// Name implements interfaces.Notifier.
func (*notifier) Name() string { return ProviderName }

// Send implements interfaces.Notifier. Validation happens before any network
// activity. Every recipient is attempted; rejections are reported per
// recipient in the result. If no recipient is accepted, the result is returned
// without sending a message body.
func (n *notifier) Send(ctx context.Context, msg interfaces.Message) (*interfaces.DeliveryResult, error) {
	if len(msg.To) == 0 {
		return nil, errors.New("smtp: at least one recipient is required")
	}
	if strings.ContainsAny(msg.Subject, "\r\n") {
		return nil, errors.New("smtp: subject must not contain CR or LF")
	}
	addrs := make([]*mail.Address, len(msg.To))
	for i, raw := range msg.To {
		a, err := parseAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("smtp: recipient %d is not a valid address", i+1)
		}
		addrs[i] = a
	}

	deadline := time.Now().Add(n.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	c, conn, err := n.connect(dctx, deadline)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	defer stop()

	if n.username != "" {
		auth := smtp.PlainAuth("", n.username, string(n.password), n.host)
		if err := c.Auth(auth); err != nil {
			return nil, stageErr("authentication", err)
		}
	}
	if err := c.Mail(n.from.Address); err != nil {
		return nil, stageErr("sender", err)
	}

	res := &interfaces.DeliveryResult{Recipients: make([]interfaces.RecipientResult, len(addrs))}
	accepted := 0
	for i, a := range addrs {
		rr := interfaces.RecipientResult{Address: a.Address}
		if err := c.Rcpt(a.Address); err != nil {
			var te *textproto.Error
			if errors.As(err, &te) {
				rr.Reason = fmt.Sprintf("rejected by server (code %d)", te.Code)
			} else {
				return nil, stageErr("recipient", err)
			}
		} else {
			rr.Accepted = true
			accepted++
		}
		res.Recipients[i] = rr
	}
	if accepted == 0 {
		_ = c.Reset()
		_ = c.Quit()
		return res, nil
	}

	w, err := c.Data()
	if err != nil {
		return nil, stageErr("data", err)
	}
	if _, err := w.Write(n.render(addrs, msg)); err != nil {
		return nil, stageErr("data", err)
	}
	if err := w.Close(); err != nil {
		return nil, stageErr("data", err)
	}
	_ = c.Quit()
	return res, nil
}

// connect dials and returns a client that is already protected by TLS.
func (n *notifier) connect(ctx context.Context, deadline time.Time) (*smtp.Client, net.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(n.host, strconv.Itoa(n.port)))
	if err != nil {
		return nil, nil, stageErr("connect", err)
	}
	_ = raw.SetDeadline(deadline)

	conn := raw
	if n.security == SecurityImplicitTLS {
		tc := tls.Client(raw, n.tlsCfg.Clone())
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, nil, stageErr("tls", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, n.host)
	if err != nil {
		_ = conn.Close()
		return nil, nil, stageErr("greeting", err)
	}
	if n.security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = conn.Close()
			return nil, nil, errors.New("smtp: server does not offer STARTTLS; refusing to continue without TLS")
		}
		if err := c.StartTLS(n.tlsCfg.Clone()); err != nil {
			_ = conn.Close()
			return nil, nil, stageErr("tls", err)
		}
	}
	return c, conn, nil
}

func (n *notifier) render(to []*mail.Address, msg interfaces.Message) []byte {
	var b strings.Builder
	toHdr := make([]string, len(to))
	for i, a := range to {
		toHdr[i] = a.String()
	}
	b.WriteString("From: " + n.from.String() + "\r\n")
	b.WriteString("To: " + strings.Join(toHdr, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	qw := quotedprintable.NewWriter(&b)
	_, _ = qw.Write([]byte(msg.Body))
	_ = qw.Close()
	return []byte(b.String())
}

// stageErr produces an error that names only the failed stage and a coarse
// cause. Server reply text and underlying error strings are dropped because
// they can echo recipients or credentials.
func stageErr(stage string, err error) error {
	var (
		ne net.Error
		te *textproto.Error
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return fmt.Errorf("smtp: %s failed: timed out", stage)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("smtp: %s failed: canceled", stage)
	case cert.IsVerificationError(err):
		return fmt.Errorf("smtp: %s failed: server certificate verification failed", stage)
	case errors.As(err, &te):
		return fmt.Errorf("smtp: %s failed: server replied with code %d", stage, te.Code)
	default:
		return fmt.Errorf("smtp: %s failed", stage)
	}
}

// String and GoString keep the credential out of any formatted output.
func (n notifier) String() string {
	return fmt.Sprintf("smtp notifier %s:%d (%s)", n.host, n.port, n.security)
}

// GoString implements fmt.GoStringer.
func (n notifier) GoString() string { return n.String() }
