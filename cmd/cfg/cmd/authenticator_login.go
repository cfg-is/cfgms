// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	// authenticatorEnvVar selects the authenticator when --authenticator is not given.
	authenticatorEnvVar = "CFGMS_AUTHENTICATOR"

	// Cookie names the controller's passkey login and logout handlers use
	// (features/controller/api/handlers_web_session.go).
	webSessionCookieName = "__Host-cfgms_session"
	webCSRFCookieName    = "__Host-cfgms_csrf"
	webPreCSRFCookieName = "__Host-cfgms_csrf_pre"

	webCSRFPath        = "/api/v1/web/csrf"
	webLoginBeginPath  = "/api/v1/web/passkey/login/begin"
	webLoginFinishPath = "/api/v1/web/passkey/login/finish"
	webLogoutPath      = "/api/v1/web/logout"

	// maxWebLoginResponseBytes bounds every login-ceremony response body read.
	maxWebLoginResponseBytes = 1 << 20
	// maxWebLoginErrorBytes bounds the server text read from a failed ceremony step.
	maxWebLoginErrorBytes = 4096

	webLogoutTimeout = 10 * time.Second
)

// authenticatorSelection is the value of the persistent --authenticator flag.
var authenticatorSelection string

// webSessionWarnWriter receives the warning printed when ending a web session
// fails. Overridable in tests; defaults to stderr.
var webSessionWarnWriter io.Writer = os.Stderr

var (
	webSessionMu      sync.Mutex
	webSessionClosers []func()
)

func init() {
	rootCmd.PersistentFlags().StringVar(&authenticatorSelection, "authenticator", "",
		"Log in with this software authenticator and use the session for this command only; "+
			"cannot be combined with --bundle or --no-bundle (env: "+authenticatorEnvVar+")")
	// Finalizers run after every executed command, whether RunE succeeded or failed,
	// so the server-side session never outlives the command that logged in.
	cobra.OnFinalize(closeWebSessions)
}

// selectedAuthenticator returns the authenticator named by --authenticator, else by
// CFGMS_AUTHENTICATOR, else "".
func selectedAuthenticator() string {
	if authenticatorSelection != "" {
		return authenticatorSelection
	}
	return os.Getenv(authenticatorEnvVar)
}

// registerWebSessionCloser queues closeFn to run when the current command ends.
func registerWebSessionCloser(closeFn func()) {
	webSessionMu.Lock()
	defer webSessionMu.Unlock()
	webSessionClosers = append(webSessionClosers, closeFn)
}

// closeWebSessions ends every web session this process logged in, once.
func closeWebSessions() {
	webSessionMu.Lock()
	closers := webSessionClosers
	webSessionClosers = nil
	webSessionMu.Unlock()
	for _, closeFn := range closers {
		closeFn()
	}
}

// loginWithAuthenticator runs the passkey login ceremony with the named software
// authenticator against the controller its record is bound to, and returns a client
// that holds the resulting web session in memory only. The returned close function
// ends the session on the controller (POST /api/v1/web/logout); it is idempotent and
// a failed logout only prints a warning that names no cookie or token value.
//
// Every refusal here happens before any network call: a conflicting credential flag,
// a TLS-skip request, a missing or unregistered record, a non-https controller URL.
func loginWithAuthenticator(ctx context.Context, name, apiURL string, tlsInsecure bool, serverName string) (*APIClient, func(), error) {
	if err := refuseConflictingCredential(tlsInsecure); err != nil {
		return nil, nil, err
	}
	rec, err := loadRegisteredAuthenticator(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	controllerURL, err := authenticatorControllerURL(rec, apiURL)
	if err != nil {
		return nil, nil, err
	}
	auth, err := rec.authenticator()
	if err != nil {
		return nil, nil, err
	}
	client, err := newWebSessionClient(rec, controllerURL, serverName)
	if err != nil {
		return nil, nil, err
	}
	if err := client.webPasskeyLogin(ctx, auth); err != nil {
		return nil, nil, fmt.Errorf("authenticator %q: %w", name, err)
	}
	return client, webSessionCloser(client), nil
}

// refuseConflictingCredential refuses the flag combinations that would make the
// authenticator a second credential or its connection unverified.
func refuseConflictingCredential(tlsInsecure bool) error {
	if bundlePath != "" || noBundle {
		return errors.New("--authenticator cannot be combined with --bundle or --no-bundle: provide exactly one credential")
	}
	if tlsInsecure {
		return errors.New("--tls-insecure cannot be used with --authenticator: a web session is only ever sent to a TLS-verified controller")
	}
	return nil
}

// newWebSessionClient builds the in-memory web-session client for rec's controller.
func newWebSessionClient(rec *authenticatorRecord, controllerURL, serverName string) (*APIClient, error) {
	var caCertPEM []byte
	if rec.CACertPEM != "" {
		caCertPEM = []byte(rec.CACertPEM)
	}
	return NewAPIClient(&APIClientConfig{
		BaseURL:    controllerURL,
		CACertPEM:  caCertPEM,
		ServerName: serverName,
		WebSession: true,
	})
}

// webSessionCloser returns the idempotent function that ends client's session.
func webSessionCloser(client *APIClient) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := client.webLogout(); err != nil {
				_, _ = fmt.Fprintf(webSessionWarnWriter,
					"Warning: could not end the web session on the controller (%s); it ends on its own when it expires\n",
					logging.SanitizeLogValue(err.Error()))
			}
		})
	}
}

// loadRegisteredAuthenticator loads the record for name and requires it to be
// registered with its controller.
func loadRegisteredAuthenticator(ctx context.Context, name string) (*authenticatorRecord, error) {
	if err := validateAuthenticatorName(name); err != nil {
		return nil, err
	}
	store, err := newCredentialStore()
	if err != nil {
		return nil, fmt.Errorf("failed to open credential store: %w", err)
	}
	exists, err := authenticatorExists(ctx, store, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, notFoundAuthenticator(name)
	}
	rec, err := loadAuthenticatorRecord(ctx, store, name)
	if err != nil {
		return nil, err
	}
	if !rec.Registered {
		return nil, fmt.Errorf("authenticator %q is not registered with its controller: run 'cfg authenticator enroll %s' first", name, name)
	}
	return rec, nil
}

// authenticatorControllerURL returns the controller URL the record is bound to,
// refusing a record whose URL is not https and an explicit --url / CFGMS_API_URL
// that names a different controller: the authenticator is bound to one controller.
func authenticatorControllerURL(rec *authenticatorRecord, apiURL string) (string, error) {
	u, err := url.Parse(rec.ControllerURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("authenticator %q: stored controller URL is not a valid https URL", rec.Name)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("authenticator %q: stored controller URL must be https (got scheme %q): a web session is only ever sent to a TLS-verified controller", rec.Name, u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("authenticator %q: stored controller URL must not contain credentials", rec.Name)
	}
	bound := strings.TrimRight(rec.ControllerURL, "/")
	if apiURL != "" && strings.TrimRight(apiURL, "/") != bound {
		return "", fmt.Errorf("authenticator %q is bound to %s: --url / CFGMS_API_URL must be omitted or equal to it", rec.Name, bound)
	}
	return bound, nil
}

// webPasskeyLogin runs the controller's usernameless passkey login ceremony: fetch
// the pre-session CSRF cookie, begin (double-submit CSRF), sign the challenge with
// auth, finish. On success the client holds the session and CSRF cookies in its
// in-memory jar and sends the session CSRF token on unsafe requests.
func (c *APIClient) webPasskeyLogin(ctx context.Context, auth *softauthn.Authenticator) (err error) {
	defer func() {
		if err != nil {
			c.csrfToken = ""
		}
	}()

	if err = c.webLoginPreSession(ctx); err != nil {
		return err
	}
	// softauthn refuses options whose rpId is not the record's before it signs.
	assertion, err := c.webLoginSignChallenge(ctx, auth)
	if err != nil {
		return err
	}
	return c.webLoginFinish(ctx, assertion)
}

// webLoginPreSession fetches the pre-session CSRF cookie and arms the client to echo
// it as X-CSRF-Token on the unsafe begin request, matching the cookie the jar sends
// (double submit).
func (c *APIClient) webLoginPreSession(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, webCSRFPath, nil)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := webLoginStepResult("csrf", resp); err != nil {
		return err
	}
	pre := c.cookieValue(webPreCSRFCookieName)
	if pre == "" {
		return errors.New("login failed: controller did not issue a pre-session CSRF token")
	}
	c.csrfToken = pre
	return nil
}

// webLoginSignChallenge begins the discoverable login and signs the controller's
// challenge with auth.
func (c *APIClient) webLoginSignChallenge(ctx context.Context, auth *softauthn.Authenticator) ([]byte, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, webLoginBeginPath, strings.NewReader("{}"))
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}
	options, err := webLoginBeginOptions(resp)
	if err != nil {
		return nil, err
	}
	assertion, err := auth.Assert(options)
	if err != nil {
		return nil, fmt.Errorf("login refused: %w", err)
	}
	return assertion, nil
}

// webLoginFinish submits the signed assertion and takes the session's CSRF token
// from the cookies the controller set in the jar.
func (c *APIClient) webLoginFinish(ctx context.Context, assertion []byte) error {
	resp, err := c.doRequest(ctx, http.MethodPost, webLoginFinishPath, bytes.NewReader(assertion))
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := webLoginStepResult("finish", resp); err != nil {
		return err
	}
	session := c.cookieValue(webSessionCookieName)
	csrf := c.cookieValue(webCSRFCookieName)
	if session == "" || csrf == "" {
		return errors.New("login failed: controller did not issue a web session")
	}
	c.csrfToken = csrf
	return nil
}

// webLoginStepResult drains resp and returns nil for a 200 response, else an error
// carrying the status and sanitized server text.
func webLoginStepResult(step string, resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebLoginResponseBytes))
		return nil
	}
	return webLoginStepError(step, resp)
}

// webLoginBeginOptions returns the assertion options from the begin response's
// API envelope.
func webLoginBeginOptions(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, webLoginStepError("begin", resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWebLoginResponseBytes))
	if err != nil {
		return nil, errors.New("login failed: could not read the controller's login challenge")
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return nil, errors.New("login failed: the controller's login challenge is malformed")
	}
	return env.Data, nil
}

// webLoginStepError describes a non-200 ceremony response. The server text is
// sanitized and bounded; no cookie or token value is ever included.
func webLoginStepError(step string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebLoginErrorBytes))
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	text := ""
	if json.Unmarshal(raw, &body) == nil {
		text = body.Error
		if text == "" {
			text = body.Message
		}
	}
	if text == "" {
		return fmt.Errorf("login failed at %s (status %d)", step, resp.StatusCode)
	}
	return fmt.Errorf("login failed at %s (status %d): %s", step, resp.StatusCode, logging.SanitizeLogValue(text))
}

// webLogout ends the session on the controller with the session CSRF token and
// drops everything held in memory. It never returns or prints a cookie or token.
func (c *APIClient) webLogout() error {
	ctx, cancel := context.WithTimeout(context.Background(), webLogoutTimeout)
	defer cancel()
	defer c.forgetWebSession()

	resp, err := c.doRequest(ctx, http.MethodPost, webLogoutPath, nil)
	if err != nil {
		// The transport error can name the URL but never a cookie or header value.
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebLoginResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("logout returned status %d", resp.StatusCode)
	}
	return nil
}

// forgetWebSession drops the CSRF token and cookie jar so the client holds no
// session after logout.
func (c *APIClient) forgetWebSession() {
	c.csrfToken = ""
	c.httpClient.Jar = nil
}

// cookieValue returns the value of the named cookie the in-memory jar holds for the
// controller, or "".
func (c *APIClient) cookieValue(name string) string {
	if c.httpClient.Jar == nil {
		return ""
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return ""
	}
	for _, ck := range c.httpClient.Jar.Cookies(base) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}
