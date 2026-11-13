// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/softauthn"
	"github.com/cfgis/cfgms/pkg/softauthn/tpmkey"
)

const (
	// enrollmentLinkEnv names the environment variable that can carry the
	// enrollment link. The link is a bearer secret and is never an argv value.
	enrollmentLinkEnv = "CFGMS_ENROLLMENT_LINK"

	// enrollmentTokenHeaderName is the header the controller reads the
	// single-use enrollment token from (handlers_webauthn.go enrollmentTokenHeader).
	enrollmentTokenHeaderName = "X-Enrollment-Token"

	enrollBeginPath  = "/api/v1/web/passkey/enroll/begin"
	enrollFinishPath = "/api/v1/web/passkey/enroll/finish"

	// maxEnrollmentLinkBytes bounds the link read from a file or stdin.
	maxEnrollmentLinkBytes = 4096

	// maxEnrollResponseBytes bounds a controller response body.
	maxEnrollResponseBytes = 1 << 20

	enrollRequestTimeout = 30 * time.Second
)

// enrollmentTokenRE bounds the token parsed from the link path to URL-safe
// characters, so it is always a valid header value.
var enrollmentTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// serverErrorCodeRE bounds a controller error code before it is printed.
var serverErrorCodeRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func init() {
	authenticatorCmd.AddCommand(newAuthenticatorEnrollCmd())
}

// newAuthenticatorEnrollCmd builds `cfg authenticator enroll`. It has no flag that
// takes the link or the token as a value: a value flag would put the bearer secret
// in argv.
func newAuthenticatorEnrollCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "enroll <name>",
		Short: "Enroll a software authenticator as an account's first passkey",
		Long: `Completes first-passkey enrollment for the account an enrollment link was issued
for (cfg account create), using the named software authenticator. The authenticator
must already exist (cfg authenticator create) and be bound to the controller that
issued the link. On success the stored record shows registered.

The enrollment link is a single-use bearer secret, so it is never accepted as a
command-line value. Provide it by exactly one of:
  --link-file <path>   read the link from a file
  --link-stdin         read the link from standard input
  CFGMS_ENROLLMENT_LINK  environment variable (used when neither flag is given)

The link's scheme and host must match the authenticator's origin; otherwise the
command refuses before contacting any server. The token is never printed or stored.
The controller policy may refuse software authenticators (for example HTTP 403); the
record then stays unregistered and the server's code is shown.

Examples:
  cfg authenticator enroll agent-1 --link-file ./enroll-link.txt
  printf '%s' "$LINK" | cfg authenticator enroll agent-1 --link-stdin`,
		Args: cobra.ExactArgs(1),
		RunE: runAuthenticatorEnroll,
	}
	c.Flags().String("link-file", "", "file containing the enrollment link")
	c.Flags().Bool("link-stdin", false, "read the enrollment link from standard input")
	return c
}

// readEnrollmentLink returns the link from the one source the operator chose.
func readEnrollmentLink(cmd *cobra.Command) (string, error) {
	file, _ := cmd.Flags().GetString("link-file")
	fromStdin, _ := cmd.Flags().GetBool("link-stdin")

	var raw []byte
	var err error
	switch {
	case file != "" && fromStdin:
		return "", errors.New("use only one of --link-file and --link-stdin")
	case file != "":
		raw, err = readBoundedFile("--link-file", file, maxEnrollmentLinkBytes)
	case fromStdin:
		raw, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxEnrollmentLinkBytes+1))
		if err != nil {
			err = errors.New("--link-stdin: failed to read standard input")
		}
	default:
		raw = []byte(os.Getenv(enrollmentLinkEnv))
		if len(raw) > maxEnrollmentLinkBytes {
			err = fmt.Errorf("%s is longer than %d bytes", enrollmentLinkEnv, maxEnrollmentLinkBytes)
		}
	}
	if err != nil {
		return "", err
	}
	if len(raw) > maxEnrollmentLinkBytes {
		return "", fmt.Errorf("enrollment link is longer than %d bytes", maxEnrollmentLinkBytes)
	}
	link := strings.TrimSpace(string(raw))
	if link == "" {
		return "", fmt.Errorf("no enrollment link: pass --link-file <path> or --link-stdin, or set %s "+
			"(the link is a secret and is never accepted as a command-line value)", enrollmentLinkEnv)
	}
	return link, nil
}

// readBoundedFile reads a regular file of at most max bytes. Errors name the flag
// and never include file content.
func readBoundedFile(flag, path string, max int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s %s is not a regular file of at most %d bytes", flag, path, max)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path to their own link file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	return data, nil
}

// normalizeOrigin returns scheme://host[:port] for u, lower-cased, without a
// default https port.
func normalizeOrigin(u *url.URL) string {
	host := strings.ToLower(u.Host)
	host = strings.TrimSuffix(host, ":443")
	return strings.ToLower(u.Scheme) + "://" + host
}

// parseEnrollmentLink validates link (<controller_url>/enroll/<token>) and returns
// its origin and token. Errors never include the link or token.
func parseEnrollmentLink(link string) (origin, token string, err error) {
	u, perr := url.Parse(link)
	if perr != nil || u.Host == "" {
		return "", "", errors.New("the enrollment link is not a valid https URL")
	}
	if u.Scheme != "https" {
		return "", "", errors.New("the enrollment link must be an https URL")
	}
	if u.User != nil {
		return "", "", errors.New("the enrollment link must not contain credentials")
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 || segs[len(segs)-2] != "enroll" {
		return "", "", errors.New("the enrollment link must end in /enroll/<token>")
	}
	token = segs[len(segs)-1]
	if !enrollmentTokenRE.MatchString(token) {
		return "", "", errors.New("the enrollment link carries a malformed token")
	}
	return normalizeOrigin(u), token, nil
}

func runAuthenticatorEnroll(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateAuthenticatorName(name); err != nil {
		return err
	}
	link, err := readEnrollmentLink(cmd)
	if err != nil {
		return err
	}
	linkOrigin, token, err := parseEnrollmentLink(link)
	if err != nil {
		return err
	}

	ctx := context.Background()
	store, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
	}
	rec, err := loadAuthenticatorRecord(ctx, store, name)
	if err != nil {
		return err
	}
	recOrigin, err := url.Parse(rec.Origin)
	if err != nil || normalizeOrigin(recOrigin) != linkOrigin {
		return fmt.Errorf("the enrollment link is for a different controller than authenticator %q is bound to (%s); "+
			"nothing was sent", name, rec.Origin)
	}

	client, err := newEnrollClient(rec)
	if err != nil {
		return err
	}
	if err := registerAuthenticator(ctx, store, rec,
		func(ctx context.Context, body []byte) (json.RawMessage, error) {
			return client.begin(ctx, token, body)
		},
		func(ctx context.Context, body []byte) error {
			return client.finish(ctx, token, rec.Label, body)
		}); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Authenticator %q enrolled and registered with %s.\n", name, rec.Origin)
	return nil
}

// tpmAttestationRequiredCode is the controller's code for refusing a begin (or a
// finish) because the account requires a TPM-held key and the registration did
// not prove one.
const tpmAttestationRequiredCode = "TPM_ATTESTATION_REQUIRED"

// registerAuthenticator runs one registration ceremony for rec and, only when the
// controller accepts it, marks the record registered with the account's user
// handle. begin sends the begin-registration request (body is nil, or the JSON
// TPM proof for a "tpm" record) and returns the controller's options; finish
// sends the authenticator's response. Both `cfg authenticator enroll` and
// `cfg webauthn register --authenticator` call it.
func registerAuthenticator(ctx context.Context, store *CredentialStore, rec *authenticatorRecord,
	begin func(context.Context, []byte) (json.RawMessage, error),
	finish func(context.Context, []byte) error) error {

	auth, options, done, err := beginRegistration(ctx, rec, begin)
	if err != nil {
		return explainTPMRefusal(rec, err)
	}
	defer done()

	var creation protocol.CredentialCreation
	if err := json.Unmarshal(options, &creation); err != nil {
		return errors.New("the controller sent malformed registration options")
	}
	userHandle, err := registrationUserHandle(creation)
	if err != nil {
		return err
	}
	body, err := auth.Register(options)
	if err != nil {
		return fmt.Errorf("authenticator %q refused the registration options: %w", rec.Name, err)
	}
	if err := finish(ctx, body); err != nil {
		return explainTPMRefusal(rec, err)
	}

	rec.UserHandle = userHandle
	rec.Registered = true
	if err := saveAuthenticatorRecord(ctx, store, rec); err != nil {
		return fmt.Errorf("the controller accepted the registration but the local record was not updated: %w", err)
	}
	return nil
}

// beginRegistration builds the authenticator for one ceremony and fetches the
// controller's options. done releases anything the authenticator needs until
// Register returns (the TPM, for a "tpm" record).
func beginRegistration(ctx context.Context, rec *authenticatorRecord,
	begin func(context.Context, []byte) (json.RawMessage, error)) (auth *softauthn.Authenticator, options json.RawMessage, done func(), err error) {

	if rec.Protection == authenticatorProtectionTPM {
		return beginTPMRegistration(ctx, rec, begin)
	}
	auth, err = rec.authenticator()
	if err != nil {
		return nil, nil, nil, err
	}
	options, err = begin(ctx, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return auth, options, func() {}, nil
}

// tpmBeginRequest is the begin body that offers the controller a TPM proof: the
// EK certificate chain and the attestation key's public area. Byte fields are
// base64 in JSON.
type tpmBeginRequest struct {
	TPM tpmBeginProof `json:"tpm"`
}

type tpmBeginProof struct {
	EKCertChain [][]byte `json:"ek_cert_chain"`
	AKPublic    []byte   `json:"ak_public"`
}

// tpmChallenge is the cfgmsTpm member of the controller's options: a credential
// challenge only this TPM's endorsement key can open, for this attestation key.
type tpmChallenge struct {
	CredentialBlob  []byte `json:"credential_blob"`
	EncryptedSecret []byte `json:"encrypted_secret"`
}

// beginTPMRegistration runs the ceremony's TPM half for a "tpm" record: it
// reads the EK certificate and derives the attestation key, calls begin with
// them, and, when the controller answers with a cfgmsTpm challenge, activates
// it and builds an authenticator whose registration is a TPM attestation. A
// controller that sends no challenge gets the usual attestation "none".
func beginTPMRegistration(ctx context.Context, rec *authenticatorRecord,
	begin func(context.Context, []byte) (json.RawMessage, error)) (*softauthn.Authenticator, json.RawMessage, func(), error) {

	blobs, err := rec.tpmBlobs()
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := rec.signer()
	if err != nil {
		return nil, nil, nil, err
	}
	t, err := openAuthenticatorTPM()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authenticator %q needs its TPM and it cannot be opened: %w", rec.Name, err)
	}
	done := func() { _ = t.Close() }
	fail := func(err error) (*softauthn.Authenticator, json.RawMessage, func(), error) {
		done()
		return nil, nil, nil, err
	}

	prep, err := tpmkey.Prepare(t)
	if err != nil {
		return fail(fmt.Errorf("authenticator %q cannot offer a TPM proof: %w", rec.Name, err))
	}
	reqBody, err := json.Marshal(tpmBeginRequest{TPM: tpmBeginProof{EKCertChain: prep.EKCertChain, AKPublic: prep.AKPublic}})
	if err != nil {
		return fail(errors.New("failed to encode the TPM proof"))
	}
	options, err := begin(ctx, reqBody)
	if err != nil {
		return fail(err)
	}

	attester, err := tpmAttesterFor(t, prep, blobs, options)
	if err != nil {
		return fail(err)
	}
	auth, err := rec.authenticatorWith(signer, attester)
	if err != nil {
		return fail(err)
	}
	return auth, options, done, nil
}

// tpmAttesterFor activates the controller's cfgmsTpm challenge in the options and
// returns the Attester that answers it, or nil when the controller sent none.
func tpmAttesterFor(t transport.TPM, prep *tpmkey.Prepared, blobs tpmkey.Blobs, options json.RawMessage) (softauthn.Attester, error) {
	challenge, err := parseTPMChallenge(options)
	if err != nil || challenge == nil {
		return nil, err
	}
	secret, err := tpmkey.Activate(t, prep, challenge.CredentialBlob, challenge.EncryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("the TPM could not activate the controller's challenge: %w", err)
	}
	return tpmkey.NewAttester(t, blobs, secret), nil
}

// parseTPMChallenge returns the cfgmsTpm member of the begin options, or nil when
// the controller sent none. A present but malformed member is an error: the
// registration must not silently fall back to attestation "none".
func parseTPMChallenge(options json.RawMessage) (*tpmChallenge, error) {
	var env struct {
		CfgmsTPM *tpmChallenge `json:"cfgmsTpm"`
	}
	if err := json.Unmarshal(options, &env); err != nil {
		return nil, errors.New("the controller sent malformed registration options")
	}
	if env.CfgmsTPM == nil {
		return nil, nil
	}
	if len(env.CfgmsTPM.CredentialBlob) == 0 || len(env.CfgmsTPM.EncryptedSecret) == 0 {
		return nil, errors.New("the controller's TPM challenge is incomplete")
	}
	return env.CfgmsTPM, nil
}

// explainTPMRefusal turns a TPM_ATTESTATION_REQUIRED refusal into the remedy.
// Other errors pass through unchanged.
func explainTPMRefusal(rec *authenticatorRecord, err error) error {
	if err == nil || !strings.Contains(err.Error(), tpmAttestationRequiredCode) {
		return err
	}
	if rec.Protection == authenticatorProtectionTPM {
		return fmt.Errorf("the controller did not accept the TPM attestation of authenticator %q (%s): %w",
			rec.Name, tpmAttestationRequiredCode, err)
	}
	return fmt.Errorf("this account requires a TPM-held key and authenticator %q is not one: "+
		"create a new authenticator on a host with a TPM using 'cfg authenticator create <name> --url <controller URL> "+
		"--key-provider tpm' and register that instead (%s): %w", rec.Name, tpmAttestationRequiredCode, err)
}

// registrationUserHandle returns the account user handle from the begin options.
func registrationUserHandle(creation protocol.CredentialCreation) ([]byte, error) {
	enc, ok := creation.Response.User.ID.(string)
	if !ok {
		return nil, errors.New("the controller's registration options carry no user handle")
	}
	handle, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(handle) == 0 {
		return nil, errors.New("the controller's registration options carry an invalid user handle")
	}
	return handle, nil
}

// enrollClient calls the controller's public enrollment routes with the
// enrollment token header. The controller URL and trust anchor come from the
// authenticator record; TLS verification is always on.
type enrollClient struct {
	baseURL string
	http    *http.Client
}

func newEnrollClient(rec *authenticatorRecord) (*enrollClient, error) {
	base, err := parseAuthenticatorHTTPSURL("url", rec.ControllerURL)
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: stored controller URL is not usable: %w", rec.Name, err)
	}
	var ca []byte
	if rec.CACertPEM != "" {
		ca = []byte(rec.CACertPEM)
	}
	tlsCfg, err := cert.CreateClientTLSConfig(nil, nil, ca, "", tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("authenticator %q: stored CA certificate is not usable", rec.Name)
	}
	return &enrollClient{
		baseURL: strings.TrimRight(base.String(), "/"),
		http: &http.Client{
			Timeout:   enrollRequestTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// Never follow a redirect: the token header would travel with it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// begin starts the registration. body is the optional JSON request body (the TPM
// proof of a "tpm" authenticator); nil sends no body.
func (c *enrollClient) begin(ctx context.Context, token string, body []byte) (json.RawMessage, error) {
	resp, err := c.do(ctx, enrollBeginPath, token, body)
	if err != nil {
		return nil, err
	}
	if resp.status != http.StatusOK {
		return nil, enrollRefusal("begin", resp)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp.body, &envelope); err != nil || len(envelope.Data) == 0 {
		return nil, errors.New("the controller's begin response was not understood")
	}
	return envelope.Data, nil
}

func (c *enrollClient) finish(ctx context.Context, token, label string, body []byte) error {
	path := enrollFinishPath
	if label != "" {
		path += "?label=" + url.QueryEscape(label)
	}
	resp, err := c.do(ctx, path, token, body)
	if err != nil {
		return err
	}
	if resp.status != http.StatusCreated {
		return enrollRefusal("finish", resp)
	}
	return nil
}

type enrollResponse struct {
	status int
	body   []byte
}

func (c *enrollClient) do(ctx context.Context, path, token string, body []byte) (*enrollResponse, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	// #nosec G704 -- the controller URL is the operator's own authenticator record.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, reader)
	if err != nil {
		return nil, errors.New("failed to create the enrollment request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(enrollmentTokenHeaderName, token)

	resp, err := c.http.Do(req) // #nosec G704 -- see above
	if err != nil {
		// A transport error names the request URL, which carries no token (the
		// token is a header), but keep the message to the failing step.
		return nil, fmt.Errorf("could not reach the controller at %s: %w", c.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponseBytes))
	if err != nil {
		return nil, errors.New("failed to read the controller's response")
	}
	return &enrollResponse{status: resp.StatusCode, body: data}, nil
}

// enrollRefusal describes a non-success controller response from its status and
// error code. The record is left untouched by the caller.
func enrollRefusal(step string, resp *enrollResponse) error {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	code := ""
	msg := ""
	if err := json.Unmarshal(resp.body, &env); err == nil {
		if serverErrorCodeRE.MatchString(env.Error.Code) {
			code = env.Error.Code
		}
		msg = env.Error.Message
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	out := fmt.Sprintf("the controller refused enrollment at %s (HTTP %d", step, resp.status)
	if code != "" {
		out += " " + code
	}
	out += ")"
	if msg != "" {
		// Quoted so control characters in a server message cannot reach the terminal.
		out += ": " + strconv.Quote(msg)
	}
	return errors.New(out + "; the authenticator stays unregistered")
}
