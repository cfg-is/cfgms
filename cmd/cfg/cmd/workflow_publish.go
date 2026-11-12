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
	"strings"
	"time"

	"github.com/spf13/cobra"

	wfpkg "github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

// maxWorkflowPublishResponseBytes bounds every publish-ceremony response body read.
const maxWorkflowPublishResponseBytes = 1 << 20

// workflowPublishJSON is the --json flag of cfg workflow publish.
var workflowPublishJSON bool

// workflowPublishCmd drives the publish ceremony for one stored workflow version.
var workflowPublishCmd = &cobra.Command{
	Use:   "publish <id> <version>",
	Short: "Publish one stored workflow version with a software authenticator",
	Long: `Publish one stored workflow version by driving the controller's publish ceremony
(POST /api/v1/workflows/{id}/versions/{version}/publish/begin and /finish) with a
software authenticator, then print the resulting publication: name, version,
content hash and signer.

The controller only accepts a publish ceremony over a passkey-authenticated web
session, so --authenticator (or CFGMS_AUTHENTICATOR) is required: the command logs
in with that authenticator, signs the challenge exactly as the controller issued it
and ends the session when it finishes. The authenticator's account must hold
workflow:publish for the workflow's tenant.

The printed content hash is the canonical hash of the version the controller will
publish. Compare it with the hash you expect; the signature covers that hash, the
tenant, the workflow name and the version, so a version edited between begin and
finish is refused by the controller and nothing is published.

Examples:
  cfg workflow publish my-workflow 1.2.0 --authenticator agent-1
  cfg workflow publish my-workflow 1.2.0 --authenticator agent-1 --json`,
	Args: cobra.ExactArgs(2),
	RunE: runWorkflowPublish,
}

func init() {
	workflowPublishCmd.Flags().StringVar(&workflowURL, "url", "", "Controller API URL; must be omitted or equal the authenticator's controller (env: CFGMS_API_URL)")
	workflowPublishCmd.Flags().StringVar(&workflowServerName, "server-name", "", "Override TLS server name for certificate verification")
	workflowPublishCmd.Flags().BoolVar(&workflowPublishJSON, "json", false, "Print the publication as JSON")
	workflowCmd.AddCommand(workflowPublishCmd)
}

// workflowPublishBeginResponse is the data of the publish/begin API envelope.
type workflowPublishBeginResponse struct {
	// Assertion is the WebAuthn request options exactly as the controller issued them.
	Assertion   json.RawMessage `json:"assertion"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	ContentHash string          `json:"content_hash"`
}

// workflowPublishResult is the publication the controller returns from publish/finish.
type workflowPublishResult struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	ContentHash     string    `json:"content_hash"`
	SignerAccountID string    `json:"signer_account_id"`
	SignedAt        time.Time `json:"signed_at"`
}

// errWorkflowPublishNeedsAuthenticator is returned, before any network call, when no
// authenticator is selected.
var errWorkflowPublishNeedsAuthenticator = errors.New(
	"cfg workflow publish requires --authenticator <name> (or " + authenticatorEnvVar + "): " +
		"the controller accepts a publish ceremony only over a passkey-authenticated web session, " +
		"which an mTLS bundle or bearer session token cannot provide")

func runWorkflowPublish(cmd *cobra.Command, args []string) error {
	name := selectedAuthenticator()
	if name == "" {
		return errWorkflowPublishNeedsAuthenticator
	}
	workflowName, version, err := parseWorkflowPublishArgs(args[0], args[1])
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Load the authenticator before logging in: a missing or unregistered record
	// is refused without any network call.
	rec, err := loadRegisteredAuthenticator(ctx, name)
	if err != nil {
		return err
	}
	auth, err := rec.authenticator()
	if err != nil {
		return err
	}
	client, err := getWorkflowClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	result, err := publishWorkflowVersion(ctx, client, auth, workflowName, version)
	if err != nil {
		return err
	}
	return writeWorkflowPublishResult(cmd.OutOrStdout(), result, workflowPublishJSON)
}

// parseWorkflowPublishArgs validates the workflow name and semantic version. Both are
// bounded here and escaped again when the request path is built.
func parseWorkflowPublishArgs(id, version string) (string, string, error) {
	if !workflowNameRE.MatchString(id) {
		return "", "", fmt.Errorf("workflow name %q invalid: must match %s", id, workflowNameRE.String())
	}
	sv, err := wfpkg.ParseSemanticVersion(version)
	if err != nil {
		return "", "", fmt.Errorf("workflow version %q invalid: must be MAJOR.MINOR.PATCH", version)
	}
	return id, sv.String(), nil
}

// workflowPublishPath returns the publish ceremony path for step ("begin" or "finish").
func workflowPublishPath(name, version, step string) string {
	return "/api/v1/workflows/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version) + "/publish/" + step
}

// publishWorkflowVersion runs the begin and finish steps over client's web session.
// The assertion is made over the begin options exactly as issued.
func publishWorkflowVersion(ctx context.Context, client *APIClient, auth *softauthn.Authenticator, name, version string) (*workflowPublishResult, error) {
	begin, err := workflowPublishBegin(ctx, client, name, version)
	if err != nil {
		return nil, err
	}
	// The controller must have answered for the version named, before anything is signed.
	if begin.Name != name || begin.Version != version {
		return nil, fmt.Errorf("publish refused: the controller began a ceremony for %s %s, not %s %s",
			logging.SanitizeLogValue(begin.Name), logging.SanitizeLogValue(begin.Version), name, version)
	}
	if begin.ContentHash == "" {
		return nil, errors.New("publish refused: the controller did not report the content hash of the version")
	}
	assertion, err := auth.Assert(begin.Assertion)
	if err != nil {
		return nil, fmt.Errorf("publish refused by the authenticator: %w", err)
	}
	result, err := workflowPublishFinish(ctx, client, name, version, assertion)
	if err != nil {
		return nil, err
	}
	// The signature the controller verified covered begin's hash; a different hash
	// here means the controller published something other than what it announced.
	if result.ContentHash != begin.ContentHash {
		return nil, fmt.Errorf("publish result is inconsistent: begin reported content hash %s but finish reported %s",
			logging.SanitizeLogValue(begin.ContentHash), logging.SanitizeLogValue(result.ContentHash))
	}
	return result, nil
}

// workflowPublishBegin calls publish/begin and decodes its data.
func workflowPublishBegin(ctx context.Context, client *APIClient, name, version string) (*workflowPublishBeginResponse, error) {
	resp, err := client.doRequest(ctx, http.MethodPost, workflowPublishPath(name, version, "begin"), strings.NewReader("{}"))
	if err != nil {
		return nil, fmt.Errorf("publish failed at begin: %w", err)
	}
	var begin workflowPublishBeginResponse
	if err := decodeWorkflowPublishStep("begin", resp, &begin); err != nil {
		return nil, err
	}
	if len(begin.Assertion) == 0 || bytes.Equal(bytes.TrimSpace(begin.Assertion), []byte("null")) {
		return nil, errors.New("publish failed at begin: the controller's challenge is missing")
	}
	return &begin, nil
}

// workflowPublishFinish submits the signed assertion and decodes the publication.
func workflowPublishFinish(ctx context.Context, client *APIClient, name, version string, assertion []byte) (*workflowPublishResult, error) {
	resp, err := client.doRequest(ctx, http.MethodPost, workflowPublishPath(name, version, "finish"), bytes.NewReader(assertion))
	if err != nil {
		return nil, fmt.Errorf("publish failed at finish: %w", err)
	}
	var result workflowPublishResult
	if err := decodeWorkflowPublishStep("finish", resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// decodeWorkflowPublishStep closes resp and decodes the data of a 200 API envelope
// into out; any other status becomes an error carrying the server's code.
func decodeWorkflowPublishStep(step string, resp *http.Response, out any) error {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWorkflowPublishResponseBytes))
	if err != nil {
		return fmt.Errorf("publish failed at %s: could not read the controller's response", step)
	}
	if resp.StatusCode != http.StatusOK {
		return workflowPublishStepError(step, resp.StatusCode, body)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return fmt.Errorf("publish failed at %s: the controller's response is malformed", step)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("publish failed at %s: the controller's response is malformed", step)
	}
	return nil
}

// workflowPublishStepError describes a refused step with the controller's error code
// and message (ErrorResponse: {"error":{"code","message"}}), sanitized and bounded.
func workflowPublishStepError(step string, status int, body []byte) error {
	var parsed struct {
		Error json.RawMessage `json:"error"`
	}
	code, message := "", ""
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Error) > 0 {
		var apiErr struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(parsed.Error, &apiErr) == nil {
			code, message = apiErr.Code, apiErr.Message
		} else {
			_ = json.Unmarshal(parsed.Error, &message)
		}
	}
	prefix := fmt.Sprintf("publish refused at %s (status %d)", step, status)
	switch {
	case code != "" && message != "":
		return fmt.Errorf("%s: %s: %s", prefix, logging.SanitizeLogValue(code), logging.SanitizeLogValue(message))
	case code != "":
		return fmt.Errorf("%s: %s", prefix, logging.SanitizeLogValue(code))
	case message != "":
		return fmt.Errorf("%s: %s", prefix, logging.SanitizeLogValue(message))
	}
	return errors.New(prefix)
}

// writeWorkflowPublishResult prints the publication as text or, with asJSON, as JSON.
func writeWorkflowPublishResult(w io.Writer, result *workflowPublishResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		return nil
	}
	_, err := fmt.Fprintf(w, "Workflow published\n  Name:         %s\n  Version:      %s\n  Content hash: %s\n  Signer:       %s\n  Signed at:    %s\n",
		result.Name, result.Version, result.ContentHash,
		result.SignerAccountID, result.SignedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}
