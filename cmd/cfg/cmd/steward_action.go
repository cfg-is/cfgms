// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

const (
	stewardActionKindService = "service"
	stewardActionKindProcess = "process"

	// Stable API codes the CLI keys on. Never match on message text.
	apiCodeEnvelopeExpired = "ENVELOPE_EXPIRED"
	apiCodeBudgetExceeded  = "ACTION_BUDGET_EXCEEDED"

	// stewardActionDefaultWait is the default per-steward wait for a terminal run.
	stewardActionDefaultWait = 90 * time.Second

	errExpiredDuringStepUp = "signature expired during step-up; run the command again"
)

// stewardActionVerbWords is the closed set of action words per target kind. It
// mirrors the API's allowlist so a bad word fails before any signing or prompt.
var stewardActionVerbWords = map[string][]string{
	stewardActionKindService: {"start", "stop", "restart"},
	stewardActionKindProcess: {"end", "suspend", "resume"},
}

var (
	stewardActionName          string
	stewardActionPID           int
	stewardActionImage         string
	stewardActionJustification string
	stewardActionWaitTimeout   time.Duration
	stewardActionJSON          bool
)

var stewardServiceCmd = &cobra.Command{
	Use:   "service <selector> <start|stop|restart> --name <service> --justification <text>",
	Short: "Start, stop or restart a service on the stewards a selector matches",
	Long: `Run an operator-signed service action on every steward the selector matches.

One envelope is signed per steward with your payload-signing credential and
submitted as its own action; each run is polled and a result printed per
steward. The exit code is 0 only when every steward reports ok.

Stop prompts for confirmation even for a single steward, and any selector that
matches more than one steward prompts with the count and list. --yes skips the
prompt.

Examples:
  cfg steward service host-a restart --name spooler --justification "stuck queue"
  cfg steward service 'tag:print' stop --name spooler --justification "maintenance" --yes`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStewardActionCmd(cmd.Context(), stewardActionKindService, args)
	},
}

var stewardProcessCmd = &cobra.Command{
	Use:   "process <selector> <end|suspend|resume> --pid <n> --image <name> --justification <text>",
	Short: "End, suspend or resume a process on the stewards a selector matches",
	Long: `Run an operator-signed process action on every steward the selector matches.

The process is identified by PID and by the image name you saw; the steward
refuses the action if the process at that PID is not the one named.

One envelope is signed per steward with your payload-signing credential and
submitted as its own action; each run is polled and a result printed per
steward. The exit code is 0 only when every steward reports ok.

End prompts for confirmation even for a single steward, and any selector that
matches more than one steward prompts with the count and list. --yes skips the
prompt.

Examples:
  cfg steward process host-a end --pid 4120 --image notepad.exe --justification "hung"`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStewardActionCmd(cmd.Context(), stewardActionKindProcess, args)
	},
}

func init() {
	for _, c := range []*cobra.Command{stewardServiceCmd, stewardProcessCmd} {
		c.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
		c.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		c.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		c.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
		c.Flags().StringVar(&stewardActionJustification, "justification", "", "Why this action is being taken (required, recorded in the audit log)")
		c.Flags().DurationVar(&stewardActionWaitTimeout, "wait-timeout", stewardActionDefaultWait, "Maximum time to wait for each steward's result")
		c.Flags().BoolVar(&stewardActionJSON, "json", false, "Emit a JSON result keyed by steward instead of plain text")
		_ = c.MarkFlagRequired("justification")
	}
	stewardServiceCmd.Flags().StringVar(&stewardActionName, "name", "", "Service name")
	_ = stewardServiceCmd.MarkFlagRequired("name")
	stewardProcessCmd.Flags().IntVar(&stewardActionPID, "pid", 0, "Process ID")
	stewardProcessCmd.Flags().StringVar(&stewardActionImage, "image", "", "Process image name, as shown to the operator")
	_ = stewardProcessCmd.MarkFlagRequired("pid")
	_ = stewardProcessCmd.MarkFlagRequired("image")

	stewardCmd.AddCommand(stewardServiceCmd)
	stewardCmd.AddCommand(stewardProcessCmd)
}

// stewardActionSpec is one operator-signed action: what to do, to which target.
type stewardActionSpec struct {
	Kind          string
	Word          string // start, stop, end, ...
	Name          string // service name, or decimal PID for a process
	Image         string // process image name (process only)
	Justification string
}

func (s stewardActionSpec) action() operatorpayload.Action {
	a := operatorpayload.Action{Verb: s.Kind + "." + s.Word, TargetKind: s.Kind, TargetName: s.Name}
	if s.Kind == stewardActionKindProcess {
		a.Parameters = map[string]string{"image": s.Image}
	}
	return a
}

func (s stewardActionSpec) path(stewardID string) string {
	if s.Kind == stewardActionKindService {
		return "/api/v1/stewards/" + url.PathEscape(stewardID) + "/services/" + url.PathEscape(s.Name) + "/actions"
	}
	return "/api/v1/stewards/" + url.PathEscape(stewardID) + "/processes/" + url.PathEscape(s.Name) + "/actions"
}

// destructive reports whether the action prompts even for a single steward.
func (s stewardActionSpec) destructive() bool { return s.Word == "stop" || s.Word == "end" }

func runStewardActionCmd(ctx context.Context, kind string, args []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	spec := stewardActionSpec{Kind: kind, Word: args[1], Justification: stewardActionJustification}
	switch kind {
	case stewardActionKindService:
		spec.Name = stewardActionName
	case stewardActionKindProcess:
		if stewardActionPID <= 0 {
			return fmt.Errorf("--pid must be a positive process id")
		}
		spec.Name = strconv.Itoa(stewardActionPID)
		spec.Image = stewardActionImage
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	return runStewardAction(ctx, client, args[0], spec, stewardActionOpts{
		Yes:         stewardYes,
		JSON:        stewardActionJSON,
		WaitTimeout: stewardActionWaitTimeout,
		Stdout:      os.Stdout,
	})
}

type stewardActionOpts struct {
	Yes         bool
	JSON        bool
	WaitTimeout time.Duration
	Stdout      io.Writer
}

// actionOutcome is one steward's result. Code is a controller result code or one of
// the CLI-local codes: not_submitted, timeout, error.
type actionOutcome struct {
	Code   string `json:"result"`
	Detail string `json:"detail"`
	RunID  string `json:"run_id,omitempty"`
}

func (o actionOutcome) ok() bool { return o.Code == "ok" }

// stewardActionResultText is the plain-words text for a controller result code.
func stewardActionResultText(code string) string {
	switch code {
	case "ok":
		return "ok"
	case "self_protect":
		return "refused: the steward will not act on itself"
	case "process_changed":
		return "refused: the process at that PID is not the one named"
	case "unsupported":
		return "unsupported"
	case "failed":
		return "failed"
	case "expired":
		return "expired, not run"
	case "no_result":
		return "sent, no result reported: the action may have run"
	default:
		return "failed (unrecognised result " + strconv.Quote(code) + ")"
	}
}

// actionConfirmFn is the multi-host confirm gate; tests replace it.
var actionConfirmFn = confirmMultiHost

// confirmSingleDestructive asks before a stop or end on one steward.
func confirmSingleDestructive(m StewardInfo, spec stewardActionSpec, yes bool) error {
	if yes {
		return nil
	}
	if !isTerminalFn() {
		return fmt.Errorf("%s %s on %s needs confirmation; pass --yes/-y to confirm, or run interactively", spec.Kind, spec.Word, stewardKey(m))
	}
	fmt.Fprintf(os.Stderr, "%s %s %q on %s. Proceed? [y/N]: ", spec.Word, spec.Kind, spec.Name, stewardKey(m))
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "y" || answer == "yes" {
			return nil
		}
	}
	return fmt.Errorf("aborted by operator")
}

// runStewardAction resolves the selector, confirms, then for each matched steward in
// turn signs one envelope immediately before submitting it, polls the run and records
// the result. It returns a non-nil error unless every steward is ok.
func runStewardAction(ctx context.Context, client *APIClient, selector string, spec stewardActionSpec, opts stewardActionOpts) error {
	valid := false
	for _, w := range stewardActionVerbWords[spec.Kind] {
		valid = valid || w == spec.Word
	}
	if !valid {
		return fmt.Errorf("unknown %s action %q (use one of: %s)", spec.Kind, spec.Word, strings.Join(stewardActionVerbWords[spec.Kind], ", "))
	}
	if strings.TrimSpace(spec.Justification) == "" {
		return fmt.Errorf("--justification is required")
	}
	if _, err := operatorpayload.ActionContent(spec.action()); err != nil {
		return fmt.Errorf("invalid %s action: %w", spec.Kind, err)
	}
	if opts.WaitTimeout <= 0 {
		opts.WaitTimeout = stewardActionDefaultWait
	}
	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	progressW := stdout
	if opts.JSON {
		progressW = os.Stderr
	}

	matches, err := resolveOrFailFast(ctx, client, selector)
	if err != nil {
		return err
	}
	if len(matches) > 1 {
		if err := actionConfirmFn(matches, opts.Yes); err != nil {
			return err
		}
	} else if spec.destructive() {
		if err := confirmSingleDestructive(matches[0], spec, opts.Yes); err != nil {
			return err
		}
	}

	outcomes := make(map[string]actionOutcome, len(matches))
	order := make([]string, 0, len(matches))
	var stopErr error
	stopReason := ""
	for _, m := range matches {
		key := stewardKey(m)
		order = append(order, key)
		if stopErr != nil || stopReason != "" {
			outcomes[key] = actionOutcome{Code: "not_submitted", Detail: "not submitted"}
			continue
		}
		runID, subErr := submitStewardAction(ctx, client, spec, m.ID)
		var budget *budgetExceededError
		var fatal *fatalActionError
		switch {
		case errors.As(subErr, &budget):
			fmt.Fprintf(os.Stderr, "refused: %s\n", budget.Error())
			stopReason = budget.Error()
			outcomes[key] = actionOutcome{Code: "not_submitted", Detail: "not submitted: " + stopReason}
			continue
		case errors.As(subErr, &fatal):
			stopErr = fatal.err
			outcomes[key] = actionOutcome{Code: "not_submitted", Detail: "not submitted: " + fatal.err.Error()}
			continue
		case subErr != nil:
			outcomes[key] = actionOutcome{Code: "error", Detail: "not submitted: " + subErr.Error()}
			continue
		}
		// Progress output is advisory: the run is already submitted, so a failed
		// progress write must not abandon polling or lose its outcome.
		_, _ = fmt.Fprintf(progressW, "%s: run %s submitted\n", key, runID)
		outcomes[key] = pollStewardAction(ctx, client, runID, m.ID, opts.WaitTimeout, progressW)
	}

	failures := 0
	for _, key := range order {
		if !outcomes[key].ok() {
			failures++
		}
	}
	if err := renderActionOutcomes(stdout, opts.JSON, order, outcomes); err != nil {
		return err
	}
	switch {
	case stopErr != nil:
		return stopErr
	case stopReason != "":
		return fmt.Errorf("%s; %d of %d stewards did not complete ok", stopReason, failures, len(matches))
	case failures > 0:
		return fmt.Errorf("%d of %d stewards did not complete ok", failures, len(matches))
	}
	return nil
}

func renderActionOutcomes(w io.Writer, asJSON bool, order []string, outcomes map[string]actionOutcome) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(outcomes)
	}
	for _, key := range order {
		if _, err := fmt.Fprintf(w, "%s: %s\n", key, outcomes[key].Detail); err != nil {
			return fmt.Errorf("failed to write result: %w", err)
		}
	}
	return nil
}

type budgetExceededError struct{}

func (*budgetExceededError) Error() string { return "steward action budget exceeded" }

// fatalActionError stops all further submits (signing or transport failure).
type fatalActionError struct{ err error }

func (e *fatalActionError) Error() string { return e.err.Error() }
func (e *fatalActionError) Unwrap() error { return e.err }

// errorBodyCode extracts error.code from a controller error body.
func errorBodyCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error.Code
}

// submitStewardAction signs and POSTs one action for one steward and returns the run
// id. The envelope is signed immediately before the submit. If the controller refuses
// it as expired (a step-up ceremony can outlast the envelope), a fresh envelope with a
// new nonce is signed and submitted once as a new request; a stale envelope is never
// resent. A second expiry fails with errExpiredDuringStepUp.
func submitStewardAction(ctx context.Context, client *APIClient, spec stewardActionSpec, stewardID string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		sig, envelope, err := buildAndSignActionEnvelope(spec.action(), stewardID)
		if err != nil {
			return "", &fatalActionError{err: err}
		}
		reqBody := map[string]interface{}{
			"action":        spec.Word,
			"justification": spec.Justification,
			"nonce":         envelope.Nonce,
			"expires_at":    envelope.ExpiresAt.Format(time.RFC3339),
			"targets":       envelope.Targets,
			"signature":     sig,
		}
		if spec.Kind == stewardActionKindProcess {
			reqBody["image"] = spec.Image
		}
		bodyJSON, err := json.Marshal(reqBody)
		if err != nil {
			return "", &fatalActionError{err: fmt.Errorf("failed to encode request: %w", err)}
		}
		resp, err := client.doRequest(ctx, http.MethodPost, spec.path(stewardID), bytes.NewReader(bodyJSON))
		if err != nil {
			return "", &fatalActionError{err: fmt.Errorf("failed to submit action: %w", err)}
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		code := errorBodyCode(body)
		switch {
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated:
			var out struct {
				Data struct {
					RunID string `json:"run_id"`
				} `json:"data"`
				RunID string `json:"run_id"`
			}
			if err := json.Unmarshal(body, &out); err != nil {
				return "", fmt.Errorf("failed to parse response: %w", err)
			}
			if id := firstNonEmpty(out.Data.RunID, out.RunID); id != "" {
				return id, nil
			}
			return "", errors.New("response carried no run id")
		case resp.StatusCode == http.StatusTooManyRequests && code == apiCodeBudgetExceeded:
			return "", &budgetExceededError{}
		case resp.StatusCode == http.StatusBadRequest && code == apiCodeEnvelopeExpired:
			if attempt == 0 {
				continue
			}
			return "", errors.New(errExpiredDuringStepUp)
		default:
			return "", fmt.Errorf("API request failed: %s - %s", resp.Status, strings.TrimSpace(string(body)))
		}
	}
	return "", errors.New(errExpiredDuringStepUp)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// pollStewardAction waits for the run to end and reads the steward's job result.
func pollStewardAction(ctx context.Context, client *APIClient, runID, stewardID string, timeout time.Duration, progressW io.Writer) actionOutcome {
	if err := waitForRun(ctx, client, runID, timeout, progressW); err != nil {
		return actionOutcome{Code: "timeout", RunID: runID, Detail: "no terminal result: " + err.Error()}
	}
	resp, err := client.Get(ctx, "/api/v1/runs/"+url.PathEscape(runID)+"/jobs")
	if err != nil {
		return actionOutcome{Code: "error", RunID: runID, Detail: "failed to fetch result: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return actionOutcome{Code: "error", RunID: runID, Detail: fmt.Sprintf("failed to fetch result: %s - %s", resp.Status, strings.TrimSpace(string(b)))}
	}
	var jobs struct {
		Data []struct {
			DeviceID   string `json:"device_id"`
			Status     string `json:"status"`
			ResultCode string `json:"result_code"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return actionOutcome{Code: "error", RunID: runID, Detail: "failed to parse result: " + err.Error()}
	}
	for _, j := range jobs.Data {
		if j.DeviceID != stewardID {
			continue
		}
		code := j.ResultCode
		if code == "" {
			code = "failed"
		}
		return actionOutcome{Code: code, RunID: runID, Detail: stewardActionResultText(code)}
	}
	return actionOutcome{Code: "error", RunID: runID, Detail: "failed: no job record returned for this steward"}
}
