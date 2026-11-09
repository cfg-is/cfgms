// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Automation library kinds and approval modes accepted by the controller routes.
const (
	automationKindScript   = "script"
	automationKindWorkflow = "workflow"

	automationApprovalsBase = "/api/v1/automation/approvals/"
	automationGrantsPath    = "/api/v1/automation/grants"
)

var automationModes = []string{"signed", "approve", "comment"}

var (
	automationURL         string
	automationTLSInsecure bool
	automationServerName  string

	automationGrantName      string
	automationGrantTenant    string
	automationGrantExpiresIn time.Duration
	automationGrantExpiresAt string

	automationVersion      string
	automationApprovalHash string
	automationContentHash  string

	automationKind     string
	automationShowDiff bool
)

// automationCmd is the parent command: cfg automation ...
var automationCmd = &cobra.Command{
	Use:   "automation",
	Short: "Manage automation grants, content approvals and library modes",
	Long: `Manage the automation controls of the controller: grants, approvals of script
and workflow versions, the pending-change queue and the library approval mode.

Everything here is also available in the web UI; cfg is an equal path, never a
requirement. Actions that need a presence check (grant create, approve, mode
set) answer the controller's challenge through the same presence relay other
presence-gated commands use: cfg prints a code and a confirmation URL, you touch
your key in the browser, and cfg retries the request with the resulting token.`,
}

var automationGrantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Create, list and revoke automation grants",
}

var automationGrantCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an automation grant",
	Long: `Create an automation grant: a credential that acts without a human until it
expires or is revoked. The credential is printed once to stdout and cannot be
read again; cfg never writes it to disk.

Exactly one of --expires-in and --expires-at is required. Creation needs a
presence check.

Examples:
  cfg automation grant create --name nightly-report --expires-in 720h`,
	Args: cobra.NoArgs,
	RunE: runAutomationGrantCreate,
}

var automationGrantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List automation grants",
	Args:  cobra.NoArgs,
	RunE:  runAutomationGrantList,
}

var automationGrantRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an automation grant and end its open runs",
	Args:  cobra.ExactArgs(1),
	RunE:  runAutomationGrantRevoke,
}

var automationApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a script or workflow version",
}

var automationApproveScriptCmd = &cobra.Command{
	Use:   "script <script-id>",
	Short: "Approve one version of a library script by its approval hash",
	Long: `Approve one version of a library script. The approval is bound to the approval
hash, which covers the script content, shell, timeout and parameters; list the
hash of a pending change with 'cfg automation pending'. Approving needs a
presence check.

Examples:
  cfg automation approve script backup-all --version 1.2.0 --approval-hash <hash>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAutomationApprove(cmd, automationKindScript, args[0])
	},
}

var automationApproveWorkflowCmd = &cobra.Command{
	Use:   "workflow <workflow-id>",
	Short: "Approve one version of a workflow by its approval hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAutomationApprove(cmd, automationKindWorkflow, args[0])
	},
}

var automationApprovalCmd = &cobra.Command{
	Use:   "approval",
	Short: "Withdraw approvals",
}

var automationApprovalRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Withdraw the approval of a script or workflow version",
}

var automationApprovalRevokeScriptCmd = &cobra.Command{
	Use:   "script <script-id>",
	Short: "Withdraw the approval of a script version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAutomationApprovalRevoke(cmd, automationKindScript, args[0])
	},
}

var automationApprovalRevokeWorkflowCmd = &cobra.Command{
	Use:   "workflow <workflow-id>",
	Short: "Withdraw the approval of a workflow version",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAutomationApprovalRevoke(cmd, automationKindWorkflow, args[0])
	},
}

var automationPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List changes awaiting approval",
	Long: `List the versions of scripts (default) or workflows (--kind workflow) that await
approval, with the approval hash to pass to 'cfg automation approve'. For
scripts, --show-diff prints the unified diff against the previously approved
version.

Examples:
  cfg automation pending --show-diff`,
	Args: cobra.NoArgs,
	RunE: runAutomationPending,
}

var automationModeCmd = &cobra.Command{
	Use:   "mode",
	Short: "Get or set the approval mode of the script or workflow library",
}

var automationModeGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the approval mode of a library",
	Args:  cobra.NoArgs,
	RunE:  runAutomationModeGet,
}

var automationModeSetCmd = &cobra.Command{
	Use:   "set <signed|approve|comment>",
	Short: "Set the approval mode of a library",
	Long: `Set the approval mode of the caller tenant's script (default) or workflow
(--kind workflow) library. Setting the mode needs a presence check.

Examples:
  cfg automation mode set approve --kind workflow`,
	Args: cobra.ExactArgs(1),
	RunE: runAutomationModeSet,
}

func init() {
	pf := automationCmd.PersistentFlags()
	pf.StringVar(&automationURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	pf.BoolVar(&automationTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	pf.StringVar(&automationServerName, "server-name", "", "Override TLS server name for certificate verification")

	gc := automationGrantCreateCmd.Flags()
	gc.StringVar(&automationGrantName, "name", "", "Grant name (required)")
	gc.StringVar(&automationGrantTenant, "tenant", "", "Tenant the grant belongs to (required for a root-scoped caller)")
	gc.DurationVar(&automationGrantExpiresIn, "expires-in", 0, "Grant lifetime from now, for example 720h")
	gc.StringVar(&automationGrantExpiresAt, "expires-at", "", "Grant expiry as an RFC 3339 time")
	_ = automationGrantCreateCmd.MarkFlagRequired("name")
	automationGrantListCmd.Flags().StringVar(&automationGrantTenant, "tenant", "", "Tenant to list (root-scoped callers)")

	for _, c := range []*cobra.Command{
		automationApproveScriptCmd, automationApproveWorkflowCmd,
		automationApprovalRevokeScriptCmd, automationApprovalRevokeWorkflowCmd,
	} {
		c.Flags().StringVar(&automationVersion, "version", "", "Version to act on (required)")
		c.Flags().StringVar(&automationApprovalHash, "approval-hash", "", "Approval hash of the version (required)")
		_ = c.MarkFlagRequired("version")
		_ = c.MarkFlagRequired("approval-hash")
	}
	for _, c := range []*cobra.Command{automationApproveScriptCmd, automationApproveWorkflowCmd} {
		c.Flags().StringVar(&automationContentHash, "content-hash", "", "Content hash the controller must still hold (optional)")
	}

	for _, c := range []*cobra.Command{automationPendingCmd, automationModeGetCmd, automationModeSetCmd} {
		c.Flags().StringVar(&automationKind, "kind", automationKindScript, "Library kind: script or workflow")
	}
	automationPendingCmd.Flags().BoolVar(&automationShowDiff, "show-diff", false, "Print the diff of each pending script change")

	automationGrantCmd.AddCommand(automationGrantCreateCmd, automationGrantListCmd, automationGrantRevokeCmd)
	automationApproveCmd.AddCommand(automationApproveScriptCmd, automationApproveWorkflowCmd)
	automationApprovalRevokeCmd.AddCommand(automationApprovalRevokeScriptCmd, automationApprovalRevokeWorkflowCmd)
	automationApprovalCmd.AddCommand(automationApprovalRevokeCmd)
	automationModeCmd.AddCommand(automationModeGetCmd, automationModeSetCmd)
	automationCmd.AddCommand(automationGrantCmd, automationApproveCmd, automationApprovalCmd, automationPendingCmd, automationModeCmd)
	rootCmd.AddCommand(automationCmd)
}

// getAutomationClient creates the API client for the automation commands.
func getAutomationClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(automationURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := automationTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	client, err := requireSessionOrBundleClient(apiURL, tlsInsecure, automationServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	return client, nil
}

// automationCall sends one request and returns the data payload of the response
// envelope (nil for a 204). A presence challenge on a gated route is answered by
// doRequest through the presence relay and the request retried, so a caller sees
// only the final result.
func automationCall(client *APIClient, method, path string, body any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	resp, err := client.doRequest(context.Background(), method, path, reader)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusNoContent:
		return nil, nil
	default:
		return nil, client.parseError(resp)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// automationJSON reports whether the operator asked for JSON output.
func automationJSON() bool { return strings.EqualFold(output, "json") }

// printAutomationJSON writes data, indented, to the command's stdout.
func printAutomationJSON(cmd *cobra.Command, data json.RawMessage) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		return fmt.Errorf("failed to format response: %w", err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), pretty.String())
	return nil
}

type automationGrantRecord struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (g automationGrantRecord) status() string {
	if g.RevokedAt != nil {
		return "revoked"
	}
	return "active"
}

// automationGrantExpiry resolves --expires-in / --expires-at to one expiry time.
func automationGrantExpiry(now time.Time) (time.Time, error) {
	switch {
	case automationGrantExpiresIn != 0 && automationGrantExpiresAt != "":
		return time.Time{}, fmt.Errorf("--expires-in and --expires-at are mutually exclusive")
	case automationGrantExpiresIn < 0:
		return time.Time{}, fmt.Errorf("--expires-in must be positive")
	case automationGrantExpiresIn > 0:
		return now.Add(automationGrantExpiresIn).UTC(), nil
	case automationGrantExpiresAt != "":
		t, err := time.Parse(time.RFC3339, automationGrantExpiresAt)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid --expires-at %q: expected an RFC 3339 time", logging.SanitizeLogValue(automationGrantExpiresAt))
		}
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("one of --expires-in or --expires-at is required")
}

func runAutomationGrantCreate(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(automationGrantName) == "" {
		return fmt.Errorf("--name must not be empty")
	}
	expiresAt, err := automationGrantExpiry(time.Now())
	if err != nil {
		return err
	}
	body := map[string]any{"name": automationGrantName, "expires_at": expiresAt}
	if automationGrantTenant != "" {
		body["tenant_id"] = automationGrantTenant
	}

	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	data, err := automationCall(client, http.MethodPost, automationGrantsPath, body)
	if err != nil {
		return fmt.Errorf("failed to create grant: %w", err)
	}

	// The credential is shown exactly once, on stdout, and only there: cfg never
	// writes it to a file. With JSON output the whole response is the output.
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	var created struct {
		Grant      automationGrantRecord `json:"grant"`
		Credential string                `json:"credential"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if created.Credential == "" {
		return fmt.Errorf("the controller returned no credential for grant %s", logging.SanitizeLogValue(created.Grant.ID))
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Grant %s (%s) created for tenant %s, expires %s.\nThe credential below is shown once and cannot be read again; store it now.\n",
		logging.SanitizeLogValue(created.Grant.ID), logging.SanitizeLogValue(created.Grant.Name),
		logging.SanitizeLogValue(created.Grant.TenantID), created.Grant.ExpiresAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), created.Credential)
	return nil
}

func runAutomationGrantList(cmd *cobra.Command, _ []string) error {
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	path := automationGrantsPath
	if automationGrantTenant != "" {
		path += "?tenant=" + url.QueryEscape(automationGrantTenant)
	}
	data, err := automationCall(client, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("failed to list grants: %w", err)
	}
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	var list struct {
		Grants []automationGrantRecord `json:"grants"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if len(list.Grants) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No automation grants found.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tNAME\tTENANT\tEXPIRES\tSTATUS")
	for _, g := range list.Grants {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", escapeControl(g.ID), escapeControl(g.Name),
			escapeControl(g.TenantID), g.ExpiresAt.UTC().Format(time.RFC3339), g.status())
	}
	return w.Flush()
}

func runAutomationGrantRevoke(cmd *cobra.Command, args []string) error {
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	data, err := automationCall(client, http.MethodDelete, automationGrantsPath+"/"+url.PathEscape(args[0]), nil)
	if err != nil {
		return fmt.Errorf("failed to revoke grant: %w", err)
	}
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	var revoked struct {
		RunsEnded int `json:"runs_ended"`
	}
	if err := json.Unmarshal(data, &revoked); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Revoked grant %s; %d open run(s) ended.\n", escapeControl(args[0]), revoked.RunsEnded)
	return nil
}

// automationApprovalsPath returns the approvals route of kind.
func automationApprovalsPath(kind string) string {
	return automationApprovalsBase + kind + "s"
}

func runAutomationApprove(cmd *cobra.Command, kind, id string) error {
	body := map[string]string{
		kind + "_id":    id,
		"version":       automationVersion,
		"approval_hash": automationApprovalHash,
	}
	if automationContentHash != "" {
		body["content_hash"] = automationContentHash
	}
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	data, err := automationCall(client, http.MethodPost, automationApprovalsPath(kind), body)
	if err != nil {
		return fmt.Errorf("failed to approve %s: %w", kind, err)
	}
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Approved %s %s version %s.\n", kind, escapeControl(id), escapeControl(automationVersion))
	return nil
}

func runAutomationApprovalRevoke(cmd *cobra.Command, kind, id string) error {
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	path := automationApprovalsPath(kind) + "/" + url.PathEscape(id) + "/" +
		url.PathEscape(automationVersion) + "/" + url.PathEscape(automationApprovalHash)
	if _, err := automationCall(client, http.MethodDelete, path, nil); err != nil {
		return fmt.Errorf("failed to withdraw %s approval: %w", kind, err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Withdrew approval of %s %s version %s.\n", kind, escapeControl(id), escapeControl(automationVersion))
	return nil
}

// validateAutomationKind rejects a kind the controller does not serve.
func validateAutomationKind(kind string) error {
	if kind != automationKindScript && kind != automationKindWorkflow {
		return fmt.Errorf("invalid --kind %q: must be script or workflow", logging.SanitizeLogValue(kind))
	}
	return nil
}

func runAutomationPending(cmd *cobra.Command, _ []string) error {
	if err := validateAutomationKind(automationKind); err != nil {
		return err
	}
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	if automationKind == automationKindWorkflow {
		return runAutomationPendingWorkflows(cmd, client)
	}
	return runAutomationPendingScripts(cmd, client)
}

// pendingScriptChange is one entry of the pending script change list.
type pendingScriptChange struct {
	ScriptID        string `json:"script_id"`
	Version         string `json:"version"`
	ApprovalHash    string `json:"approval_hash"`
	PreviousVersion string `json:"previous_version"`
	FirstSeen       string `json:"first_seen"`
	Diff            string `json:"diff"`
	DiffUnavailable string `json:"diff_unavailable"`
}

func runAutomationPendingScripts(cmd *cobra.Command, client *APIClient) error {
	data, err := automationCall(client, http.MethodGet, automationApprovalsPath(automationKindScript)+"/pending", nil)
	if err != nil {
		return fmt.Errorf("failed to list pending changes: %w", err)
	}
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	var list struct {
		Changes []pendingScriptChange `json:"changes"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if len(list.Changes) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No pending changes.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SCRIPT\tVERSION\tPREVIOUS\tFIRST SEEN\tAPPROVAL HASH")
	for _, c := range list.Changes {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", escapeControl(c.ScriptID), escapeControl(c.Version),
			escapeControl(c.PreviousVersion), escapeControl(c.FirstSeen), escapeControl(c.ApprovalHash))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if automationShowDiff {
		printPendingDiffs(cmd.OutOrStdout(), list.Changes)
	}
	return nil
}

// printPendingDiffs prints the diff of each pending change, or why there is none.
func printPendingDiffs(out io.Writer, changes []pendingScriptChange) {
	for _, c := range changes {
		_, _ = fmt.Fprintf(out, "\n--- %s %s\n", escapeControl(c.ScriptID), escapeControl(c.Version))
		if c.Diff == "" {
			_, _ = fmt.Fprintf(out, "(no diff: %s)\n", escapeControl(c.DiffUnavailable))
			continue
		}
		_, _ = fmt.Fprintln(out, escapeDiff(c.Diff))
	}
}

// escapeDiff escapes control characters other than newline and tab, so a diff of
// attacker-influenced script text cannot drive the operator's terminal.
func escapeDiff(diff string) string {
	var b strings.Builder
	for _, r := range diff {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		b.WriteString(escapeControl(string(r)))
	}
	return b.String()
}

// workflowPendingRow is one entry of the workflow approvals list.
type workflowPendingRow struct {
	WorkflowID   string `json:"workflow_id"`
	Version      string `json:"version"`
	ApprovalHash string `json:"approval_hash"`
	State        string `json:"state"`
	Reason       string `json:"reason"`
}

// runAutomationPendingWorkflows lists the workflow versions without an approval:
// the workflow routes have no separate pending queue, so the pending ones are the
// entries of the approvals list in the pending state.
func runAutomationPendingWorkflows(cmd *cobra.Command, client *APIClient) error {
	data, err := automationCall(client, http.MethodGet, automationApprovalsPath(automationKindWorkflow), nil)
	if err != nil {
		return fmt.Errorf("failed to list pending changes: %w", err)
	}
	var list struct {
		Workflows []workflowPendingRow `json:"workflows"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	pending := make([]workflowPendingRow, 0, len(list.Workflows))
	for _, wf := range list.Workflows {
		if wf.State == "pending" {
			pending = append(pending, wf)
		}
	}
	if automationJSON() {
		raw, err := json.Marshal(map[string]any{"changes": pending})
		if err != nil {
			return fmt.Errorf("failed to encode output: %w", err)
		}
		return printAutomationJSON(cmd, raw)
	}
	if len(pending) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No pending changes.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "WORKFLOW\tVERSION\tREASON\tAPPROVAL HASH")
	for _, wf := range pending {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", escapeControl(wf.WorkflowID), escapeControl(wf.Version),
			escapeControl(wf.Reason), escapeControl(wf.ApprovalHash))
	}
	return w.Flush()
}

func automationModePath(kind string) string {
	return "/api/v1/automation/libraries/" + kind + "/mode"
}

func runAutomationModeGet(cmd *cobra.Command, _ []string) error {
	if err := validateAutomationKind(automationKind); err != nil {
		return err
	}
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	data, err := automationCall(client, http.MethodGet, automationModePath(automationKind), nil)
	if err != nil {
		return fmt.Errorf("failed to read approval mode: %w", err)
	}
	return printAutomationMode(cmd, data)
}

func runAutomationModeSet(cmd *cobra.Command, args []string) error {
	if err := validateAutomationKind(automationKind); err != nil {
		return err
	}
	mode := args[0]
	valid := false
	for _, m := range automationModes {
		valid = valid || m == mode
	}
	if !valid {
		return fmt.Errorf("invalid mode %q: must be one of %s", logging.SanitizeLogValue(mode), strings.Join(automationModes, ", "))
	}
	client, err := getAutomationClient()
	if err != nil {
		return err
	}
	data, err := automationCall(client, http.MethodPut, automationModePath(automationKind), map[string]string{"mode": mode})
	if err != nil {
		return fmt.Errorf("failed to set approval mode: %w", err)
	}
	return printAutomationMode(cmd, data)
}

func printAutomationMode(cmd *cobra.Command, data json.RawMessage) error {
	if automationJSON() {
		return printAutomationJSON(cmd, data)
	}
	var m struct {
		Kind string `json:"kind"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s library approval mode: %s\n", escapeControl(m.Kind), escapeControl(m.Mode))
	return nil
}
