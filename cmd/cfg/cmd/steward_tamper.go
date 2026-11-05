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
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// Operator verbs that end a steward's tampered state: restore it to trusted, or
// ban its identity. Investigation uses the existing signed actions
// (`cfg steward run-command`, scripts and tools), which stay available against a
// tampered steward.

var stewardTamperReason string

// APITamperVerbResponse is the result of a tamper restore or ban.
type APITamperVerbResponse struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	Note           string   `json:"note"`
}

// stewardFaultStillReportedError is the controller's refusal of a restore while
// the steward still reports a tamper code.
type stewardFaultStillReportedError struct {
	StewardID string
	Codes     []string
	Message   string
}

func (e *stewardFaultStillReportedError) Error() string {
	return fmt.Sprintf("409 Conflict: fault_still_reported (%s): %s\nRepair it instead: cfg steward tamper repair %s",
		strings.Join(e.Codes, ", "), e.Message, e.StewardID)
}

// tamperVerbDo posts a tamper verb. A restore refused with fault_still_reported
// comes back as *stewardFaultStillReportedError; other failures are the usual
// operator-readable API error.
func tamperVerbDo(ctx context.Context, c *APIClient, stewardID, verb, reason string) (*APITamperVerbResponse, error) {
	path := "/api/v1/stewards/" + url.PathEscape(stewardID) + "/tamper/" + verb
	var payload io.Reader
	if reason != "" {
		b, err := json.Marshal(map[string]string{"reason": reason})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		payload = bytes.NewReader(b)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var fault struct {
			Error   string   `json:"error"`
			Codes   []string `json:"codes"`
			Message string   `json:"message"`
		}
		if resp.StatusCode == http.StatusConflict && json.Unmarshal(body, &fault) == nil && fault.Error == "fault_still_reported" {
			return nil, &stewardFaultStillReportedError{StewardID: stewardID, Codes: fault.Codes, Message: fault.Message}
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil, identityVerbError(resp)
	}
	var env struct {
		Data APITamperVerbResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &env.Data, nil
}

var stewardTamperCmd = &cobra.Command{
	Use:   "tamper",
	Short: "End a steward's tampered state: restore it or ban it",
	Long: `A steward that reports tampering is marked tampered: it stays visible, receives
no automated commands or config, and keeps reporting. Scripts, commands and tools
you sign yourself still reach it, so investigate with 'cfg steward run-command'
and the other signed actions, then end the state with one of:

  cfg steward tamper restore <steward-id>   back to trusted; normal traffic resumes
  cfg steward tamper ban <steward-id>       revoke the identity; refused from then on
  cfg steward tamper repair <steward-id>    repair and restore a steward that still reports a fault

All need strong assurance (a passkey tap) and are audited with your identity.`,
}

var stewardTamperRestoreCmd = &cobra.Command{
	Use:   "restore <steward-id>",
	Short: "Return a tampered steward to trusted",
	Long: `Return a tampered steward to trusted (active, or registered if it never sent a
heartbeat). Automated commands and config pulls resume, and a connected steward
is told it is released.

A steward whose latest heartbeat (within the last 5 minutes) still carries a
tamper code is refused: it still reports a fault and must be repaired and
restored instead. Nothing overrides that check. A restored steward that reports
a tamper code again returns to tampered on its next heartbeat.

Only a tampered steward can be restored. --reason is stored in the audit event.
Requires strong assurance (admin mTLS or a passkey-elevated session).`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardTamperRestore,
}

var stewardTamperBanCmd = &cobra.Command{
	Use:   "ban <steward-id>",
	Short: "Revoke a tampered steward's identity",
	Long: `Revoke every client certificate issued for the steward ID and mark the record
revoked. The live control stream is closed and the steward is refused from then
on, including refresh, renewal and any registration naming it as the machine it
was copied from.

A ban affects only the identity named. A locked copy that names it is a different
identity and may be the real endpoint: it is banned or linked on its own.
Only a tampered steward can be banned. --reason is stored in the audit event.
Requires strong assurance (admin mTLS or a passkey-elevated session).`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardTamperBan,
}

func runStewardTamperRestore(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	if err := confirmIdentityAction(fmt.Sprintf(
		"This returns tampered steward %s to trusted: automated commands and config resume.", stewardID), stewardYes); err != nil {
		return err
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	res, err := tamperVerbDo(context.Background(), client, stewardID, "restore", stewardTamperReason)
	if err != nil {
		return err
	}
	fmt.Printf("Steward %s restored; status: %s.\n", res.ID, res.Status)
	if res.Note != "" {
		fmt.Printf("Note: %s\n", res.Note)
	}
	return nil
}

func runStewardTamperBan(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	if err := confirmIdentityAction(fmt.Sprintf(
		"This bans steward %s: its certificates are revoked and it is refused from now on.", stewardID), stewardYes); err != nil {
		return err
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	res, err := tamperVerbDo(context.Background(), client, stewardID, "ban", stewardTamperReason)
	if err != nil {
		return err
	}
	fmt.Printf("Steward %s banned; status: %s.\n", res.ID, res.Status)
	if len(res.RevokedSerials) == 0 {
		fmt.Println("Revoked serials: none issued by this controller.")
	} else {
		fmt.Println("Revoked serials:")
		for _, s := range res.RevokedSerials {
			fmt.Printf("  %s\n", s)
		}
	}
	if res.Note != "" {
		fmt.Printf("Note: %s\n", res.Note)
	}
	return nil
}

var stewardTamperApproveLoss []string

var stewardTamperRepairCmd = &cobra.Command{
	Use:   "repair <steward-id>",
	Short: "Repair and restore a tampered steward, approving any data it would lose",
	Long: `Ask a tampered steward that still reports a fault to repair itself. The steward
resets rights on its own files and makes a new identity key; its old client
certificate is revoked. It keeps its steward ID, local logs and action history,
except for any loss you approve. The request is signed and sent at once to a
connected steward, or when it next connects.

The command first reads the local data the repair would lose (repair.loss.*
codes the steward reported) and prints it. A repair that would lose data needs
exactly that loss approved with --approve-loss <code,code>; without the exact
approval nothing is sent and the command exits non-zero listing the codes. The
controller and the steward each check the approval.

If an unauthorized party holds a copy of the steward's keys and completes the
repair first, that party wins and the steward's credentials are refused; the
controller then marks it contested.

--reason is stored in the audit event. Requires strong assurance (admin mTLS or a
passkey-elevated session). Follow it with 'cfg steward tamper repair-status'.`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardTamperRepair,
}

var stewardTamperRepairStatusCmd = &cobra.Command{
	Use:   "repair-status <steward-id>",
	Short: "Show the state of a steward's latest repair request",
	Long: `Show the latest repair request for a steward: waiting (not yet delivered or
started), running, completed, restored, failed, refused_data_loss, cancelled or
contested, with who requested it, the approved loss codes and the outcome codes.
Requires strong assurance (admin mTLS or a passkey-elevated session).`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardTamperRepairStatus,
}

// APITamperRepairResponse is the 202 body of a repair request.
type APITamperRepairResponse struct {
	RepairID  string   `json:"repair_id"`
	State     string   `json:"state"`
	Delivered bool     `json:"delivered"`
	LossCodes []string `json:"loss_codes"`
	ExpiresAt string   `json:"expires_at"`
	Note      string   `json:"note"`
}

// APITamperRepairStatus is the body of GET .../tamper/repair.
type APITamperRepairStatus struct {
	RepairID      string   `json:"repair_id"`
	State         string   `json:"state"`
	RequestedBy   string   `json:"requested_by"`
	RequestedAt   string   `json:"requested_at"`
	LossCodes     []string `json:"loss_codes"`
	OutcomeCodes  []string `json:"outcome_codes"`
	CompletedFrom string   `json:"completed_from"`
}

// stewardLossApprovalRequiredError reports that the approval is not exactly the
// loss the steward reported. Nothing was sent.
type stewardLossApprovalRequiredError struct {
	StewardID string
	LossCodes []string
}

func (e *stewardLossApprovalRequiredError) Error() string {
	if len(e.LossCodes) == 0 {
		return fmt.Sprintf("loss_approval_required: the steward reports no data loss; run without --approve-loss: cfg steward tamper repair %s", e.StewardID)
	}
	return fmt.Sprintf("loss_approval_required: repairing would lose: %s\nApprove exactly that loss: cfg steward tamper repair %s --approve-loss %s",
		strings.Join(e.LossCodes, ", "), e.StewardID, strings.Join(e.LossCodes, ","))
}

// stewardLossCodes reads the loss-risk codes the steward last reported.
func stewardLossCodes(ctx context.Context, c *APIClient, stewardID string) ([]string, error) {
	resp, err := c.Get(ctx, "/api/v1/stewards/"+url.PathEscape(stewardID))
	if err != nil {
		return nil, fmt.Errorf("failed to read steward: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, identityVerbError(resp)
	}
	var env struct {
		Data struct {
			HealthReasons []struct {
				Code string `json:"code"`
			} `json:"health_reasons"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("failed to decode steward: %w", err)
	}
	seen := map[string]bool{}
	var codes []string
	for _, hr := range env.Data.HealthReasons {
		if strings.HasPrefix(hr.Code, "repair.loss.") && !seen[hr.Code] {
			seen[hr.Code] = true
			codes = append(codes, hr.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

func normalizeApprovedLoss(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func sameCodes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runStewardTamperRepair(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	ctx := context.Background()
	lossCodes, err := stewardLossCodes(ctx, client, stewardID)
	if err != nil {
		return err
	}
	approved := normalizeApprovedLoss(stewardTamperApproveLoss)
	if len(lossCodes) == 0 {
		fmt.Println("The steward reports no local data that the repair would lose.")
	} else {
		fmt.Println("Repairing would lose this local data:")
		for _, c := range lossCodes {
			fmt.Printf("  %s\n", c)
		}
	}
	if !sameCodes(lossCodes, approved) {
		return &stewardLossApprovalRequiredError{StewardID: stewardID, LossCodes: lossCodes}
	}
	if err := confirmIdentityAction(fmt.Sprintf(
		"This repairs tampered steward %s: it makes a new identity key and its old certificate is revoked. Approved data loss: %s.",
		stewardID, lossSummary(approved)), stewardYes); err != nil {
		return err
	}
	res, err := tamperRepairDo(ctx, client, stewardID, stewardTamperReason, approved)
	if err != nil {
		return err
	}
	delivery := "queued; the steward receives it when it next connects"
	if res.Delivered {
		delivery = "sent to the connected steward"
	}
	fmt.Printf("Repair %s requested for steward %s; %s.\n", res.RepairID, stewardID, delivery)
	fmt.Printf("State: %s. Follow it with: cfg steward tamper repair-status %s\n", res.State, stewardID)
	if res.Note != "" {
		fmt.Printf("Note: %s\n", res.Note)
	}
	return nil
}

func lossSummary(codes []string) string {
	if len(codes) == 0 {
		return "none"
	}
	return strings.Join(codes, ", ")
}

// tamperRepairDo posts the repair request. A 409 loss_approval_required comes
// back as *stewardLossApprovalRequiredError.
func tamperRepairDo(ctx context.Context, c *APIClient, stewardID, reason string, approved []string) (*APITamperRepairResponse, error) {
	if approved == nil {
		approved = []string{}
	}
	b, err := json.Marshal(map[string]interface{}{"reason": reason, "approved_loss_codes": approved})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/stewards/"+url.PathEscape(stewardID)+"/tamper/repair", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var gate struct {
			Error     string   `json:"error"`
			LossCodes []string `json:"loss_codes"`
		}
		if resp.StatusCode == http.StatusConflict && json.Unmarshal(body, &gate) == nil && gate.Error == "loss_approval_required" {
			return nil, &stewardLossApprovalRequiredError{StewardID: stewardID, LossCodes: gate.LossCodes}
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil, identityVerbError(resp)
	}
	var env struct {
		Data APITamperRepairResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &env.Data, nil
}

func runStewardTamperRepairStatus(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	var st APITamperRepairStatus
	if err := identityVerbDo(context.Background(), client, http.MethodGet,
		"/api/v1/stewards/"+url.PathEscape(stewardID)+"/tamper/repair", nil, &st); err != nil {
		return err
	}
	fmt.Printf("Repair %s for steward %s: %s\n", st.RepairID, stewardID, st.State)
	fmt.Printf("Requested by %s at %s\n", st.RequestedBy, st.RequestedAt)
	fmt.Printf("Approved loss: %s\n", lossSummary(st.LossCodes))
	if len(st.OutcomeCodes) > 0 {
		fmt.Printf("Outcome: %s\n", strings.Join(st.OutcomeCodes, ", "))
	}
	if st.CompletedFrom != "" {
		fmt.Printf("Completed from: %s\n", st.CompletedFrom)
	}
	return nil
}

func init() {
	stewardTamperRepairCmd.Flags().StringSliceVar(&stewardTamperApproveLoss, "approve-loss", nil,
		"Approve exactly this data loss, as comma-separated codes (e.g. repair.loss.local_logs)")
	for _, c := range []*cobra.Command{stewardTamperRepairCmd, stewardTamperRepairStatusCmd} {
		addTamperFlags(c)
	}
	for _, c := range []*cobra.Command{stewardTamperRestoreCmd, stewardTamperBanCmd} {
		addTamperFlags(c)
	}
	stewardCmd.AddCommand(stewardTamperCmd)
}

// addTamperFlags adds the connection flags (and --reason) to a tamper verb and
// attaches it to the tamper command.
func addTamperFlags(c *cobra.Command) {
	c.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	c.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	c.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	c.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	c.Flags().StringVar(&stewardTamperReason, "reason", "", "Reason stored in the audit event")
	stewardTamperCmd.AddCommand(c)
}
