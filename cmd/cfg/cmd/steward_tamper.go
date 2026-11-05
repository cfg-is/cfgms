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
	Codes   []string
	Message string
}

func (e *stewardFaultStillReportedError) Error() string {
	return fmt.Sprintf("409 Conflict: fault_still_reported (%s): %s", strings.Join(e.Codes, ", "), e.Message)
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
			return nil, &stewardFaultStillReportedError{Codes: fault.Codes, Message: fault.Message}
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

Both need strong assurance (a passkey tap) and are audited with your identity.`,
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

func init() {
	for _, c := range []*cobra.Command{stewardTamperRestoreCmd, stewardTamperBanCmd} {
		c.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
		c.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		c.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		c.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
		c.Flags().StringVar(&stewardTamperReason, "reason", "", "Reason stored in the audit event")
		stewardTamperCmd.AddCommand(c)
	}
	stewardCmd.AddCommand(stewardTamperCmd)
}
