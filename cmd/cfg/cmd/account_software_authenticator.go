// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6142: cfg account software-authenticator — set or clear the account's
// software-authenticator flag.
//
// The command relays PUT /api/v1/accounts/{username}/software-authenticator. The
// route is presence-gated like any other presence-gated route, so the client's
// step-up handling applies unchanged. Enabling needs a root-scope caller and
// clearing may be done by a tenant administrator; the server decides, and the CLI
// only reports its refusal (a non-zero exit carrying the server message).
//
// The command never writes the controller.cfg tenant list: the flag has no effect
// until the account's tenant is listed there, and that is an operator edit of the
// config file.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

// apiSoftwareAuthenticatorRequest is the body of the PUT route; the server
// rejects any other field.
type apiSoftwareAuthenticatorRequest struct {
	Enabled bool `json:"enabled"`
}

// apiSoftwareAuthenticatorResponse mirrors api.SoftwareAuthenticatorFlagResponse.
type apiSoftwareAuthenticatorResponse struct {
	Username                   string `json:"username"`
	TenantID                   string `json:"tenant_id"`
	AllowSoftwareAuthenticator bool   `json:"allow_software_authenticator"`
}

// accountSoftwareAuthenticatorCmd implements cfg account software-authenticator.
var accountSoftwareAuthenticatorCmd = &cobra.Command{
	Use:   "software-authenticator <username>",
	Short: "Set or clear the software-authenticator flag on an account",
	Long: `Set or clear the software-authenticator flag on a web-admin account.

A software authenticator is accepted for an account only when the account's
tenant is listed in webauthn.allow_software_authenticators.tenants in
controller.cfg and the account carries this flag. This command changes the
flag only. Setting it has no effect until the tenant is listed in controller.cfg,
which is an operator edit of the config file.

Both directions need a fresh presence tap. Enabling needs a root-scope caller;
clearing may be done by a tenant administrator for an account in their tenant.
The controller decides and its refusal is reported with a non-zero exit.

--enabled is required.

Examples:
  cfg account software-authenticator agent-admin --enabled=true
  cfg account software-authenticator agent-admin --enabled=false --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountSoftwareAuthenticator,
}

func init() {
	accountSoftwareAuthenticatorCmd.Flags().Bool("enabled", false, "Set (true) or clear (false) the software-authenticator flag (required)")
	accountSoftwareAuthenticatorCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")
	_ = accountSoftwareAuthenticatorCmd.MarkFlagRequired("enabled")

	accountCmd.AddCommand(accountSoftwareAuthenticatorCmd)
}

// AccountSetSoftwareAuthenticator calls PUT /api/v1/accounts/{username}/software-authenticator.
func (c *APIClient) AccountSetSoftwareAuthenticator(ctx context.Context, username string, enabled bool) (*apiSoftwareAuthenticatorResponse, error) {
	body, err := json.Marshal(apiSoftwareAuthenticatorRequest{Enabled: enabled})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, http.MethodPut,
		"/api/v1/accounts/"+url.PathEscape(username)+"/software-authenticator", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// The route answers {"error":{"code","message"}}; crossingError reads that
		// shape and returns the server message.
		return nil, crossingError(resp, "software-authenticator flag not changed")
	}

	var result apiSoftwareAuthenticatorResponse
	if _, err := decodeCrossingData(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func runAccountSoftwareAuthenticator(cmd *cobra.Command, args []string) error {
	username := args[0]

	enabled, err := cmd.Flags().GetBool("enabled")
	if err != nil {
		return fmt.Errorf("--enabled must be true or false: %w", err)
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	result, err := client.AccountSetSoftwareAuthenticator(context.Background(), username, enabled)
	if err != nil {
		return err
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	state := "disabled"
	if result.AllowSoftwareAuthenticator {
		state = "enabled"
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Software authenticator %s for account: %s\n", state, result.Username)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Tenant:      %s\n", result.TenantID)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Flag:        %v\n", result.AllowSoftwareAuthenticator)
	return nil
}
