// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3725 (Epic #3711): revocation and containment for enrolment-issued
// credentials. Revoke every certificate issued from one enrolment token, cancel a
// request that was approved but never collected, and find — and, as a separate
// explicit action, revoke — enrolment-issued certificates with no account binding.
//
// All four subcommands attach to the existing "cfg credential" root group
// (credential_request_signing_cert.go) rather than a new command tree, and use
// resolveSessionOrBundleClient exactly like cfg account — the underlying REST
// endpoints gate each verb server-side via permissionAssurance.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var (
	credentialContainmentAPIURL   string
	credentialContainmentForce    bool
	credentialListOrphanedJSONOut bool
)

// credentialRevokeByTokenCmd implements cfg credential revoke-by-token.
var credentialRevokeByTokenCmd = &cobra.Command{
	Use:   "revoke-by-token <token-id>",
	Short: "Revoke every certificate issued from an enrolment token",
	Long: `Revokes every certificate already issued from one enrolment token and blocks
every still-pending/approved request under it from ever producing one.

Reports a per-request outcome (contained / already_contained / error) rather than
failing the whole operation on the first error. This is irreversible — revoked
certificates cannot be un-revoked. Use --force to skip the interactive confirmation
prompt.

Examples:
  cfg credential revoke-by-token et-1234
  cfg credential revoke-by-token et-1234 --force`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialRevokeByToken,
}

// credentialCancelRequestCmd implements cfg credential cancel-request.
var credentialCancelRequestCmd = &cobra.Command{
	Use:   "cancel-request <request-id>",
	Short: "Cancel an approved-but-uncollected credential request",
	Long: `Cancels a credential request that is approved but not yet collected, so it can
never be collected. Refused with a distinct error if the request is pending (not
yet approved — use deny instead), already collected (use revoke-by-token instead),
or already denied.

Use --force to skip the interactive confirmation prompt.

Examples:
  cfg credential cancel-request cr-1234
  cfg credential cancel-request cr-1234 --force`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialCancelRequest,
}

// credentialListOrphanedCmd implements cfg credential list-orphaned.
var credentialListOrphanedCmd = &cobra.Command{
	Use:   "list-orphaned",
	Short: "List collected enrolment-flow certificates with no account binding",
	Long: `Lists "collected" enrolment-flow certificates whose bound account no longer
carries a matching binding — the on-demand equivalent of the background orphan
sweep. Listing never revokes anything; use revoke-orphaned as a separate explicit
action.

Examples:
  cfg credential list-orphaned
  cfg credential list-orphaned --json`,
	Args: cobra.NoArgs,
	RunE: runCredentialListOrphaned,
}

// credentialRevokeOrphanedCmd implements cfg credential revoke-orphaned.
var credentialRevokeOrphanedCmd = &cobra.Command{
	Use:   "revoke-orphaned <serial>",
	Short: "Revoke a listed orphaned enrolment-flow certificate",
	Long: `Revokes a certificate previously found by "cfg credential list-orphaned". Refuses
with a conflict if the serial is bound to an account (not orphaned) or already
revoked.

This is irreversible. Use --force to skip the interactive confirmation prompt.

Examples:
  cfg credential revoke-orphaned 123456789
  cfg credential revoke-orphaned 123456789 --force`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialRevokeOrphaned,
}

func init() {
	credentialRevokeByTokenCmd.Flags().StringVar(&credentialContainmentAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialRevokeByTokenCmd.Flags().BoolVar(&credentialContainmentForce, "force", false, "Skip confirmation prompt")

	credentialCancelRequestCmd.Flags().StringVar(&credentialContainmentAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialCancelRequestCmd.Flags().BoolVar(&credentialContainmentForce, "force", false, "Skip confirmation prompt")

	credentialListOrphanedCmd.Flags().StringVar(&credentialContainmentAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialListOrphanedCmd.Flags().BoolVar(&credentialListOrphanedJSONOut, "json", false, "Emit JSON output")

	credentialRevokeOrphanedCmd.Flags().StringVar(&credentialContainmentAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	credentialRevokeOrphanedCmd.Flags().BoolVar(&credentialContainmentForce, "force", false, "Skip confirmation prompt")

	credentialCmd.AddCommand(credentialRevokeByTokenCmd)
	credentialCmd.AddCommand(credentialCancelRequestCmd)
	credentialCmd.AddCommand(credentialListOrphanedCmd)
	credentialCmd.AddCommand(credentialRevokeOrphanedCmd)
}

// getCredentialContainmentAPIClient resolves an authenticated client exactly like
// cfg account's getAccountClient — session token or mTLS bundle, whichever is active.
func getCredentialContainmentAPIClient() (*APIClient, error) {
	apiURL := credentialContainmentAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	client, err := resolveSessionOrBundleClient(apiURL, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve API client: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("no controller connection found — run 'cfg connect' or set CFGMS_API_URL")
	}
	return client, nil
}

// ---- response DTOs mirroring the server-side types -----------------------------------

// apiCredentialRequestContainmentOutcome mirrors api.credentialRequestContainmentOutcome.
type apiCredentialRequestContainmentOutcome struct {
	RequestID string `json:"request_id"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail,omitempty"`
}

// apiRevokeByEnrolmentTokenResponse mirrors api.RevokeByEnrolmentTokenResponse.
type apiRevokeByEnrolmentTokenResponse struct {
	TokenID string                                   `json:"token_id"`
	Results []apiCredentialRequestContainmentOutcome `json:"results"`
}

// apiOrphanedCredentialInfo mirrors api.OrphanedCredentialInfo.
type apiOrphanedCredentialInfo struct {
	RequestID   string `json:"request_id"`
	TenantID    string `json:"tenant_id"`
	Serial      string `json:"serial"`
	AccountID   string `json:"account_id"`
	CollectedAt string `json:"collected_at"`
}

// ---- run functions ---------------------------------------------------------------

func runCredentialRevokeByToken(cmd *cobra.Command, args []string) error {
	tokenID := args[0]

	if err := confirmDestructive(cmd,
		fmt.Sprintf("Revoke every certificate issued from enrolment token %q and block its pending/approved requests?", tokenID),
		credentialContainmentForce); err != nil {
		return err
	}

	client, err := getCredentialContainmentAPIClient()
	if err != nil {
		return err
	}

	path := "/api/v1/enrolment-tokens/" + url.PathEscape(tokenID) + "/revoke-issued-credentials"
	resp, err := client.doRequest(context.Background(), http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return client.parseError(resp)
	}

	var envelope struct {
		Data apiRevokeByEnrolmentTokenResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// A token with no lodged requests is not itself an error at the API layer (the
	// token may simply never have been spent), but a CLI invocation that finds
	// nothing to contain must not report silent success (Issue #3725 AC).
	if len(envelope.Data.Results) == 0 {
		return fmt.Errorf("no credential requests found for enrolment token %s", tokenID)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Containment results for enrolment token %s:\n", tokenID)
	for _, r := range envelope.Data.Results {
		if r.Detail != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s (%s)\n", r.RequestID, r.Outcome, r.Detail)
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", r.RequestID, r.Outcome)
		}
	}
	return nil
}

func runCredentialCancelRequest(cmd *cobra.Command, args []string) error {
	requestID := args[0]

	if err := confirmDestructive(cmd,
		fmt.Sprintf("Cancel credential request %q? It can never be collected afterward.", requestID),
		credentialContainmentForce); err != nil {
		return err
	}

	client, err := getCredentialContainmentAPIClient()
	if err != nil {
		return err
	}

	path := "/api/v1/credential-requests/" + url.PathEscape(requestID) + "/cancel"
	resp, err := client.doRequest(context.Background(), http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return client.parseError(resp)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Credential request cancelled: %s\n", requestID)
	return nil
}

func runCredentialListOrphaned(cmd *cobra.Command, _ []string) error {
	client, err := getCredentialContainmentAPIClient()
	if err != nil {
		return err
	}

	resp, err := client.doRequest(context.Background(), http.MethodGet, "/api/v1/credential-requests/orphaned", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return client.parseError(resp)
	}

	var envelope struct {
		Data []apiOrphanedCredentialInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if credentialListOrphanedJSONOut {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(envelope.Data)
	}

	if len(envelope.Data) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No orphaned enrolment-flow certificates found.")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Orphaned enrolment-flow certificates (%d):\n\n", len(envelope.Data))
	for _, o := range envelope.Data {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Request:   %s\n", o.RequestID)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Serial:    %s\n", o.Serial)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Tenant:    %s\n", o.TenantID)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Account:   %s\n", o.AccountID)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Collected: %s\n", o.CollectedAt)
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func runCredentialRevokeOrphaned(cmd *cobra.Command, args []string) error {
	serial := args[0]

	if err := confirmDestructive(cmd,
		fmt.Sprintf("Revoke orphaned certificate %q? (this is irreversible)", serial),
		credentialContainmentForce); err != nil {
		return err
	}

	client, err := getCredentialContainmentAPIClient()
	if err != nil {
		return err
	}

	path := "/api/v1/credential-requests/orphaned/" + url.PathEscape(serial) + "/revoke"
	resp, err := client.doRequest(context.Background(), http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return client.parseError(resp)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Orphaned certificate revoked: %s\n", serial)
	return nil
}
