// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3582: cfg account — account lifecycle and certificate-binding CLI verbs.
//
// All subcommands use resolveSessionOrBundleClient — account management is accessible
// via both session tokens and mTLS certificates. The underlying REST endpoints gate
// each verb via the appropriate permission (account:create, account:list, etc.) so the
// assurance requirement is enforced server-side, not at the CLI layer.
//
// The create/list/get/update/delete verbs mirror the existing cfg token and cfg tenant
// patterns. The bind-cert/certs/revoke-cert/rotate-cert verbs mirror cfg webauthn,
// including the --force guard on destructive actions.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	accountAPIURL string

	// Lifecycle verb flags
	accountUsername    string
	accountTenantID    string
	accountRootScope   bool
	accountPermissions []string
	accountDisabled    string // "true" or "false"; empty means not set
	accountJSONOutput  bool
	accountForce       bool

	// Cert-binding verb flags
	accountCertSerial      string
	accountCertFingerprint string
	accountCertLabel       string
	accountCertNewSerial   string
)

// accountCmd is the root command: cfg account ...
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage web-admin accounts and their certificate credentials",
	Long: `Manage web-admin account lifecycle and bound mTLS certificate credentials.

Account subcommands call the /api/v1/accounts REST endpoints. Cert subcommands
call the /api/v1/accounts/{username}/certs endpoints.

Subcommands:
  create      Create or reset a web-admin account
  list        List all web-admin accounts
  get         Get a single web-admin account
  update      Update account permissions or disabled state
  delete      Delete an account (offboarding cascade)

  bind-cert   Bind an mTLS certificate serial to an account
  certs       List bound mTLS certificates for an account
  revoke-cert Revoke and unbind an mTLS certificate from an account
  rotate-cert Atomically swap old certificate for a new one`,
}

// accountCreateCmd implements cfg account create.
var accountCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create or reset a web-admin account",
	Long: `Create a new web-admin account, or reset an existing one (upsert).

On creation a single-use enrollment magic link is printed. The link lets the
account's holder register their first passkey via the controller web UI.
The link is shown once and not stored in plaintext.

Examples:
  cfg account create --username alice
  cfg account create --username alice --tenant-id acme-corp
  cfg account create --username alice --root-scope
  cfg account create --username alice --permission account:list --permission account:get`,
	RunE: runAccountCreate,
}

// accountListCmd implements cfg account list.
var accountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List web-admin accounts",
	Long: `List all web-admin accounts visible to the caller's tenant scope.

Examples:
  cfg account list
  cfg account list --json`,
	RunE: runAccountList,
}

// accountGetCmd implements cfg account get.
var accountGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Get a web-admin account",
	Long: `Get account identity and status for a single web-admin account.
Returns tenant_id, root_scope, permissions, disabled state, and whether
an outstanding enrollment link exists.

Examples:
  cfg account get alice
  cfg account get alice --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountGet,
}

// accountUpdateCmd implements cfg account update.
var accountUpdateCmd = &cobra.Command{
	Use:   "update <username>",
	Short: "Update a web-admin account",
	Long: `Update account permissions and/or disabled state.

All fields are optional — omitted flags retain existing values.

Examples:
  cfg account update alice --permission account:list --permission account:get
  cfg account update alice --disabled=true
  cfg account update alice --disabled=false`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountUpdate,
}

// accountDeleteCmd implements cfg account delete.
var accountDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a web-admin account",
	Long: `Delete a web-admin account via the offboarding cascade:
disable → revoke bound certificates → revoke sessions → delete.

This is irreversible. Use --force to skip the interactive confirmation prompt.

Examples:
  cfg account delete alice
  cfg account delete alice --force`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountDelete,
}

// accountBindCertCmd implements cfg account bind-cert.
var accountBindCertCmd = &cobra.Command{
	Use:   "bind-cert <username>",
	Short: "Bind an mTLS certificate to an account",
	Long: `Bind a certificate serial to a web-admin account.

The serial must be a 1-40 character alphanumeric string (matching CFGMS-issued
and common external CA serial formats). A serial can be bound to at most one
account at a time.

Examples:
  cfg account bind-cert alice --serial 12345
  cfg account bind-cert alice --serial 12345 --label "primary laptop"`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountBindCert,
}

// accountCertsCmd implements cfg account certs.
var accountCertsCmd = &cobra.Command{
	Use:   "certs <username>",
	Short: "List bound mTLS certificates for an account",
	Long: `List all mTLS certificate bindings for a web-admin account.

Examples:
  cfg account certs alice
  cfg account certs alice --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAccountCerts,
}

// accountRevokeCertCmd implements cfg account revoke-cert.
var accountRevokeCertCmd = &cobra.Command{
	Use:   "revoke-cert <username> <serial>",
	Short: "Revoke and unbind an mTLS certificate from an account",
	Long: `Revoke an mTLS certificate via the controller CA, then remove the binding.

This is irreversible — the certificate is added to the CRL and will be rejected
on all subsequent admin mTLS connections. Use --force to skip the interactive
confirmation prompt.

Examples:
  cfg account revoke-cert alice 12345
  cfg account revoke-cert alice 12345 --force`,
	Args: cobra.ExactArgs(2),
	RunE: runAccountRevokeCert,
}

// accountRotateCertCmd implements cfg account rotate-cert.
var accountRotateCertCmd = &cobra.Command{
	Use:   "rotate-cert <username> <old_serial>",
	Short: "Atomically rotate an mTLS certificate binding",
	Long: `Bind a new certificate serial and revoke the old one in a single resumable operation.

The operation is safe to retry: if interrupted between binding the new serial
and revoking the old one, a repeated call with the same arguments completes
the rotation without a second bind or a second revocation attempt.

Examples:
  cfg account rotate-cert alice 12345 --new-serial 67890
  cfg account rotate-cert alice 12345 --new-serial 67890 --force`,
	Args: cobra.ExactArgs(2),
	RunE: runAccountRotateCert,
}

func init() {
	accountCmd.PersistentFlags().StringVar(&accountAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")

	// create flags
	accountCreateCmd.Flags().StringVar(&accountUsername, "username", "", "Account username (required)")
	accountCreateCmd.Flags().StringVar(&accountTenantID, "tenant-id", "", "Tenant ID for the new account")
	accountCreateCmd.Flags().BoolVar(&accountRootScope, "root-scope", false, "Grant cross-tenant root scope (mutually exclusive with --tenant-id)")
	accountCreateCmd.Flags().StringArrayVar(&accountPermissions, "permission", nil, "Permission to grant (repeatable)")
	accountCreateCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")
	_ = accountCreateCmd.MarkFlagRequired("username")

	// list flags
	accountListCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")

	// get flags
	accountGetCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")

	// update flags
	accountUpdateCmd.Flags().StringArrayVar(&accountPermissions, "permission", nil, "Permission to set (repeatable; replaces existing set)")
	accountUpdateCmd.Flags().StringVar(&accountDisabled, "disabled", "", "Set disabled state: true or false")
	accountUpdateCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")

	// delete flags
	accountDeleteCmd.Flags().BoolVar(&accountForce, "force", false, "Skip confirmation prompt")

	// bind-cert flags
	accountBindCertCmd.Flags().StringVar(&accountCertSerial, "serial", "", "Certificate serial number (required)")
	accountBindCertCmd.Flags().StringVar(&accountCertFingerprint, "fingerprint", "", "Certificate fingerprint (optional; stored for audit correlation)")
	accountBindCertCmd.Flags().StringVar(&accountCertLabel, "label", "", "Human-readable label for the binding")
	_ = accountBindCertCmd.MarkFlagRequired("serial")

	// certs flags
	accountCertsCmd.Flags().BoolVar(&accountJSONOutput, "json", false, "Emit JSON output")

	// revoke-cert flags
	accountRevokeCertCmd.Flags().BoolVar(&accountForce, "force", false, "Skip confirmation prompt")

	// rotate-cert flags
	accountRotateCertCmd.Flags().StringVar(&accountCertNewSerial, "new-serial", "", "New certificate serial number (required)")
	accountRotateCertCmd.Flags().StringVar(&accountCertFingerprint, "fingerprint", "", "New certificate fingerprint (optional; stored for audit correlation)")
	accountRotateCertCmd.Flags().BoolVar(&accountForce, "force", false, "Skip confirmation prompt")
	_ = accountRotateCertCmd.MarkFlagRequired("new-serial")

	accountCmd.AddCommand(accountCreateCmd)
	accountCmd.AddCommand(accountListCmd)
	accountCmd.AddCommand(accountGetCmd)
	accountCmd.AddCommand(accountUpdateCmd)
	accountCmd.AddCommand(accountDeleteCmd)
	accountCmd.AddCommand(accountBindCertCmd)
	accountCmd.AddCommand(accountCertsCmd)
	accountCmd.AddCommand(accountRevokeCertCmd)
	accountCmd.AddCommand(accountRotateCertCmd)
}

// getAccountClient returns an APIClient for account commands.
func getAccountClient() (*APIClient, error) {
	apiURL := accountAPIURL
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

// confirmDestructive prompts the user for confirmation unless --force is set.
// Returns nil when the action should proceed, or an error to abort.
//
// The answer is read from cmd.InOrStdin(), which resolves to os.Stdin for the real
// command tree and to a caller-supplied reader when a test drives the command — so
// the prompt path itself is exercisable rather than short-circuited.
func confirmDestructive(cmd *cobra.Command, prompt string, force bool) error {
	if force {
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N]: ", prompt)
	var response string
	_, _ = fmt.Fscan(cmd.InOrStdin(), &response)
	if strings.ToLower(strings.TrimSpace(response)) != "y" {
		return fmt.Errorf("aborted")
	}
	return nil
}

// --- request/response types mirroring the server-side structs ---

// apiAccountCreateRequest mirrors api.AccountRequest.
type apiAccountCreateRequest struct {
	Username    string   `json:"username"`
	TenantID    string   `json:"tenant_id,omitempty"`
	RootScope   bool     `json:"root_scope,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// apiAccountUpdateRequest mirrors api.AccountUpdateRequest.
type apiAccountUpdateRequest struct {
	Permissions *[]string `json:"permissions"`
	Disabled    *bool     `json:"disabled"`
}

// apiAccountInfo mirrors api.AccountInfo.
type apiAccountInfo struct {
	ID                           string   `json:"id"`
	Username                     string   `json:"username"`
	TenantID                     string   `json:"tenant_id"`
	RootScope                    bool     `json:"root_scope"`
	Permissions                  []string `json:"permissions"`
	Disabled                     bool     `json:"disabled"`
	CreatedAt                    string   `json:"created_at"`
	HasOutstandingEnrollmentLink bool     `json:"has_outstanding_enrollment_link"`
}

// apiAccountCreateResponse mirrors api.AccountCreateResponse.
type apiAccountCreateResponse struct {
	apiAccountInfo
	EnrollmentMagicLink string `json:"enrollment_magic_link,omitempty"`
}

// apiCertBindingInfo mirrors api.CertBindingInfo.
// LastUsedAt is empty when the server omits last_used_at — a binding that has never
// authenticated (Issue #3715). Display code must render that as an explicit "never"
// value, not a blank line.
type apiCertBindingInfo struct {
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
	BoundAt     string `json:"bound_at"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
}

// certBindingLastUsedDisplay renders a binding's LastUsedAt for human-readable output,
// making the never-used state explicit rather than printing a blank value.
func certBindingLastUsedDisplay(lastUsedAt string) string {
	if lastUsedAt == "" {
		return "never"
	}
	return lastUsedAt
}

// apiBindCertRequest mirrors api.BindCertRequest.
type apiBindCertRequest struct {
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Label       string `json:"label,omitempty"`
}

// apiRotateCertRequest mirrors api.RotateCertRequest.
type apiRotateCertRequest struct {
	Serial      string `json:"serial"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// --- API client methods ---

// AccountCreate calls POST /api/v1/accounts.
func (c *APIClient) AccountCreate(ctx context.Context, req *apiAccountCreateRequest) (*apiAccountCreateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/accounts", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result apiAccountCreateResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode account data: %w", err)
	}
	return &result, nil
}

// AccountList calls GET /api/v1/accounts.
func (c *APIClient) AccountList(ctx context.Context) ([]apiAccountInfo, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/accounts", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var accounts []apiAccountInfo
	if err := json.Unmarshal(envelope.Data, &accounts); err != nil {
		return nil, fmt.Errorf("failed to decode account list: %w", err)
	}
	return accounts, nil
}

// AccountGet calls GET /api/v1/accounts/{username}.
func (c *APIClient) AccountGet(ctx context.Context, username string) (*apiAccountInfo, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/accounts/"+url.PathEscape(username), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("account not found: %s", username)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var account apiAccountInfo
	if err := json.Unmarshal(envelope.Data, &account); err != nil {
		return nil, fmt.Errorf("failed to decode account data: %w", err)
	}
	return &account, nil
}

// AccountUpdate calls PUT /api/v1/accounts/{username}.
func (c *APIClient) AccountUpdate(ctx context.Context, username string, req *apiAccountUpdateRequest) (*apiAccountCreateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "PUT", "/api/v1/accounts/"+url.PathEscape(username), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("account not found: %s", username)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result apiAccountCreateResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode account data: %w", err)
	}
	return &result, nil
}

// AccountDelete calls DELETE /api/v1/accounts/{username}.
func (c *APIClient) AccountDelete(ctx context.Context, username string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/api/v1/accounts/"+url.PathEscape(username), nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("account not found: %s", username)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}
	return nil
}

// AccountBindCert calls POST /api/v1/accounts/{username}/certs/bind.
func (c *APIClient) AccountBindCert(ctx context.Context, username string, req *apiBindCertRequest) (*apiCertBindingInfo, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequest(ctx, "POST", "/api/v1/accounts/"+url.PathEscape(username)+"/certs/bind", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var result apiCertBindingInfo
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to decode binding data: %w", err)
	}
	return &result, nil
}

// AccountListCerts calls GET /api/v1/accounts/{username}/certs.
func (c *APIClient) AccountListCerts(ctx context.Context, username string) ([]apiCertBindingInfo, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/accounts/"+url.PathEscape(username)+"/certs", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("account not found: %s", username)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	var bindings []apiCertBindingInfo
	if err := json.Unmarshal(envelope.Data, &bindings); err != nil {
		return nil, fmt.Errorf("failed to decode cert bindings: %w", err)
	}
	return bindings, nil
}

// AccountRevokeCert calls POST /api/v1/accounts/{username}/certs/revoke/{serial}.
func (c *APIClient) AccountRevokeCert(ctx context.Context, username, serial string) error {
	path := "/api/v1/accounts/" + url.PathEscape(username) + "/certs/revoke/" + url.PathEscape(serial)
	resp, err := c.doRequest(ctx, "POST", path, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("account or certificate binding not found")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.parseError(resp)
	}
	return nil
}

// AccountRotateCert calls POST /api/v1/accounts/{username}/certs/rotate/{old_serial}.
func (c *APIClient) AccountRotateCert(ctx context.Context, username, oldSerial string, req *apiRotateCertRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	path := "/api/v1/accounts/" + url.PathEscape(username) + "/certs/rotate/" + url.PathEscape(oldSerial)
	resp, err := c.doRequest(ctx, "POST", path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("account or old certificate binding not found")
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}
	return nil
}

// --- command handlers ---

func runAccountCreate(cmd *cobra.Command, args []string) error {
	if accountUsername == "" {
		return fmt.Errorf("--username is required")
	}
	if accountRootScope && accountTenantID != "" {
		return fmt.Errorf("--root-scope and --tenant-id are mutually exclusive")
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	req := &apiAccountCreateRequest{
		Username:    accountUsername,
		TenantID:    accountTenantID,
		RootScope:   accountRootScope,
		Permissions: accountPermissions,
	}

	result, err := client.AccountCreate(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account provisioned: %s\n", result.Username)
	printAccountInfo(cmd, &result.apiAccountInfo)
	if result.EnrollmentMagicLink != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n  Enrollment link: %s\n", result.EnrollmentMagicLink)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  (shown once — share with the account holder via a secure channel)\n")
	}
	return nil
}

func runAccountList(cmd *cobra.Command, args []string) error {
	client, err := getAccountClient()
	if err != nil {
		return err
	}

	accounts, err := client.AccountList(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list accounts: %w", err)
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(accounts)
	}

	if len(accounts) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No accounts found.")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Accounts (%d):\n\n", len(accounts))
	for i, a := range accounts {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [%d] %s\n", i+1, a.Username)
		if a.TenantID != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Tenant:      %s\n", a.TenantID)
		} else if a.RootScope {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Scope:       root\n")
		}
		if a.Disabled {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Disabled:    true\n")
		}
		if len(a.Permissions) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Permissions: %s\n", strings.Join(a.Permissions, ", "))
		}
		if a.HasOutstandingEnrollmentLink {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Enrollment:  link outstanding\n")
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func runAccountGet(cmd *cobra.Command, args []string) error {
	username := args[0]
	client, err := getAccountClient()
	if err != nil {
		return err
	}

	acct, err := client.AccountGet(context.Background(), username)
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(acct)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account: %s\n", acct.Username)
	printAccountInfo(cmd, acct)
	return nil
}

func runAccountUpdate(cmd *cobra.Command, args []string) error {
	username := args[0]

	req := &apiAccountUpdateRequest{}

	if len(accountPermissions) > 0 {
		perms := accountPermissions
		req.Permissions = &perms
	}

	if accountDisabled != "" {
		switch accountDisabled {
		case "true":
			b := true
			req.Disabled = &b
		case "false":
			b := false
			req.Disabled = &b
		default:
			return fmt.Errorf("--disabled must be 'true' or 'false'")
		}
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	result, err := client.AccountUpdate(context.Background(), username, req)
	if err != nil {
		return fmt.Errorf("failed to update account: %w", err)
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account updated: %s\n", result.Username)
	printAccountInfo(cmd, &result.apiAccountInfo)
	return nil
}

func runAccountDelete(cmd *cobra.Command, args []string) error {
	username := args[0]

	if err := confirmDestructive(cmd,
		fmt.Sprintf("Delete account %q and revoke all bound certificates and sessions?", username),
		accountForce); err != nil {
		return err
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	if err := client.AccountDelete(context.Background(), username); err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Account deleted: %s\n", username)
	return nil
}

func runAccountBindCert(cmd *cobra.Command, args []string) error {
	username := args[0]

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	req := &apiBindCertRequest{
		Serial:      accountCertSerial,
		Fingerprint: accountCertFingerprint,
		Label:       accountCertLabel,
	}

	binding, err := client.AccountBindCert(context.Background(), username, req)
	if err != nil {
		return fmt.Errorf("failed to bind certificate: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate bound to %s\n", username)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Serial:   %s\n", binding.Serial)
	if binding.Fingerprint != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint: %s\n", binding.Fingerprint)
	}
	if binding.Label != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Label:    %s\n", binding.Label)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Bound at: %s\n", binding.BoundAt)
	return nil
}

func runAccountCerts(cmd *cobra.Command, args []string) error {
	username := args[0]

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	bindings, err := client.AccountListCerts(context.Background(), username)
	if err != nil {
		return fmt.Errorf("failed to list certificate bindings: %w", err)
	}

	if accountJSONOutput {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(bindings)
	}

	if len(bindings) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No certificate bindings for %s.\n", username)
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate bindings for %s (%d):\n\n", username, len(bindings))
	for i, b := range bindings {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [%d] Serial:   %s\n", i+1, b.Serial)
		if b.Fingerprint != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Fingerprint: %s\n", b.Fingerprint)
		}
		if b.Label != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Label:    %s\n", b.Label)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Bound at: %s\n", b.BoundAt)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "      Last used: %s\n", certBindingLastUsedDisplay(b.LastUsedAt))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func runAccountRevokeCert(cmd *cobra.Command, args []string) error {
	username := args[0]
	serial := args[1]

	if err := confirmDestructive(cmd,
		fmt.Sprintf("Revoke certificate %q bound to account %q? (this is irreversible)", serial, username),
		accountForce); err != nil {
		return err
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	if err := client.AccountRevokeCert(context.Background(), username, serial); err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate revoked: %s (account: %s)\n", serial, username)
	return nil
}

func runAccountRotateCert(cmd *cobra.Command, args []string) error {
	username := args[0]
	oldSerial := args[1]

	// Rotation revokes the old serial through the CA and adds it to the CRL —
	// irreversible, exactly like revoke-cert, so it takes the same guard.
	if err := confirmDestructive(cmd,
		fmt.Sprintf("Rotate account %q from certificate %q to %q? The old certificate is revoked (this is irreversible)",
			username, oldSerial, accountCertNewSerial),
		accountForce); err != nil {
		return err
	}

	client, err := getAccountClient()
	if err != nil {
		return err
	}

	req := &apiRotateCertRequest{
		Serial:      accountCertNewSerial,
		Fingerprint: accountCertFingerprint,
	}

	if err := client.AccountRotateCert(context.Background(), username, oldSerial, req); err != nil {
		return fmt.Errorf("failed to rotate certificate: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate rotated for %s\n", username)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Old serial: %s (revoked)\n", oldSerial)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  New serial: %s (bound)\n", accountCertNewSerial)
	return nil
}

// printAccountInfo writes the standard account info block to cmd's output.
func printAccountInfo(cmd *cobra.Command, a *apiAccountInfo) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  ID:          %s\n", a.ID)
	if a.TenantID != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Tenant:      %s\n", a.TenantID)
	} else if a.RootScope {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Scope:       root\n")
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Disabled:    %v\n", a.Disabled)
	if len(a.Permissions) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Permissions: %s\n", strings.Join(a.Permissions, ", "))
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Created:     %s\n", a.CreatedAt)
	if a.HasOutstandingEnrollmentLink {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Enrollment:  link outstanding\n")
	}
}
