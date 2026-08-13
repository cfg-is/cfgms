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
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// roleConfig is the shape stored and returned by the role-config REST endpoints.
type roleConfig struct {
	Name      string          `json:"name"`
	TenantID  string          `json:"tenant_id,omitempty"`
	Selector  string          `json:"selector"`
	Fragment  json.RawMessage `json:"fragment"`
	CreatedAt string          `json:"created_at,omitempty"`
	CreatedBy string          `json:"created_by,omitempty"`
}

var (
	roleURL         string
	roleAPIKey      string
	roleTLSCACert   string
	roleTLSInsecure bool
	roleServerName  string

	// roleTenant targets a specific tenant. Role configs are stored per tenant, so
	// a global/root admin must name the tenant explicitly; a tenant-scoped caller
	// is pinned to its own tenant and this flag is ignored (Issue #2548).
	roleTenant string

	// create flags
	roleSelector   string
	roleConfigFile string
)

// roleTenantQuery returns the "?tenant=<id>" query suffix when --tenant is set,
// or "" otherwise. Used by every role sub-command so a root admin can target a
// tenant (the controller pins tenant-scoped callers to their own tenant).
func roleTenantQuery() string {
	if roleTenant == "" {
		return ""
	}
	return "?tenant=" + url.QueryEscape(roleTenant)
}

// roleCmd is the parent command: cfg role ...
var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Manage role configs on the controller",
	Long: `Create, list, show, and delete role configs stored on the controller.

A role config couples a selector expression with a StewardConfig fragment.
During config resolution (S4) matching stewards receive the fragment merged
into their effective config.

Supported sub-commands: create, ls, show, delete`,
}

// roleCreateCmd implements cfg role create <name> --selector <expr> --config <file>.
var roleCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a role config",
	Long: `Create a role config with a selector and a StewardConfig fragment file.

The selector expression uses the same syntax as 'cfg steward select'.
The config file must be a YAML file containing a StewardConfig fragment
(partial config — steward ID is not required).

Examples:
  cfg role create github-runners \
    --selector "os:windows tag:github-runner" \
    --config fragment.yaml \
    --url https://controller.example.com --api-key mykey`,
	Args: cobra.ExactArgs(1),
	RunE: runRoleCreate,
}

// roleLsCmd implements cfg role ls.
var roleLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List role configs",
	Long: `List all role configs for the authenticated tenant.

Examples:
  cfg role ls --url https://controller.example.com --api-key mykey`,
	RunE: runRoleLs,
}

// roleShowCmd implements cfg role show <name>.
var roleShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a role config",
	Long: `Display a role config including its selector and fragment.

Examples:
  cfg role show github-runners --url https://controller.example.com --api-key mykey`,
	Args: cobra.ExactArgs(1),
	RunE: runRoleShow,
}

// roleDeleteCmd implements cfg role delete <name>.
var roleDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a role config",
	Long: `Delete a role config by name.

Examples:
  cfg role delete github-runners --url https://controller.example.com --api-key mykey`,
	Args: cobra.ExactArgs(1),
	RunE: runRoleDelete,
}

func init() {
	commonFlags := []*cobra.Command{roleCreateCmd, roleLsCmd, roleShowCmd, roleDeleteCmd}
	for _, cmd := range commonFlags {
		cmd.Flags().StringVar(&roleURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
		cmd.Flags().StringVar(&roleAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
		cmd.Flags().StringVar(&roleTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		cmd.Flags().BoolVar(&roleTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		cmd.Flags().StringVar(&roleTenant, "tenant", "", "Target tenant ID (required for a global admin; ignored for a tenant-scoped caller)")
	}

	roleCreateCmd.Flags().StringVar(&roleSelector, "selector", "", "Selector expression (required)")
	roleCreateCmd.Flags().StringVar(&roleConfigFile, "config", "", "Path to StewardConfig fragment YAML file (required)")
	_ = roleCreateCmd.MarkFlagRequired("selector")
	_ = roleCreateCmd.MarkFlagRequired("config")

	roleCmd.AddCommand(roleCreateCmd)
	roleCmd.AddCommand(roleLsCmd)
	roleCmd.AddCommand(roleShowCmd)
	roleCmd.AddCommand(roleDeleteCmd)
	rootCmd.AddCommand(roleCmd)
}

// getRoleClient returns an API client for role commands, mirroring the
// getControllerClient / getScriptLibClient pattern.
func getRoleClient() (*APIClient, error) {
	apiURL := roleURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := roleTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := roleServerName

	client, err := resolveSessionOrBundleClient(apiURL, tlsInsecure, serverName)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := roleAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsCACertPath := roleTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

func runRoleCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// #nosec G304 -- roleConfigFile is an explicit local CLI flag; reading the
	// operator-selected role fragment is the create command's purpose.
	fragmentBytes, err := os.ReadFile(roleConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %q: %w", roleConfigFile, err)
	}

	// Decode the YAML fragment into a generic map so it round-trips through
	// JSON without requiring the full StewardConfig type here.
	var fragmentMap interface{}
	if err := yaml.Unmarshal(fragmentBytes, &fragmentMap); err != nil {
		return fmt.Errorf("failed to parse config fragment YAML: %w", err)
	}

	fragmentJSON, err := json.Marshal(fragmentMap)
	if err != nil {
		return fmt.Errorf("failed to convert config fragment to JSON: %w", err)
	}

	payload := map[string]interface{}{
		"name":     name,
		"selector": roleSelector,
		"fragment": json.RawMessage(fragmentJSON),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client, err := getRoleClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/roles"+roleTenantQuery(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create failed (%s): %s", resp.Status, string(respBody))
	}

	var apiResp struct {
		Data roleConfig `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created role config %q (selector: %s)\n", apiResp.Data.Name, apiResp.Data.Selector)
	return nil
}

func runRoleLs(cmd *cobra.Command, _ []string) error {
	client, err := getRoleClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/roles"+roleTenantQuery())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("list failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []roleConfig `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Data) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No role configs found.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tSELECTOR\tCREATED BY")
	_, _ = fmt.Fprintln(w, "----\t--------\t----------")
	for _, rc := range apiResp.Data {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", rc.Name, rc.Selector, rc.CreatedBy)
	}
	return w.Flush()
}

func runRoleShow(cmd *cobra.Command, args []string) error {
	name := url.PathEscape(args[0])

	client, err := getRoleClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/roles/"+name+roleTenantQuery())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("role config %q not found", args[0])
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("show failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data roleConfig `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	rc := apiResp.Data
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Name:      %s\n", rc.Name)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Selector:  %s\n", rc.Selector)
	if rc.CreatedBy != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CreatedBy: %s\n", rc.CreatedBy)
	}
	if rc.CreatedAt != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CreatedAt: %s\n", rc.CreatedAt)
	}
	fragJSON, _ := json.MarshalIndent(rc.Fragment, "", "  ")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Fragment:\n%s\n", string(fragJSON))
	return nil
}

func runRoleDelete(cmd *cobra.Command, args []string) error {
	name := url.PathEscape(args[0])

	client, err := getRoleClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodDelete, "/api/v1/roles/"+name+roleTenantQuery(), nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("role config %q not found", args[0])
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed (%s): %s", resp.Status, string(body))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted role config %q\n", args[0])
	return nil
}
