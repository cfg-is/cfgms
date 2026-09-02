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

// hypervProfileEnrollFile is the enroll block shape read from --file YAML.
type hypervProfileEnrollFile struct {
	RegistrationTokenSecretKey string `yaml:"registration_token_secret_key" json:"registration_token_secret_key,omitempty"`
	BundleURL                  string `yaml:"bundle_url" json:"bundle_url,omitempty"`
	CorrelationLabel           string `yaml:"correlation_label" json:"correlation_label,omitempty"`
}

// hypervProfileFile is the YAML shape read from --file for `cfg hyperv profile
// create`. It mirrors hyperv.UnattendProfile's authorable fields (name is taken
// from the positional argument, not this file — the key name is authoritative,
// mirroring ConfigBackedProfileStore.GetProfile's own tolerance of an omitted
// stored Name).
type hypervProfileFile struct {
	OSFamily     string                  `yaml:"os_family" json:"os_family"`
	AnswerFormat string                  `yaml:"answer_format" json:"answer_format"`
	Template     string                  `yaml:"template" json:"template"`
	Enroll       hypervProfileEnrollFile `yaml:"enroll" json:"enroll,omitempty"`
}

// hypervProfileInfo is the shape returned by the hyperv-profile REST endpoints.
type hypervProfileInfo struct {
	Name         string                  `json:"name"`
	OSFamily     string                  `json:"os_family"`
	AnswerFormat string                  `json:"answer_format"`
	Template     string                  `json:"template"`
	Enroll       hypervProfileEnrollFile `json:"enroll,omitempty"`
}

var (
	hypervProfileURL         string
	hypervProfileTLSCACert   string
	hypervProfileTLSInsecure bool
	hypervProfileServerName  string

	// hypervProfileTenant targets a specific tenant. Hyperv profiles are stored
	// per tenant, so a global/root admin must name the tenant explicitly; a
	// tenant-scoped caller is pinned to its own tenant and this flag is ignored
	// (mirrors --tenant on `cfg role`, Issue #2548).
	hypervProfileTenant string

	// create flags
	hypervProfileFilePath string
)

// hypervProfileTenantQuery returns the "?tenant=<id>" query suffix when
// --tenant is set, or "" otherwise.
func hypervProfileTenantQuery() string {
	if hypervProfileTenant == "" {
		return ""
	}
	return "?tenant=" + url.QueryEscape(hypervProfileTenant)
}

// hypervCmd is the parent command: cfg hyperv ...
var hypervCmd = &cobra.Command{
	Use:   "hyperv",
	Short: "Manage Hyper-V VM provisioning resources on the controller",
}

// hypervProfileCmd is the parent command: cfg hyperv profile ...
var hypervProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage Hyper-V VM-provisioning profiles on the controller",
	Long: `Create, list, show, and delete unattended-install profiles stored under
hyperv-profiles/<name>. A stored profile is rendered and executed as root by
cloud-init/preseed at guest first boot, so create and delete require an admin
session at strong assurance with a fresh user-presence proof.

Supported sub-commands: create, ls, show, delete`,
}

// hypervProfileCreateCmd implements cfg hyperv profile create <name> --file <file>.
var hypervProfileCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a Hyper-V VM-provisioning profile",
	Long: `Create a Hyper-V VM-provisioning profile from a YAML file.

The file must contain os_family, answer_format, template, and an optional
enroll block (see docs/operations/hyperv-profile-authoring.md). The profile is
validated server-side (name, answer_format, that the template parses, and a
size cap) before it is stored — an invalid profile is rejected immediately.

Examples:
  cfg hyperv profile create debian-12-acme-corp --file profile.yaml \
    --url https://controller.example.com --bundle /path/to/admin.bundle.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runHypervProfileCreate,
}

// hypervProfileLsCmd implements cfg hyperv profile ls.
var hypervProfileLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List Hyper-V VM-provisioning profiles",
	Long: `List all Hyper-V VM-provisioning profiles for the authenticated tenant.

Examples:
  cfg hyperv profile ls --url https://controller.example.com --bundle /path/to/admin.bundle.yaml`,
	RunE: runHypervProfileLs,
}

// hypervProfileShowCmd implements cfg hyperv profile show <name>.
var hypervProfileShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a Hyper-V VM-provisioning profile",
	Long: `Display a Hyper-V VM-provisioning profile including its template and enroll wiring.

Examples:
  cfg hyperv profile show debian-12-acme-corp --url https://controller.example.com --bundle /path/to/admin.bundle.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runHypervProfileShow,
}

// hypervProfileDeleteCmd implements cfg hyperv profile delete <name>.
var hypervProfileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a Hyper-V VM-provisioning profile",
	Long: `Delete a Hyper-V VM-provisioning profile by name.

Examples:
  cfg hyperv profile delete debian-12-acme-corp --url https://controller.example.com --bundle /path/to/admin.bundle.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runHypervProfileDelete,
}

func init() {
	commonFlags := []*cobra.Command{hypervProfileCreateCmd, hypervProfileLsCmd, hypervProfileShowCmd, hypervProfileDeleteCmd}
	for _, cmd := range commonFlags {
		cmd.Flags().StringVar(&hypervProfileURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
		cmd.Flags().StringVar(&hypervProfileTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		cmd.Flags().BoolVar(&hypervProfileTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		cmd.Flags().StringVar(&hypervProfileServerName, "server-name", "", "Override TLS server name for certificate verification")
		cmd.Flags().StringVar(&hypervProfileTenant, "tenant", "", "Target tenant ID (required for a global admin; ignored for a tenant-scoped caller)")
	}

	hypervProfileCreateCmd.Flags().StringVar(&hypervProfileFilePath, "file", "", "Path to profile YAML file (required)")
	_ = hypervProfileCreateCmd.MarkFlagRequired("file")

	hypervProfileCmd.AddCommand(hypervProfileCreateCmd)
	hypervProfileCmd.AddCommand(hypervProfileLsCmd)
	hypervProfileCmd.AddCommand(hypervProfileShowCmd)
	hypervProfileCmd.AddCommand(hypervProfileDeleteCmd)
	hypervCmd.AddCommand(hypervProfileCmd)
	rootCmd.AddCommand(hypervCmd)
}

// getHypervProfileClient returns an API client for hyperv-profile commands,
// mirroring getRoleClient.
func getHypervProfileClient() (*APIClient, error) {
	apiURL := hypervProfileURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := hypervProfileTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := hypervProfileServerName

	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

func runHypervProfileCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// #nosec G304 -- hypervProfileFilePath is an explicit local CLI flag; reading
	// the operator-selected profile file is the create command's purpose.
	fileBytes, err := os.ReadFile(hypervProfileFilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile file %q: %w", hypervProfileFilePath, err)
	}

	var pf hypervProfileFile
	if err := yaml.Unmarshal(fileBytes, &pf); err != nil {
		return fmt.Errorf("failed to parse profile YAML: %w", err)
	}

	payload := map[string]interface{}{
		"name":          name,
		"os_family":     pf.OSFamily,
		"answer_format": pf.AnswerFormat,
		"template":      pf.Template,
		"enroll":        pf.Enroll,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client, err := getHypervProfileClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/hyperv/profiles"+hypervProfileTenantQuery(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create failed (%s): %s", resp.Status, string(respBody))
	}

	var apiResp struct {
		Data hypervProfileInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created hyperv profile %q (os_family: %s, answer_format: %s)\n",
		apiResp.Data.Name, apiResp.Data.OSFamily, apiResp.Data.AnswerFormat)
	return nil
}

func runHypervProfileLs(cmd *cobra.Command, _ []string) error {
	client, err := getHypervProfileClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/hyperv/profiles"+hypervProfileTenantQuery())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("list failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			Profiles []string `json:"profiles"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Data.Profiles) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No hyperv profiles found.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME")
	_, _ = fmt.Fprintln(w, "----")
	for _, name := range apiResp.Data.Profiles {
		_, _ = fmt.Fprintln(w, name)
	}
	return w.Flush()
}

func runHypervProfileShow(cmd *cobra.Command, args []string) error {
	name := url.PathEscape(args[0])

	client, err := getHypervProfileClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/hyperv/profiles/"+name+hypervProfileTenantQuery())
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("hyperv profile %q not found", args[0])
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("show failed (%s): %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data hypervProfileInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	p := apiResp.Data
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Name:         %s\n", p.Name)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OSFamily:     %s\n", p.OSFamily)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "AnswerFormat: %s\n", p.AnswerFormat)
	if p.Enroll.RegistrationTokenSecretKey != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "EnrollTokenSecretKey: %s\n", p.Enroll.RegistrationTokenSecretKey)
	}
	if p.Enroll.BundleURL != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "EnrollBundleURL:      %s\n", p.Enroll.BundleURL)
	}
	if p.Enroll.CorrelationLabel != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "EnrollCorrelationLabel: %s\n", p.Enroll.CorrelationLabel)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Template:\n%s\n", p.Template)
	return nil
}

func runHypervProfileDelete(cmd *cobra.Command, args []string) error {
	name := url.PathEscape(args[0])

	client, err := getHypervProfileClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodDelete, "/api/v1/hyperv/profiles/"+name+hypervProfileTenantQuery(), nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("hyperv profile %q not found", args[0])
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed (%s): %s", resp.Status, string(body))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted hyperv profile %q\n", args[0])
	return nil
}
