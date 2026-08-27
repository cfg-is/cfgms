// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// moduleRefRE validates "publisher/name@version" module references.
// Allows alphanumerics, dots, hyphens, and underscores in each component.
var moduleRefRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$`)

var (
	moduleAPIURL      string
	moduleTLSCACert   string
	moduleTLSInsecure bool
	moduleServerName  string

	moduleListTenant string
	moduleListStatus string
	moduleListJSON   bool
)

// moduleCmd is the parent command for module management operations.
var moduleCmd = &cobra.Command{
	Use:   "module",
	Short: "Manage modules in the controller cache",
	Long: `Manage the controller's module cache and approval queue.

Modules are fetched from configured git sources, verified, and staged in the
controller's content-addressed cache. Use these commands to inspect and manage
the approval state of cached module bundles.

This command communicates with the controller's REST API and requires an admin mTLS
bundle or an active session (cfg connect). The controller URL can be provided via
flags or environment variables:
  - CFGMS_API_URL: Controller REST API URL (default: http://localhost:9080)
  - CFGMS_ADMIN_BUNDLE: Path to the admin mTLS bundle
  - CFGMS_TLS_CA_CERT: Path to CA certificate for TLS verification
  - CFGMS_TLS_INSECURE: Skip TLS verification (development only)

Examples:
  # List all modules in the cache
  cfg module list

  # List pending modules for a specific tenant
  cfg module list --tenant root/msp-a --status pending

  # Approve a queued module
  cfg module approve cfgms/hyperv@0.2.1`,
}

// moduleListCmd lists cached modules with their approval status.
var moduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cached modules and their approval status",
	Long: `List all modules in the controller module cache.

The --status flag filters the output:
  pending   — modules awaiting admin approval (QueueForReview)
  approved  — modules approved and available for steward delivery
  rejected  — modules rejected due to signature verification failure

Examples:
  cfg module list
  cfg module list --status pending
  cfg module list --tenant root/msp-a
  cfg module list --status approved --json`,
	RunE: runModuleList,
}

// moduleApproveCmd promotes a queued module to approved.
var moduleApproveCmd = &cobra.Command{
	Use:   "approve <publisher>/<name>@<version>",
	Short: "Approve a queued module",
	Long: `Approve a module that is queued for review.

The module reference must be in the form publisher/name@version, for example:
  cfgms/hyperv@0.2.1

Only modules in "pending" state (QueueForReview) can be approved. Modules that
are already approved or rejected return an error.

This command requires admin mTLS authentication via an admin bundle file.

Examples:
  cfg module approve cfgms/hyperv@0.2.1
  cfg module approve acme-corp/custom-module@1.3.0`,
	Args: cobra.ExactArgs(1),
	RunE: runModuleApprove,
}

func init() {
	moduleCmd.PersistentFlags().StringVar(&moduleAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	moduleCmd.PersistentFlags().StringVar(&moduleTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	moduleCmd.PersistentFlags().BoolVar(&moduleTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	moduleCmd.PersistentFlags().StringVar(&moduleServerName, "server-name", "", "Override TLS server name for certificate verification")

	moduleListCmd.Flags().StringVar(&moduleListTenant, "tenant", "", "Filter by tenant path (e.g. root/msp-a); default shows all tenants")
	moduleListCmd.Flags().StringVar(&moduleListStatus, "status", "", "Filter by approval status: pending, approved, or rejected")
	moduleListCmd.Flags().BoolVar(&moduleListJSON, "json", false, "Emit JSON output instead of human-readable table")

	moduleCmd.AddCommand(moduleListCmd)
	moduleCmd.AddCommand(moduleApproveCmd)
}

func getModuleAPIClient() (*APIClient, error) {
	apiURL := moduleAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := moduleTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := moduleServerName

	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

// moduleCacheEntry mirrors the JSON response from GET /api/v1/modules.
type moduleCacheEntry struct {
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
	Status      string `json:"status"`
	TenantID    string `json:"tenant_id,omitempty"`
}

type moduleListResponse struct {
	Modules []moduleCacheEntry `json:"modules"`
	Total   int                `json:"total"`
}

func runModuleList(cmd *cobra.Command, _ []string) error {
	if moduleListStatus != "" {
		allowed := map[string]bool{"pending": true, "approved": true, "rejected": true}
		if !allowed[moduleListStatus] {
			return fmt.Errorf("invalid --status %q: must be pending, approved, or rejected", moduleListStatus)
		}
	}

	client, err := getModuleAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Build query string.
	params := url.Values{}
	if moduleListTenant != "" {
		params.Set("tenant", moduleListTenant)
	}
	if moduleListStatus != "" {
		params.Set("status", moduleListStatus)
	}

	path := "/api/v1/modules"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := client.doRequest(context.Background(), http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(body))
	}

	var result moduleListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if moduleListJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result.Modules)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "PUBLISHER\tNAME\tVERSION\tSTATUS\tCONTENT HASH"); err != nil {
		return err
	}
	for _, m := range result.Modules {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			m.Publisher, m.Name, m.Version, m.Status, shortHash(m.ContentHash)); err != nil {
			return err
		}
	}
	return w.Flush()
}

func runModuleApprove(_ *cobra.Command, args []string) error {
	ref := args[0]
	if !moduleRefRE.MatchString(ref) {
		return fmt.Errorf("invalid module reference %q: must match publisher/name@version (alphanumerics, dots, hyphens, underscores only)", ref)
	}

	// Split ref into publisher/name and version.
	atIdx := strings.LastIndex(ref, "@")
	namespacedName := ref[:atIdx]
	version := ref[atIdx+1:]
	slashIdx := strings.Index(namespacedName, "/")
	publisher := namespacedName[:slashIdx]
	name := namespacedName[slashIdx+1:]

	client, err := getModuleAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// POST /api/v1/modules/{publisher}/{name}/{version}/approve
	// url.PathEscape on each component closes path-injection sinks (CWE-918);
	// defense-in-depth with the moduleRefRE validation above.
	path := fmt.Sprintf("/api/v1/modules/%s/%s/%s/approve",
		url.PathEscape(publisher), url.PathEscape(name), url.PathEscape(version))

	resp, err := client.doRequest(context.Background(), http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(body))
	}

	fmt.Printf("module approved: %s\n", ref)
	return nil
}

// shortHash returns the first 12 characters of a hash for display purposes.
func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "..."
}
