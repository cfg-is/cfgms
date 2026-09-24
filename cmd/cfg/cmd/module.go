// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"errors"
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

	moduleListStatus string
	moduleListJSON   bool

	moduleApproveContentHash string
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

  # List pending modules
  cfg module list --status pending

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

The controller's cache is content-addressed, so more than one distinct bundle can
be pending under the same publisher/name@version — the publisher name of an
unverified bundle is self-asserted manifest data. A reference matching several
pending bundles is therefore rejected, listing each candidate content hash;
re-run with --content-hash to name the exact bundle that was reviewed. The
approved content hash is echoed on success so the confirmation binds to specific
content, not to a mutable triple.

This command requires admin mTLS authentication via an admin bundle file.

Examples:
  cfg module approve cfgms/hyperv@0.2.1
  cfg module approve acme-corp/custom-module@1.3.0
  cfg module approve cfgms/hyperv@0.2.1 --content-hash sha256:9f2c4a1b...`,
	Args: cobra.ExactArgs(1),
	RunE: runModuleApprove,
}

func init() {
	moduleCmd.PersistentFlags().StringVar(&moduleAPIURL, "api-url", "", "Controller REST API URL (env: CFGMS_API_URL)")
	moduleCmd.PersistentFlags().StringVar(&moduleTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	moduleCmd.PersistentFlags().BoolVar(&moduleTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only)")
	moduleCmd.PersistentFlags().StringVar(&moduleServerName, "server-name", "", "Override TLS server name for certificate verification")

	moduleListCmd.Flags().StringVar(&moduleListStatus, "status", "", "Filter by approval status: pending, approved, or rejected")
	moduleListCmd.Flags().BoolVar(&moduleListJSON, "json", false, "Emit JSON output instead of human-readable table")

	moduleApproveCmd.Flags().StringVar(&moduleApproveContentHash, "content-hash", "",
		"Content hash (full value or unambiguous prefix) selecting which pending bundle to approve; required when a reference matches more than one")

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

// moduleCacheEntry mirrors one entry of the JSON response from GET /api/v1/modules.
type moduleCacheEntry struct {
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
	Status      string `json:"status"`
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

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	var result moduleListResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return fmt.Errorf("failed to decode module list data: %w", err)
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

// moduleApprovalQueueEntry mirrors one entry of the "pending" array returned by
// GET /api/v1/modules/approvals (features/controller/api's moduleApprovalEntry).
type moduleApprovalQueueEntry struct {
	Address     string `json:"address"`
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
}

type moduleApprovalQueueResponse struct {
	Pending []moduleApprovalQueueEntry `json:"pending"`
}

// urlSafeHashToStandard maps the URL-safe base64 alphabet used in composite
// addresses and cache directory names back to the standard alphabet.
var urlSafeHashToStandard = strings.NewReplacer("_", "/", "-", "+")

// normalizeContentHash puts a content hash into one comparable form so an
// operator can paste either rendering they were shown: the raw standard-base64
// value from `cfg module list`, or the URL-safe value embedded in a composite
// address. Standard base64 never contains _ or -, and the URL-safe alphabet never
// contains / or +, so this cannot make two distinct hashes compare equal.
// Trailing = padding is dropped because the URL-safe rendering strips it.
func normalizeContentHash(hash string) string {
	return strings.TrimRight(urlSafeHashToStandard.Replace(hash), "=")
}

// selectPendingApproval resolves a publisher/name@version reference against the
// controller's pending queue to exactly one bundle.
//
// The module cache is content-addressed — its key includes the content hash — so
// the triple is NOT unique: several distinct bundles can sit in the queue under
// the same publisher/name@version. Picking one of them (e.g. the first the
// controller listed) would let content chosen by whoever produced the second
// bundle receive an approval the operator granted to the bundle they reviewed,
// and approval authorizes a signed binary to execute on every targeted endpoint.
// That is reachable because an unknown publisher is queued for review before any
// signature is verified, making the publisher name self-asserted at that point.
// So an ambiguous reference is an error naming every candidate, and contentHash
// (full value, or a prefix unique within the candidate set) is the selector that
// resolves it (Issue #4270).
func selectPendingApproval(pending []moduleApprovalQueueEntry, publisher, name, version, contentHash string) (moduleApprovalQueueEntry, error) {
	wantHash := normalizeContentHash(contentHash)

	matches := make([]moduleApprovalQueueEntry, 0, 1)
	for _, entry := range pending {
		if entry.Publisher != publisher || entry.Name != name || entry.Version != version {
			continue
		}
		if wantHash != "" && !strings.HasPrefix(normalizeContentHash(entry.ContentHash), wantHash) {
			continue
		}
		matches = append(matches, entry)
	}

	ref := publisher + "/" + name + "@" + version

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if contentHash != "" {
			return moduleApprovalQueueEntry{}, fmt.Errorf(
				"module %s with content hash %q not found in pending approval queue", ref, contentHash)
		}
		return moduleApprovalQueueEntry{}, fmt.Errorf("module %s not found in pending approval queue", ref)
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "module %s matches %d pending bundles; re-run with --content-hash to select one:",
			ref, len(matches))
		for _, m := range matches {
			fmt.Fprintf(&b, "\n  %s", m.ContentHash)
		}
		if contentHash != "" {
			fmt.Fprintf(&b, "\n(content hash %q is a prefix of more than one candidate)", contentHash)
		}
		return moduleApprovalQueueEntry{}, errors.New(b.String())
	}
}

func runModuleApprove(cmd *cobra.Command, args []string) error {
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

	// Only a queued (pending) bundle can be approved (NOT_PENDING otherwise), and
	// GET /api/v1/modules/approvals already returns exactly that set — so resolve
	// the ref against it and approve by its composite address, rather than
	// guessing an address client-side (Issue #4270).
	resp, err := client.doRequest(context.Background(), http.MethodGet, "/api/v1/modules/approvals", nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned %s: %s", resp.Status, string(body))
	}

	// Unwrap APIResponse envelope: {"data": {...}, "timestamp": "..."}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	var queue moduleApprovalQueueResponse
	if err := json.Unmarshal(envelope.Data, &queue); err != nil {
		return fmt.Errorf("failed to decode pending approval queue: %w", err)
	}

	target, err := selectPendingApproval(queue.Pending, publisher, name, version, moduleApproveContentHash)
	if err != nil {
		return err
	}

	// POST /api/v1/modules/approvals/{address}/approve
	// url.PathEscape closes path-injection sinks (CWE-918); the address itself
	// comes from the controller's own queue response, not user input.
	approvePath := "/api/v1/modules/approvals/" + url.PathEscape(target.Address) + "/approve"

	approveResp, err := client.doRequest(context.Background(), http.MethodPost, approvePath, nil)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = approveResp.Body.Close() }()

	if approveResp.StatusCode != http.StatusOK && approveResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(approveResp.Body)
		return fmt.Errorf("controller returned %s: %s", approveResp.Status, string(body))
	}

	// Echo the content hash: approval is a decision about content, and the ref
	// alone does not identify which bundle was authorized.
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "module approved: %s (content hash: %s)\n", ref, target.ContentHash)
	return err
}

// shortHash returns the first 12 characters of a hash for display purposes.
func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "..."
}
