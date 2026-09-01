// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/spf13/cobra"
)

const (
	// operatorEnvelopeExpiry bounds the validity window of a client-signed
	// operator command envelope (Issue #3694). Inline commands execute
	// immediately, so a short, fixed window is deliberate — it is not a
	// user-configurable flag.
	operatorEnvelopeExpiry = 5 * time.Minute

	// operatorNonceBytes is the raw byte length of a generated envelope nonce,
	// before hex-encoding. Must be at least 16 per Issue #3694's AC.
	operatorNonceBytes = 16
)

var (
	stewardURL              string
	stewardTLSCACert        string
	stewardTLSInsecure      bool
	stewardServerName       string
	stewardStatusJSONOutput bool
	stewardDNAAttribute     string
	stewardDNAJSONOutput    bool
	stewardModulesJSON      bool
)

var (
	stewardLogsTail   int
	stewardLogsSince  string
	stewardLogsLevel  string
	stewardLogsModule string
	stewardLogsJSON   bool
)

var stewardMoveToTenant string

var (
	stewardMoveJSONOutput         bool
	stewardDecommissionJSONOutput bool
)

// stewardYes is the persistent --yes/-y flag shared across the steward command
// tree. It suppresses the multi-host confirmation prompt for mutating verbs but
// never suppresses the 0-match fail-fast error (see confirmMultiHost).
var stewardYes bool

// stewardCmd is the parent command for steward subcommands.
var stewardCmd = &cobra.Command{
	Use:   "steward",
	Short: "Manage registered stewards",
	Long: `Commands for inspecting and managing stewards registered with the controller.

Every subcommand accepts the same selector grammar. See docs/administration/cli-selectors.md
for the full grammar reference, per-shell quoting rules, and worked examples.

Quick reference:
  web-01              exact hostname match (case-insensitive)
  'web-*'             hostname glob (must quote to prevent shell expansion)
  acme-corp/web-01    host in a child tenant (/ or \ separator, both accepted)
  os:linux            attribute filter (os, platform, arch, tag, dna.<key>)
  'os:linux tag:prod' AND composition (space-separated terms, must quote)
  id:steward-abc123   exact steward ID
  all                 every steward in the caller's authorized subtree`,
}

// stewardListCmd lists stewards registered with the controller.
// An optional selector argument limits output to matching stewards via
// POST /api/v1/fleet/resolve; without an argument the full fleet is listed
// via GET /api/v1/stewards (backward compatible).
var stewardListCmd = &cobra.Command{
	Use:   "list [selector]",
	Short: "List registered stewards",
	Long: `Display stewards registered with the controller.

Without a selector, prints the full fleet via GET /api/v1/stewards.
With a selector, resolves matching stewards via POST /api/v1/fleet/resolve
and prints only those that match. A selector that matches no stewards is an
error; use "all" to match every steward in the caller's authorized subtree.

Use this command as the dry-run before any mutating verb — it is read-only.

Examples:
  # List all stewards
  cfg steward list

  # Exact hostname match (no quotes needed for a bare hostname)
  cfg steward list web-01

  # Hostname glob (must quote so the shell does not expand *)
  cfg steward list 'web-*'

  # Exact hostname in a child tenant
  cfg steward list acme-corp/web-01

  # Glob in a child tenant (must quote: contains both / and *)
  cfg steward list 'acme-corp/web-*'

  # Attribute filters
  cfg steward list os:linux
  cfg steward list 'os:linux arch:amd64'
  cfg steward list 'os:linux tag:prod'
  cfg steward list 'dna.role:db'

  # All stewards in a child tenant
  cfg steward list acme-corp/all

  # Whole fleet
  cfg steward list all`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStewardList,
}

// ---------------------------------------------------------------------------
// Package-level variables for steward run subcommands.
// ---------------------------------------------------------------------------

var (
	stewardRunTarget       string
	stewardRunScript       string
	stewardRunVersion      string
	stewardRunParams       []string
	stewardRunWait         bool
	stewardRunSkipOffline  bool
	stewardRunWaitTimeout  time.Duration
	stewardRunShell        string
	stewardRunResultDevice string
)

// Package-level vars for steward exec. Declared separately from run-command
// vars so the two commands cannot share state.
var (
	stewardExecCommand    string
	stewardExecShell      string
	stewardExecTimeout    time.Duration
	stewardExecJSONOutput bool
)

var (
	stewardRunScriptJSONOutput  bool
	stewardRunCommandJSONOutput bool
)

// runWaitPollInterval is the delay between status polls in the --wait loop.
// Overridable in tests to avoid real sleeps.
var runWaitPollInterval = 5 * time.Second

// ---------------------------------------------------------------------------
// Run subcommand definitions
// ---------------------------------------------------------------------------

var stewardRunScriptCmd = &cobra.Command{
	Use:   "run-script",
	Short: "Run a library script against matching stewards",
	Long: `Submit a library script to matching stewards and return a run ID.

Exits immediately (async) by default. Use --wait to block until completion.

Examples:
  # Exact hostname target (bare token, no quotes needed)
  cfg steward run-script --target web-01 --script my-script

  # Hostname glob — all hosts starting with 'web-' (must quote)
  cfg steward run-script --target 'web-*' --script my-script --yes

  # Child-tenant scope (forward slash, no quotes needed for exact name)
  cfg steward run-script --target acme-corp/web-01 --script my-script

  # Attribute filter
  cfg steward run-script --target os:linux --script my-script

  # Wait for completion with a custom timeout
  cfg steward run-script --target 'os:linux tag:prod' --script my-script --version v2 --wait --wait-timeout 10m`,
	RunE: runRunScript,
}

var stewardRunCommandCmd = &cobra.Command{
	Use:   "run-command <inline-content-or-file>",
	Short: "Run an inline command against matching stewards",
	Long: `Sign and submit an inline command or script file to matching stewards.

The argument is treated as a file path if the path exists on disk; otherwise
it is used as the inline script body. Content is base64-encoded and signed with
the operator's mTLS bundle key before transmission.

Requires an admin bundle with a private key (--bundle or CFGMS_ADMIN_BUNDLE).

Examples:
  # Inline command to a single host by bare hostname
  cfg steward run-command --shell bash --target web-01 "echo hello"

  # Inline command to a hostname glob (must quote glob; requires --yes)
  cfg steward run-command --shell bash --target 'web-*' "echo hello" --yes

  # Script file to a child-tenant host (forward slash, no quotes needed)
  cfg steward run-command --shell bash --target acme-corp/web-01 ./scripts/deploy.sh

  # Attribute filter
  cfg steward run-command --shell bash --target os:linux ./scripts/deploy.sh --yes`,
	Args: cobra.ExactArgs(1),
	RunE: runRunCommand,
}

var stewardExecCmd = &cobra.Command{
	Use:   "exec <selector>",
	Short: "Execute an ad-hoc command on matching stewards",
	Long: `Sign and submit an inline command to matching stewards and display the result.

The argument is a selector identifying which stewards to target — a bare
hostname, id:, glob, or attribute filter. The command is submitted as a signed
inline script and dispatched to every steward the selector matches.
The CLI blocks until all jobs reach a terminal state or the timeout elapses.

Requires an admin bundle with a private key (--bundle or CFGMS_ADMIN_BUNDLE).

The --shell flag is required. Allowed values: bash, sh, pwsh (cmd on Windows as fallback).

Output is capped at 64 KB per steward in the CLI display. If the output for a
steward exceeds the cap a truncation warning is printed to stderr.

Examples:
  # Exact hostname (bare token) — single-host, no confirmation prompt
  cfg steward exec web-01 --command "hostname" --shell bash

  # Hostname glob — fan out to all hosts starting with 'web-' (must quote; requires --yes)
  cfg steward exec 'web-*' --command "uptime" --shell bash --yes

  # Exact hostname in a child tenant
  cfg steward exec acme-corp/web-01 --command "uname -r" --shell bash

  # Glob in a child tenant with tenant-path scoping (must quote)
  cfg steward exec 'acme-corp/web-*' --command "df -h" --shell bash --yes

  # Attribute filter: all Linux stewards (requires --yes)
  cfg steward exec os:linux --command "uname -r" --shell bash --yes

  # Explicit steward ID
  cfg steward exec id:steward-abc123 --command "uptime" --shell bash --timeout 30s

  # JSON output keyed by hostname#steward-id
  cfg steward exec web-01 --command "uptime" --shell bash --json`,
	Args: cobra.ExactArgs(1),
	RunE: runRunCommandSingle,
}

var stewardRunStatusCmd = &cobra.Command{
	Use:   "run-status <run-id>",
	Short: "Show status of a run",
	Long: `Display the status and job counts for a run.

Examples:
  cfg steward run-status 550e8400-e29b-41d4-a716-446655440000`,
	Args: cobra.ExactArgs(1),
	RunE: runRunStatus,
}

var stewardRunResultCmd = &cobra.Command{
	Use:   "run-result <run-id>",
	Short: "Show job output for a run",
	Long: `Display per-steward job details for a completed or in-progress run.

Use --device to filter output to a single steward.

Examples:
  cfg steward run-result 550e8400-e29b-41d4-a716-446655440000
  cfg steward run-result 550e8400-e29b-41d4-a716-446655440000 --device steward-abc`,
	Args: cobra.ExactArgs(1),
	RunE: runRunResult,
}

var stewardRunCancelCmd = &cobra.Command{
	Use:   "run-cancel <run-id>",
	Short: "Cancel a run",
	Long: `Cancel all pending and running jobs within a run.

Examples:
  cfg steward run-cancel 550e8400-e29b-41d4-a716-446655440000`,
	Args: cobra.ExactArgs(1),
	RunE: runRunCancel,
}

// stewardMoveCmd moves one or more stewards to a different tenant via the controller REST API.
var stewardMoveCmd = &cobra.Command{
	Use:   "move <selector>",
	Short: "Move matching stewards to a different tenant",
	Long: `Move one or more stewards to a different tenant.

The selector is resolved against the fleet before any mutation occurs. A selector
that matches more than one steward triggers the --yes confirmation gate; a
single-match selector proceeds without prompting.

Post-move, each steward is subject to the DESTINATION tenant's refresh policy and
module/publisher trust configuration. Trust is never resolved from the old
(source-tenant, device-key) pair — identity continuity is preserved while the
trust context changes immediately to the destination tenant.

Requires an admin bundle with mTLS access (Tier-3 endpoint).

Examples:
  # Exact hostname (bare token) — single-host, no confirmation prompt
  cfg steward move web-01 --to-tenant dest-tenant

  # Exact hostname in a child tenant
  cfg steward move acme-corp/web-01 --to-tenant acme-corp/us-east

  # Hostname glob — all hosts starting with 'web-' (must quote; requires --yes)
  cfg steward move 'acme-corp/web-*' --to-tenant acme-corp/us-east --yes

  # All stewards in a child tenant (requires --yes)
  cfg steward move acme-corp/all --to-tenant acme-corp/us-east --yes

  # Attribute filter with JSON output
  cfg steward move os:linux --to-tenant dest-tenant --yes --json`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardMove,
}

// stewardDecommissionCmd permanently decommissions one or more stewards from the fleet.
var stewardDecommissionCmd = &cobra.Command{
	Use:   "decommission <selector>",
	Short: "Decommission matching stewards from the fleet",
	Long: `Mark one or more stewards as deregistered after their hosts or VMs have been torn down.

The selector is resolved against the fleet before any mutation occurs. A selector
that matches more than one steward triggers the --yes confirmation gate; a
single-match selector proceeds without prompting.

Requires an admin mTLS certificate. Records are retained in durable storage
for audit but no longer appear in cfg steward list. Any active connections are dropped.

Examples:
  # Exact hostname (bare token) — single-host, no confirmation prompt
  cfg steward decommission web-01

  # Exact hostname in a child tenant
  cfg steward decommission acme-corp/web-01

  # Hostname glob — all hosts starting with 'decom-' (must quote; requires --yes)
  cfg steward decommission 'decom-*' --yes

  # Tag filter — all stewards carrying the 'decom' tag (requires --yes)
  cfg steward decommission 'tag:decom' --yes

  # All stewards in a child tenant with JSON output (requires --yes)
  cfg steward decommission acme-corp/all --yes --json`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardDecommission,
}

func runStewardDecommission(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	if err := confirmMultiHost(matches, stewardYes); err != nil {
		return err
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			resp, err := client.doRequest(ctx, http.MethodDelete, "/api/v1/stewards/"+s.ID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to decommission steward: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			switch resp.StatusCode {
			case http.StatusOK:
				return json.RawMessage(`{"status":"decommissioned"}`), nil
			case http.StatusNotFound:
				return nil, fmt.Errorf("steward %s not found", s.ID)
			case http.StatusForbidden:
				return nil, fmt.Errorf("decommission requires an admin mTLS certificate")
			case http.StatusServiceUnavailable:
				return nil, fmt.Errorf("fleet store unavailable; retry later")
			default:
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}
		})

	if stewardDecommissionJSONOutput {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			// Multi-host: print per-steward errors to stderr so partial failures
			// are visible while the generic overallErr signals the non-zero exit.
			// Single-host: skip printing here; the specific error is returned below.
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}
		fmt.Printf("Steward %s decommissioned.\n", m.ID)
	}

	// For single-host failure, surface the specific per-steward error from RunE
	// (cobra prints it) — preserves the pre-selector single-ID error semantics.
	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

// stewardLogsCmd pulls recent log entries from one or more stewards via the controller REST API.
var stewardLogsCmd = &cobra.Command{
	Use:   "logs <selector>",
	Short: "Pull recent log entries from stewards matching a selector",
	Long: `Pull recent log entries from the controller's log-pull endpoint for every steward the selector matches.

Note: Log pull is not yet available. Collect logs directly from the steward host.

Examples:
  # Exact hostname (bare token, no quotes needed)
  cfg steward logs web-01

  # Exact hostname in a child tenant
  cfg steward logs acme-corp/web-01

  # Hostname glob — all hosts starting with 'web-' (must quote)
  cfg steward logs 'web-*' --tail 20

  # Attribute filter with options
  cfg steward logs os:linux --tail 50 --level WARN

  # Single host with time filter
  cfg steward logs web-01 --since 1h --module file`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardLogs,
}

func runStewardMove(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	if err := confirmMultiHost(matches, stewardYes); err != nil {
		return err
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			reqBody, err := json.Marshal(map[string]string{"new_tenant_id": stewardMoveToTenant})
			if err != nil {
				return nil, fmt.Errorf("failed to encode request: %w", err)
			}

			resp, err := client.doRequest(ctx, http.MethodPost, "/api/v1/stewards/"+s.ID+"/move", bytes.NewReader(reqBody))
			if err != nil {
				return nil, fmt.Errorf("failed to move steward: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
				}
			}()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}

			switch resp.StatusCode {
			case http.StatusForbidden:
				return nil, fmt.Errorf("move denied: insufficient scope to move steward %s to tenant %s", s.ID, stewardMoveToTenant)
			case http.StatusNotFound:
				return nil, fmt.Errorf("steward %s not found", s.ID)
			case http.StatusOK:
				// handled below
			default:
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}

			var apiResp struct {
				Data struct {
					StewardID      string `json:"steward_id"`
					TenantID       string `json:"tenant_id"`
					PreviousTenant string `json:"previous_tenant"`
					Status         string `json:"status"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &apiResp); err != nil {
				return nil, fmt.Errorf("failed to parse response: %w", err)
			}

			payload, err := json.Marshal(apiResp.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal result: %w", err)
			}
			return payload, nil
		})

	if stewardMoveJSONOutput {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			// Multi-host: print per-steward errors to stderr so partial failures
			// are visible while the generic overallErr signals the non-zero exit.
			// Single-host: skip printing here; the specific error is returned below.
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}

		var d struct {
			StewardID      string `json:"steward_id"`
			TenantID       string `json:"tenant_id"`
			PreviousTenant string `json:"previous_tenant"`
			Status         string `json:"status"`
		}
		if err := json.Unmarshal(r.Payload, &d); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: failed to parse result: %v\n", key, err)
			continue
		}

		switch d.Status {
		case "no_change":
			fmt.Printf("Steward %s is already in tenant %s (no change)\n", m.ID, d.TenantID)
		case "moved":
			fmt.Printf("Steward %s moved to tenant %s (was: %s)\n", m.ID, d.TenantID, d.PreviousTenant)
		default:
			fmt.Printf("Steward %s: status=%s tenant=%s\n", m.ID, d.Status, d.TenantID)
		}
	}

	// For single-host failure, surface the specific per-steward error from RunE
	// (cobra prints it) — preserves the pre-selector single-ID error semantics.
	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

// logsNotImplementedPayload is the sentinel returned by the fan-out action when a
// steward reports 501 (log pull not yet available). It lets the output phase
// distinguish "not implemented" from a genuine read failure without forcing a
// non-zero exit — matching the pre-selector single-ID behaviour.
var logsNotImplementedPayload = json.RawMessage(`{"status":"not_implemented"}`)

func runStewardLogs(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	v := url.Values{}
	v.Set("tail", fmt.Sprintf("%d", stewardLogsTail))
	if stewardLogsSince != "" {
		v.Set("since", stewardLogsSince)
	}
	if stewardLogsLevel != "" {
		v.Set("level", stewardLogsLevel)
	}
	if stewardLogsModule != "" {
		v.Set("module", stewardLogsModule)
	}
	queryStr := v.Encode()

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			path := "/api/v1/stewards/" + s.ID + "/logs?" + queryStr
			resp, err := client.Get(ctx, path)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch logs: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
				}
			}()

			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("steward %s not found", s.ID)
			}
			if resp.StatusCode == http.StatusNotImplemented {
				return logsNotImplementedPayload, nil
			}
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}
			return body, nil
		})

	if stewardLogsJSON {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}

		if len(matches) > 1 {
			fmt.Printf("=== %s ===\n", key)
		}

		var statusCheck struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(r.Payload, &statusCheck) == nil && statusCheck.Status == "not_implemented" {
			fmt.Println("Log pull not yet available for this steward. Collect logs directly from the host.")
			continue
		}

		var apiResp struct {
			Lines []struct {
				Timestamp string `json:"timestamp"`
				Level     string `json:"level"`
				Module    string `json:"module"`
				Message   string `json:"message"`
			} `json:"lines"`
		}
		if err := json.Unmarshal(r.Payload, &apiResp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: failed to parse response: %v\n", key, err)
			continue
		}

		for _, line := range apiResp.Lines {
			fmt.Printf("%s [%s] [%s] %s\n", line.Timestamp, line.Level, line.Module, line.Message)
		}
	}

	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

func init() {
	stewardListCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardListCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardListCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	stewardListCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")

	stewardStatusCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardStatusCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardStatusCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	stewardStatusCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardStatusCmd.Flags().BoolVar(&stewardStatusJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	stewardDNACmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardDNACmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardDNACmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	stewardDNACmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardDNACmd.Flags().StringVar(&stewardDNAAttribute, "attribute", "", "Return a single attribute value by key (for scripted probes)")
	stewardDNACmd.Flags().BoolVar(&stewardDNAJSONOutput, "json", false, "Emit JSON output instead of human-readable text")

	// run-script flags
	stewardRunScriptCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunScriptCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunScriptCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunScriptCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunTarget, "target", "", "Fleet selector (e.g. os:linux, group:prod)")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunScript, "script", "", "Script ID from the controller library")
	stewardRunScriptCmd.Flags().StringVar(&stewardRunVersion, "version", "", "Script version (default: latest)")
	stewardRunScriptCmd.Flags().StringArrayVar(&stewardRunParams, "param", nil, "Parameter key=value (repeatable)")
	stewardRunScriptCmd.Flags().BoolVar(&stewardRunWait, "wait", false, "Block until all jobs reach terminal state")
	stewardRunScriptCmd.Flags().BoolVar(&stewardRunSkipOffline, "skip-offline", false, "Skip offline stewards instead of queuing for them")
	stewardRunScriptCmd.Flags().DurationVar(&stewardRunWaitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait when --wait is set")
	stewardRunScriptCmd.Flags().BoolVar(&stewardRunScriptJSONOutput, "json", false, "Emit keyed-by-steward JSON dispatch results (requires --target)")

	// run-command flags
	stewardRunCommandCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunCommandCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunCommandCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunCommandCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardRunCommandCmd.Flags().StringVar(&stewardRunTarget, "target", "", "Fleet selector (e.g. os:linux, group:prod)")
	stewardRunCommandCmd.Flags().StringVar(&stewardRunShell, "shell", "", "Shell to use (e.g. bash, sh, powershell)")
	stewardRunCommandCmd.Flags().StringArrayVar(&stewardRunParams, "param", nil, "Parameter key=value (repeatable)")
	stewardRunCommandCmd.Flags().BoolVar(&stewardRunWait, "wait", false, "Block until all jobs reach terminal state")
	stewardRunCommandCmd.Flags().BoolVar(&stewardRunSkipOffline, "skip-offline", false, "Skip offline stewards instead of queuing for them")
	stewardRunCommandCmd.Flags().DurationVar(&stewardRunWaitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait when --wait is set")
	stewardRunCommandCmd.Flags().BoolVar(&stewardRunCommandJSONOutput, "json", false, "Emit keyed-by-steward JSON dispatch results (requires --target)")

	// exec flags (single-steward ad-hoc run)
	stewardExecCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardExecCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardExecCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardExecCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardExecCmd.Flags().StringVar(&stewardExecCommand, "command", "", "Command to execute on the steward (inline string or file path)")
	stewardExecCmd.Flags().StringVar(&stewardExecShell, "shell", "", "Shell to use (bash, sh, pwsh)")
	stewardExecCmd.Flags().DurationVar(&stewardExecTimeout, "timeout", 30*time.Second, "Maximum time to wait for job completion")
	stewardExecCmd.Flags().BoolVar(&stewardExecJSONOutput, "json", false, "Emit JSON job record instead of plain output")

	// run-status flags
	stewardRunStatusCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunStatusCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunStatusCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunStatusCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")

	// run-result flags
	stewardRunResultCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunResultCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunResultCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunResultCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardRunResultCmd.Flags().StringVar(&stewardRunResultDevice, "device", "", "Filter output to a single device ID")

	// run-cancel flags
	stewardRunCancelCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardRunCancelCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardRunCancelCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardRunCancelCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")

	// modules flags
	stewardModulesCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardModulesCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardModulesCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	stewardModulesCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardModulesCmd.Flags().BoolVar(&stewardModulesJSON, "json", false, "Emit JSON output instead of human-readable text")

	// logs flags
	stewardLogsCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardLogsCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardLogsCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardLogsCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardLogsCmd.Flags().IntVar(&stewardLogsTail, "tail", 100, "Number of log lines to return (1-1000)")
	stewardLogsCmd.Flags().StringVar(&stewardLogsSince, "since", "", "Return logs from this duration ago (e.g. 1h, 30m)")
	stewardLogsCmd.Flags().StringVar(&stewardLogsLevel, "level", "", "Filter by log level (DEBUG, INFO, WARN, ERROR)")
	stewardLogsCmd.Flags().StringVar(&stewardLogsModule, "module", "", "Filter by module name")
	stewardLogsCmd.Flags().BoolVar(&stewardLogsJSON, "json", false, "Emit raw JSON output instead of human-readable text")

	// move flags (Issue #2342, #2444)
	stewardMoveCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardMoveCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardMoveCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardMoveCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardMoveCmd.Flags().StringVar(&stewardMoveToTenant, "to-tenant", "", "Destination tenant ID (required)")
	stewardMoveCmd.Flags().BoolVar(&stewardMoveJSONOutput, "json", false, "Emit keyed-by-steward JSON results")
	if err := stewardMoveCmd.MarkFlagRequired("to-tenant"); err != nil {
		panic(err)
	}

	// decommission flags (Issue #2408, #2444)
	stewardDecommissionCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardDecommissionCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
	stewardDecommissionCmd.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	stewardDecommissionCmd.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	stewardDecommissionCmd.Flags().BoolVar(&stewardDecommissionJSONOutput, "json", false, "Emit keyed-by-steward JSON results")

	// --yes/-y is a persistent flag on the steward command tree so it is
	// accepted (and inert where irrelevant) by every subcommand. Mutating
	// verbs call confirmMultiHost which checks this flag.
	stewardCmd.PersistentFlags().BoolVarP(&stewardYes, "yes", "y", false,
		"Skip confirmation prompts for multi-host mutating commands")

	stewardCmd.AddCommand(stewardListCmd)
	stewardCmd.AddCommand(stewardStatusCmd)
	stewardCmd.AddCommand(stewardDNACmd)
	stewardCmd.AddCommand(stewardModulesCmd)
	stewardCmd.AddCommand(stewardMoveCmd)
	stewardCmd.AddCommand(stewardDecommissionCmd)
	stewardCmd.AddCommand(stewardRunScriptCmd)
	stewardCmd.AddCommand(stewardRunCommandCmd)
	stewardCmd.AddCommand(stewardExecCmd)
	stewardCmd.AddCommand(stewardRunStatusCmd)
	stewardCmd.AddCommand(stewardRunResultCmd)
	stewardCmd.AddCommand(stewardRunCancelCmd)
	stewardCmd.AddCommand(stewardLogsCmd)

	// upgrade subcommands
	stewardUpgradeCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardUpgradeCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardUpgradeCmd.Flags().StringVar(&stewardUpgradeVersion, "version", "", "Target steward version (required)")
	stewardUpgradeCmd.Flags().StringVar(&stewardUpgradePlatform, "platform", "", "Target platform (e.g. linux, windows; auto-detected if omitted)")
	stewardUpgradeCmd.Flags().StringVar(&stewardUpgradeArch, "arch", "", "Target architecture (e.g. amd64, arm64; auto-detected if omitted)")
	stewardUpgradeCmd.Flags().BoolVar(&stewardUpgradeWait, "wait", false, "Block until all stewards reach a terminal state")
	stewardUpgradeCmd.Flags().DurationVar(&stewardUpgradeWaitTimeout, "wait-timeout", 2*time.Minute, "Maximum time to wait when --wait is set")
	stewardUpgradeCmd.Flags().BoolVar(&stewardUpgradeJSONOutput, "json", false, "Emit keyed-by-steward JSON dispatch results")

	stewardUpgradeStatusCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardUpgradeStatusCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardUpgradeStatusCmd.Flags().StringVar(&stewardUpgradeID, "upgrade-id", "", "Upgrade record ID to query directly")

	stewardUpgradeRollbackCmd.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
	stewardUpgradeRollbackCmd.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	stewardUpgradeRollbackCmd.Flags().StringVar(&stewardUpgradeID, "upgrade-id", "", "Upgrade record ID to roll back")
	stewardUpgradeRollbackCmd.Flags().StringVar(&stewardUpgradeToVersion, "to-version", "", "Target version to roll back to (optional; used with --upgrade-id)")

	stewardCmd.AddCommand(stewardUpgradeCmd)
	stewardUpgradeCmd.AddCommand(stewardUpgradeStatusCmd)
	stewardUpgradeCmd.AddCommand(stewardUpgradeRollbackCmd)

	// Refresh management subcommands (Issue #2097).
	stewardCmd.AddCommand(refreshCmd)
}

// getStewardClient creates an API client using an active session or an admin mTLS bundle.
func getStewardClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(stewardURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	tlsInsecure := stewardTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	serverName := stewardServerName

	return requireSessionOrBundleClient(apiURL, tlsInsecure, serverName)
}

// stewardEntry is a local representation of a steward from the API response.
type stewardEntry struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version"`
	DNA      *struct {
		Hostname string `json:"hostname"`
	} `json:"dna,omitempty"`
}

// stewardStatusCmd shows detailed status for every steward a selector matches.
var stewardStatusCmd = &cobra.Command{
	Use:   "status <selector>",
	Short: "Show detailed status for stewards matching a selector",
	Long: `Display full details for every steward the selector matches.

Prints labelled fields including id, status, last_seen, version, hostname, OS,
connection state, and other available metadata. With --json, emits a
keyed-by-steward JSON array (one entry per matched steward).

Examples:
  # Exact hostname match (bare token, no quotes needed)
  cfg steward status web-01

  # Exact hostname in a child tenant
  cfg steward status acme-corp/web-01

  # Hostname glob — all hosts starting with 'web-' (must quote)
  cfg steward status 'web-*'

  # Glob in a child tenant (must quote)
  cfg steward status 'acme-corp/web-*'

  # Attribute filter: all Linux stewards
  cfg steward status os:linux

  # Exact steward ID
  cfg steward status id:steward-abc123

  # JSON output keyed by hostname#steward-id
  cfg steward status 'os:linux tag:prod' --json

  # With explicit controller URL
  cfg steward status web-01 --url=https://controller.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardStatus,
}

// stewardDNACmd shows the DNA snapshot for every steward a selector matches.
var stewardDNACmd = &cobra.Command{
	Use:   "dna <selector>",
	Short: "Show DNA snapshot for stewards matching a selector",
	Long: `Display the most recent DNA snapshot for a steward registered with the controller.

Use --attribute to retrieve a single dotted-path attribute value for scripted probes.
Use --json to write the raw API response body to stdout.

Examples:
  # Exact hostname (bare token, no quotes needed)
  cfg steward dna web-01

  # Exact hostname in a child tenant
  cfg steward dna acme-corp/web-01

  # Hostname glob — all hosts starting with 'db-' (must quote)
  cfg steward dna 'db-*'

  # All Linux stewards in a child tenant
  cfg steward dna 'acme-corp/os:linux'

  # Show full DNA as raw JSON
  cfg steward dna web-01 --json

  # Retrieve a single attribute value (exits non-zero if not present)
  cfg steward dna web-01 --attribute os`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardDNA,
}

// stewardDNAInfo is a local representation of the DNA snapshot returned by the API.
type stewardDNAInfo struct {
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	CollectedAt  string            `json:"collected_at"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

func runStewardDNA(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			path := "/api/v1/stewards/" + s.ID + "/dna"
			if stewardDNAAttribute != "" {
				path += "?attribute=" + url.QueryEscape(stewardDNAAttribute)
			}

			resp, err := client.Get(ctx, path)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch steward DNA: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
				}
			}()

			if resp.StatusCode == http.StatusNotFound {
				if stewardDNAAttribute != "" {
					return nil, fmt.Errorf("attribute %q not found for steward %s", stewardDNAAttribute, s.ID)
				}
				return nil, fmt.Errorf("steward %s not found or has no DNA snapshot", s.ID)
			}
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}
			return body, nil
		})

	if stewardDNAJSONOutput {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}

		// --attribute: print "<key>: <value>" per steward in multi-match,
		// just "<value>" in single-match (backward compatible).
		if stewardDNAAttribute != "" {
			var attrResp struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(r.Payload, &attrResp); err != nil {
				fmt.Fprintf(os.Stderr, "error: %s: failed to parse attribute response: %v\n", key, err)
				continue
			}
			if len(matches) > 1 {
				fmt.Printf("%s: %s\n", key, attrResp.Value)
			} else {
				fmt.Println(attrResp.Value)
			}
			continue
		}

		if len(matches) > 1 {
			fmt.Printf("=== %s ===\n", key)
		}

		var apiResp struct {
			Data stewardDNAInfo `json:"data"`
		}
		if err := json.Unmarshal(r.Payload, &apiResp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: failed to parse response: %v\n", key, err)
			continue
		}

		d := apiResp.Data
		fmt.Printf("Hostname:      %s\n", d.Hostname)
		fmt.Printf("OS:            %s\n", d.OS)
		if d.Architecture != "" {
			fmt.Printf("Architecture:  %s\n", d.Architecture)
		}
		if d.CollectedAt != "" {
			fmt.Printf("CollectedAt:   %s\n", d.CollectedAt)
		}
		for k, v := range d.Attributes {
			fmt.Printf("%s=%s\n", k, v)
		}
	}

	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

// stewardModulesCmd lists modules currently loaded by every steward a selector matches.
var stewardModulesCmd = &cobra.Command{
	Use:   "modules <selector>",
	Short: "List modules loaded by stewards matching a selector",
	Long: `Display the modules currently loaded by every steward the selector matches.

Retrieves module data from each steward's DNA attributes reported to the controller.
When a steward does not report module data, a 501 response is returned and the
entry exits 0 with an informational message.

Examples:
  # Exact hostname (bare token, no quotes needed)
  cfg steward modules web-01

  # Exact hostname in a child tenant
  cfg steward modules acme-corp/web-01

  # Hostname glob — all hosts starting with 'db-' (must quote)
  cfg steward modules 'db-*'

  # All Linux stewards
  cfg steward modules os:linux

  # All stewards in a child tenant, JSON output
  cfg steward modules 'acme-corp/os:linux' --json

  # With explicit controller URL
  cfg steward modules web-01 --url=https://controller.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardModules,
}

// stewardStatusInfo is a local representation of a steward detail from the API response.
type stewardStatusInfo struct {
	ID              string            `json:"id"`
	Status          string            `json:"status"`
	LastSeen        time.Time         `json:"last_seen"`
	Version         string            `json:"version"`
	ConnectionState string            `json:"connection_state"`
	ActiveSessions  int               `json:"active_sessions"`
	TenantID        string            `json:"tenant_id,omitempty"`
	Group           string            `json:"group,omitempty"`
	Metrics         map[string]string `json:"metrics,omitempty"`
	DNA             *struct {
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"dna,omitempty"`
}

func runStewardStatus(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			resp, err := client.Get(ctx, "/api/v1/stewards/"+s.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch steward: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
				}
			}()

			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("steward %s not found", s.ID)
			}
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}
			return body, nil
		})

	if stewardStatusJSONOutput {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}

		if len(matches) > 1 {
			fmt.Printf("=== %s ===\n", key)
		}

		var apiResp struct {
			Data stewardStatusInfo `json:"data"`
		}
		if err := json.Unmarshal(r.Payload, &apiResp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: failed to parse result: %v\n", key, err)
			continue
		}

		s := apiResp.Data
		fmt.Printf("ID:               %s\n", s.ID)
		fmt.Printf("Status:           %s\n", s.Status)
		fmt.Printf("Connection:       %s\n", s.ConnectionState)
		lastSeen := ""
		if !s.LastSeen.IsZero() {
			lastSeen = s.LastSeen.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("Last Seen:        %s\n", lastSeen)
		fmt.Printf("Version:          %s\n", s.Version)
		if s.DNA != nil {
			fmt.Printf("Hostname:         %s\n", s.DNA.Hostname)
			fmt.Printf("OS:               %s\n", s.DNA.OS)
			if s.DNA.Architecture != "" {
				fmt.Printf("Architecture:     %s\n", s.DNA.Architecture)
			}
		}
		if s.TenantID != "" {
			fmt.Printf("Tenant ID:        %s\n", s.TenantID)
		}
		if s.Group != "" {
			fmt.Printf("Group:            %s\n", s.Group)
		}
	}

	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

// modulesNotImplementedPayload is the sentinel returned by the fan-out action
// when a steward reports 501 (module list not yet available). Mirrors the
// logsNotImplementedPayload pattern so the output phase can distinguish
// "not implemented" from a genuine read failure without forcing a non-zero exit.
var modulesNotImplementedPayload = json.RawMessage(`{"status":"not_implemented"}`)

func runStewardModules(_ *cobra.Command, args []string) error {
	selector := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}

	results, overallErr := fanOutConcurrent(context.Background(), matches,
		func(ctx context.Context, s StewardInfo) (json.RawMessage, error) {
			resp, err := client.Get(ctx, "/api/v1/stewards/"+s.ID+"/modules")
			if err != nil {
				return nil, fmt.Errorf("failed to fetch steward modules: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "failed to close response body: %v\n", err)
				}
			}()

			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("steward %s not found", s.ID)
			}
			if resp.StatusCode == http.StatusNotImplemented {
				return modulesNotImplementedPayload, nil
			}
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}
			return body, nil
		})

	if stewardModulesJSON {
		entries := keyedOutput(matches, results)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return err
		}
		return overallErr
	}

	for _, m := range matches {
		key := stewardKey(m)
		r := results[key]
		if r.Err != nil {
			if len(matches) > 1 {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", key, r.Err)
			}
			continue
		}

		if len(matches) > 1 {
			fmt.Printf("=== %s ===\n", key)
		}

		var statusCheck struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(r.Payload, &statusCheck) == nil && statusCheck.Status == "not_implemented" {
			fmt.Println("Module list not available for this steward. Upgrade the steward to a version that reports module DNA attributes.")
			continue
		}

		var apiResp struct {
			Data struct {
				Modules []struct {
					Name    string `json:"name"`
					Version string `json:"version,omitempty"`
				} `json:"modules"`
			} `json:"data"`
		}
		if err := json.Unmarshal(r.Payload, &apiResp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: failed to parse response: %v\n", key, err)
			continue
		}

		if len(apiResp.Data.Modules) == 0 {
			fmt.Println("No modules loaded.")
			continue
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "NAME\tVERSION"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "----\t-------"); err != nil {
			return err
		}
		for _, mod := range apiResp.Data.Modules {
			if _, err := fmt.Fprintf(w, "%s\t%s\n", mod.Name, mod.Version); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}

	if overallErr != nil && len(matches) == 1 {
		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
	}
	return overallErr
}

func runStewardList(cmd *cobra.Command, args []string) error {
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Selector path: resolve matching stewards via POST /api/v1/fleet/resolve.
	if len(args) > 0 {
		matches, err := resolveOrFailFast(context.Background(), client, args[0])
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "ID\tSTATUS\tVERSION\tLAST SEEN\tHOSTNAME"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "--\t------\t-------\t---------\t--------"); err != nil {
			return err
		}
		for _, s := range matches {
			hostname := ""
			if s.DNA != nil {
				hostname = s.DNA.Hostname
			}
			lastSeen := ""
			if !s.LastSeen.IsZero() {
				lastSeen = s.LastSeen.Format("2006-01-02 15:04:05")
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Status, s.Version, lastSeen, hostname); err != nil {
				return err
			}
		}
		return w.Flush()
	}

	// No-arg path: unchanged GET /api/v1/stewards behavior (backward compatible).
	resp, err := client.Get(context.Background(), "/api/v1/stewards")
	if err != nil {
		return fmt.Errorf("failed to fetch stewards: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []stewardEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Data) == 0 {
		fmt.Println("No stewards registered.")
		printPendingRegistrationCount(client)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tSTATUS\tVERSION\tLAST SEEN\tHOSTNAME"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "--\t------\t-------\t---------\t--------"); err != nil {
		return err
	}
	for _, s := range apiResp.Data {
		hostname := ""
		if s.DNA != nil {
			hostname = s.DNA.Hostname
		}
		lastSeen := ""
		if !s.LastSeen.IsZero() {
			lastSeen = s.LastSeen.Format("2006-01-02 15:04:05")
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Status, s.Version, lastSeen, hostname); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	printPendingRegistrationCount(client)
	return nil
}

// printPendingRegistrationCount appends a trailing pending-count line to the
// default `cfg steward list` output so a queued steward is distinguishable from
// one that never contacted the controller (Issue #3786). Best-effort: a caller
// without the registration:list-pending permission gets a 403 here, which is
// silently omitted rather than failing the whole command. A zero count is also
// omitted — the line exists to surface a backlog, not to announce its absence.
func printPendingRegistrationCount(client *APIClient) {
	pending, status, err := client.ListPendingRegistrationsWithHTTPStatus(context.Background())
	if err != nil || status != http.StatusOK || len(pending) == 0 {
		return
	}
	fmt.Printf("\n%d pending registration(s) — cfg registration pending\n", len(pending))
}

// ---------------------------------------------------------------------------
// Run subcommand types
// ---------------------------------------------------------------------------

// commandSignature holds the cryptographic signature embedded in run-command requests.
type commandSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`      // base64-encoded raw signature bytes
	PublicKey string `json:"public_key"` // cert PEM from the operator bundle
}

// runRecord mirrors the fields returned by GET /api/v1/runs/{run_id}.
type runRecord struct {
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	JobCount      int    `json:"job_count"`
	CompletedJobs int    `json:"completed_jobs"`
	FailedJobs    int    `json:"failed_jobs"`
}

// runJobRecord mirrors the fields returned by GET /api/v1/runs/{run_id}/jobs.
type runJobRecord struct {
	JobID       string `json:"job_id"`
	RunID       string `json:"run_id"`
	DeviceID    string `json:"device_id"`
	ExecutionID string `json:"execution_id,omitempty"`
	Status      string `json:"status"`
	Output      string `json:"output,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
}

// ---------------------------------------------------------------------------
// run-script
// ---------------------------------------------------------------------------

func runRunScript(_ *cobra.Command, _ []string) error {
	params, err := parseRunParams(stewardRunParams)
	if err != nil {
		return err
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	var matches []StewardInfo
	if stewardRunTarget != "" {
		matches, err = resolveOrFailFast(context.Background(), client, stewardRunTarget)
		if err != nil {
			return err
		}
		if err := confirmMultiHost(matches, stewardYes); err != nil {
			return err
		}
	}

	reqBody := map[string]interface{}{
		"target":         stewardRunTarget,
		"script_id":      stewardRunScript,
		"script_version": stewardRunVersion,
		"params":         params,
		"skip_offline":   stewardRunSkipOffline,
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/runs/script", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to submit run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	runID := apiResp.Data.RunID

	if stewardRunScriptJSONOutput && len(matches) > 0 {
		return emitKeyedDispatchOutput(matches, map[string]interface{}{"run_id": runID})
	}

	if stewardRunWait {
		fmt.Printf("Run ID: %s\n", runID)
		return waitForRun(context.Background(), client, runID, stewardRunWaitTimeout, os.Stdout)
	}

	fmt.Println(runID)
	return nil
}

// ---------------------------------------------------------------------------
// run-command
// ---------------------------------------------------------------------------

func runRunCommand(_ *cobra.Command, args []string) error {
	content, err := readCommandContent(args[0])
	if err != nil {
		return err
	}

	params, err := parseRunParams(stewardRunParams)
	if err != nil {
		return err
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	var matches []StewardInfo
	if stewardRunTarget != "" {
		matches, err = resolveOrFailFast(context.Background(), client, stewardRunTarget)
		if err != nil {
			return err
		}
		if err := confirmMultiHost(matches, stewardYes); err != nil {
			return err
		}
	}

	// The operator signature binds an explicit, resolved target-ID list (Issue #3694).
	// An empty --target means "all stewards" server-side, so resolve "all" here too;
	// otherwise reuse the resolution already done above for the confirm gate.
	envelopeMatches := matches
	if stewardRunTarget == "" {
		envelopeMatches, err = resolveOrFailFast(context.Background(), client, "all")
		if err != nil {
			return err
		}
	}
	targetIDs := make([]string, len(envelopeMatches))
	for i, m := range envelopeMatches {
		targetIDs[i] = m.ID
	}

	sig, envelope, err := buildAndSignEnvelope(content, stewardRunShell, targetIDs)
	if err != nil {
		return err
	}

	reqBody := map[string]interface{}{
		"target":       stewardRunTarget,
		"content":      base64.StdEncoding.EncodeToString(content),
		"shell":        stewardRunShell,
		"params":       params,
		"skip_offline": stewardRunSkipOffline,
		"signature":    sig,
		"targets":      envelope.Targets,
		"nonce":        envelope.Nonce,
		"expires_at":   envelope.ExpiresAt.Format(time.RFC3339),
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/runs/command", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to submit run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	runID := apiResp.Data.RunID

	if stewardRunCommandJSONOutput && len(matches) > 0 {
		return emitKeyedDispatchOutput(matches, map[string]interface{}{"run_id": runID})
	}

	if stewardRunWait {
		fmt.Printf("Run ID: %s\n", runID)
		return waitForRun(context.Background(), client, runID, stewardRunWaitTimeout, os.Stdout)
	}

	fmt.Println(runID)
	return nil
}

// ---------------------------------------------------------------------------
// exec (selector-based ad-hoc run)
// ---------------------------------------------------------------------------

// execCLIOutputCap is the maximum bytes of job output the CLI displays.
// If the output exceeds this cap, a truncation warning is printed to stderr.
const execCLIOutputCap = 64 * 1024

func runRunCommandSingle(_ *cobra.Command, args []string) error {
	selector := args[0]

	if stewardExecCommand == "" {
		return fmt.Errorf("--command is required")
	}
	if stewardExecShell == "" {
		return fmt.Errorf("--shell is required")
	}

	content, err := readCommandContent(stewardExecCommand)
	if err != nil {
		return err
	}

	timeout := stewardExecTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Resolve selector to determine match count for the confirm gate.
	// exec is a mutating verb (A4): confirmMultiHost blocks when N > 1 and
	// --yes is absent.
	matches, err := resolveOrFailFast(context.Background(), client, selector)
	if err != nil {
		return err
	}
	if err := confirmMultiHost(matches, stewardYes); err != nil {
		return err
	}

	// The operator signature binds the explicit, already-resolved target-ID list
	// (Issue #3694) — reusing `matches` from the confirm-gate resolution above.
	targetIDs := make([]string, len(matches))
	for i, m := range matches {
		targetIDs[i] = m.ID
	}
	sig, envelope, err := buildAndSignEnvelope(content, stewardExecShell, targetIDs)
	if err != nil {
		return err
	}

	reqBody := map[string]interface{}{
		"target":     selector,
		"content":    base64.StdEncoding.EncodeToString(content),
		"shell":      stewardExecShell,
		"signature":  sig,
		"targets":    envelope.Targets,
		"nonce":      envelope.Nonce,
		"expires_at": envelope.ExpiresAt.Format(time.RFC3339),
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/runs/command", bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to submit command: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	runID := apiResp.Data.RunID
	// In --json mode, route progress text to stderr so stdout carries only
	// the keyed JSON payload.
	progressW := io.Writer(os.Stdout)
	if stewardExecJSONOutput {
		progressW = os.Stderr
	}
	if _, err := fmt.Fprintf(progressW, "Run ID: %s\n", runID); err != nil {
		return fmt.Errorf("failed to write progress: %w", err)
	}

	if err := waitForRun(context.Background(), client, runID, timeout, progressW); err != nil {
		return err
	}

	return fetchAndDisplayExecOutput(client, runID, matches)
}

// fetchAndDisplayExecOutput retrieves job records for runID and prints output
// for every steward in matches. Each steward gets a host-prefixed block in
// human mode; --json produces a keyed-by-steward array (story 4 schema).
// Applies the 64 KB CLI display cap per steward in human mode.
func fetchAndDisplayExecOutput(client *APIClient, runID string, matches []StewardInfo) error {
	resp, err := client.Get(context.Background(), "/api/v1/runs/"+runID+"/jobs")
	if err != nil {
		return fmt.Errorf("failed to fetch job output: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get job results: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []runJobRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse job results: %w", err)
	}

	// Index returned jobs by device ID for O(1) lookup when building per-steward output.
	jobByDevice := make(map[string]runJobRecord, len(apiResp.Data))
	for _, job := range apiResp.Data {
		jobByDevice[job.DeviceID] = job
	}

	if stewardExecJSONOutput {
		// Build keyed-by-steward output using story 4's keyedOutput helper.
		perStewardResult := make(map[string]fanOutResult, len(matches))
		for _, m := range matches {
			key := stewardKey(m)
			job, ok := jobByDevice[m.ID]
			if !ok {
				perStewardResult[key] = fanOutResult{
					Err: fmt.Errorf("no job record returned for steward %s", m.ID),
				}
				continue
			}
			payload, merr := json.Marshal(map[string]interface{}{
				"exit_code": job.ExitCode,
				"output":    job.Output,
				"status":    job.Status,
			})
			if merr != nil {
				return fmt.Errorf("failed to marshal job output: %w", merr)
			}
			perStewardResult[key] = fanOutResult{
				Success: job.Status == "completed",
				Payload: payload,
			}
		}
		entries := keyedOutput(matches, perStewardResult)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	// Human output: one host-prefixed block per matched steward, in match order.
	for _, m := range matches {
		key := stewardKey(m)
		job, ok := jobByDevice[m.ID]
		if !ok {
			fmt.Fprintf(os.Stderr, "warning: no job record returned for %s\n", key)
			continue
		}
		output := job.Output
		if len(output) > execCLIOutputCap {
			fmt.Fprintf(os.Stderr, "warning: output for %s truncated at 64 KB\n", key)
			output = output[:execCLIOutputCap]
		}
		fmt.Printf("=== %s ===\n", key)
		fmt.Printf("Exit code: %d\n", job.ExitCode)
		if output != "" {
			fmt.Print(output)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// run-status
// ---------------------------------------------------------------------------

func runRunStatus(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	run, err := fetchRunRecord(context.Background(), client, runID)
	if err != nil {
		return err
	}

	fmt.Printf("Run ID:    %s\n", run.RunID)
	fmt.Printf("Status:    %s\n", run.Status)
	fmt.Printf("Jobs:      %d total, %d completed, %d failed\n", run.JobCount, run.CompletedJobs, run.FailedJobs)
	return nil
}

// ---------------------------------------------------------------------------
// run-result
// ---------------------------------------------------------------------------

func runRunResult(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/runs/"+runID+"/jobs")
	if err != nil {
		return fmt.Errorf("failed to fetch run jobs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("run %s not found", runID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []runJobRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	jobs := apiResp.Data
	if stewardRunResultDevice != "" {
		filtered := jobs[:0]
		for _, j := range jobs {
			if j.DeviceID == stewardRunResultDevice {
				filtered = append(filtered, j)
			}
		}
		jobs = filtered
	}

	if len(jobs) == 0 {
		fmt.Println("No jobs found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DEVICE\tSTATUS\tJOB ID\tEXECUTION ID"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "------\t------\t------\t------------"); err != nil {
		return err
	}
	for _, j := range jobs {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", j.DeviceID, j.Status, j.JobID, j.ExecutionID); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// run-cancel
// ---------------------------------------------------------------------------

func runRunCancel(_ *cobra.Command, args []string) error {
	runID := args[0]

	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodDelete, "/api/v1/runs/"+runID, nil)
	if err != nil {
		return fmt.Errorf("failed to cancel run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("run %s not found", runID)
	case http.StatusConflict:
		return fmt.Errorf("run %s is already in a terminal state", runID)
	case http.StatusOK:
		fmt.Printf("Run %s cancelled\n", runID)
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseRunParams converts "key=value" strings to a map. Returns an error for
// any entry that does not contain exactly one "=".
func parseRunParams(params []string) (map[string]string, error) {
	result := make(map[string]string, len(params))
	for _, p := range params {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid parameter %q: expected key=value format", p)
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
}

// readCommandContent returns the raw bytes to sign and execute.
// If arg looks like an existing file path the file is read; otherwise arg
// itself is used as inline content.
func readCommandContent(arg string) ([]byte, error) {
	if _, err := os.Stat(arg); err == nil {
		data, err := os.ReadFile(arg) // #nosec G304 — user-provided path, intentional
		if err != nil {
			return nil, fmt.Errorf("read command file %q: %w", arg, err)
		}
		return data, nil
	}
	return []byte(arg), nil
}

// signCommandContent locates the operator's admin bundle, extracts its private
// key, and signs content. Returns an error if no bundle or no private key is found.
func signCommandContent(content []byte) (*commandSignature, error) {
	bundleEnvVal, _ := os.LookupEnv("CFGMS_ADMIN_BUNDLE")
	bundleFilePath, err := findBundlePath(bundleEnvVal)
	if err != nil {
		return nil, fmt.Errorf("bundle resolution failed: %w", err)
	}
	if bundleFilePath == "" {
		return nil, fmt.Errorf("no admin bundle found: run-command requires a bundle with a private key for signing; use --bundle or set CFGMS_ADMIN_BUNDLE")
	}

	b, err := bundle.Read(bundleFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle at %s: %w", bundleFilePath, err)
	}

	if b.KeyPEM == "" {
		return nil, fmt.Errorf("bundle at %s has no private key: run-command requires signing capability", bundleFilePath)
	}

	privKey, err := parsePrivKeyFromPEM(b.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle private key: %w", err)
	}

	var algorithm string
	switch privKey.(type) {
	case *rsa.PrivateKey:
		algorithm = "rsa-sha256"
	case *ecdsa.PrivateKey:
		algorithm = "ecdsa-sha256"
	default:
		return nil, fmt.Errorf("unsupported key type %T in bundle (expected RSA or ECDSA)", privKey)
	}

	digest, err := hashContent(content, algorithm)
	if err != nil {
		return nil, err
	}

	sigBytes, err := signDigest(digest, privKey, algorithm)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return &commandSignature{
		Algorithm: algorithm,
		Value:     base64.StdEncoding.EncodeToString(sigBytes),
		PublicKey: b.CertPEM,
	}, nil
}

// generateOperatorNonce returns a fresh operatorpayload.Envelope nonce: at least
// operatorNonceBytes of crypto/rand, hex-encoded. Never derived from a counter,
// timestamp, or UUID (Issue #3694 AC) — those are all predictable or reused across
// process restarts, defeating the replay protection a nonce exists to provide.
func generateOperatorNonce() (string, error) {
	buf := make([]byte, operatorNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// buildAndSignEnvelope resolves the fields of an operatorpayload.Envelope binding
// content, shell, and the caller's already-resolved target steward IDs to a fresh
// nonce and a bounded expiry, then signs its canonical bytes with the operator's
// admin-bundle key (Issue #3694). Returns the signature to embed in the request body
// alongside the returned envelope, whose Targets/Nonce/ExpiresAt the caller forwards
// as separate request fields so the controller and steward can independently verify
// against the exact bytes that were signed.
func buildAndSignEnvelope(content []byte, shell string, targets []string) (*commandSignature, operatorpayload.Envelope, error) {
	nonce, err := generateOperatorNonce()
	if err != nil {
		return nil, operatorpayload.Envelope{}, err
	}
	envelope := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(operatorEnvelopeExpiry).UTC(),
	}
	canonicalBytes, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		return nil, operatorpayload.Envelope{}, fmt.Errorf("build operator envelope: %w", err)
	}
	sig, err := signCommandContent(canonicalBytes)
	if err != nil {
		return nil, operatorpayload.Envelope{}, err
	}
	return sig, envelope, nil
}

// parsePrivKeyFromPEM decodes a PEM block and parses a private key in any of
// the three formats `controller --init` may have emitted: PKCS#8 (modern
// default), PKCS#1 RSA (legacy "RSA PRIVATE KEY"), or SEC1 EC ("EC PRIVATE
// KEY"). Tries them in order; returns the first that succeeds.
//
// Earlier versions only tried PKCS#8, which left every admin bundle minted
// before the controller switched its key emitter unable to sign run-command
// requests (surfaced via the #1887 #1852 validation session).
func parsePrivKeyFromPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key data")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("parse private key: not PKCS#8, PKCS#1, or SEC1")
}

// fetchRunRecord calls GET /api/v1/runs/{runID} and returns the parsed record.
func fetchRunRecord(ctx context.Context, client *APIClient, runID string) (*runRecord, error) {
	resp, err := client.Get(ctx, "/api/v1/runs/"+runID)
	if err != nil {
		return nil, fmt.Errorf("failed to poll run: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("run %s not found", runID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data runRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse run response: %w", err)
	}
	return &apiResp.Data, nil
}

// waitForRun polls GET /api/v1/runs/{runID} every runWaitPollInterval until the
// run reaches a terminal state or the timeout elapses. Progress text is written
// to progressW so callers can route it to stdout or stderr without mutating
// global state.
func waitForRun(ctx context.Context, client *APIClient, runID string, timeout time.Duration, progressW io.Writer) error {
	deadline := time.Now().Add(timeout)

	for {
		run, err := fetchRunRecord(ctx, client, runID)
		if err != nil {
			return err
		}

		if isRunTerminal(run.Status) {
			if _, err := fmt.Fprintf(progressW, "Status: %s\n", run.Status); err != nil {
				return fmt.Errorf("failed to write progress: %w", err)
			}
			if _, err := fmt.Fprintf(progressW, "Jobs: %d total, %d completed, %d failed\n", run.JobCount, run.CompletedJobs, run.FailedJobs); err != nil {
				return fmt.Errorf("failed to write progress: %w", err)
			}
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for run %s (status: %s, %d/%d jobs completed)",
				timeout, runID, run.Status, run.CompletedJobs, run.JobCount)
		}

		if _, err := fmt.Fprintf(progressW, "Waiting... status: %s (%d/%d completed)\n", run.Status, run.CompletedJobs, run.JobCount); err != nil {
			return fmt.Errorf("failed to write progress: %w", err)
		}

		select {
		case <-time.After(runWaitPollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func isRunTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}
