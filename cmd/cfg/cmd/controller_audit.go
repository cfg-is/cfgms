// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// Flags for cfg controller audit list.
var (
	auditSince     string
	auditUntil     string
	auditLimit     int
	auditOffset    int
	auditSeverity  string
	auditAction    string
	auditEventType string
	auditUserID    string
	auditResult    string
	auditModule    string
)

// controllerAuditCmd groups audit-log subcommands under cfg controller audit.
var controllerAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log commands",
	Long:  `Read and query controller audit log entries for the current tenant.`,
}

// controllerAuditListCmd lists audit log entries from the controller.
var controllerAuditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit log entries",
	Long: `List audit log entries for the authenticated tenant.

Entries are returned in descending timestamp order. Use --since and --until to
narrow the time range, and --module to filter by resource-type prefix (e.g.
--module=hyperv returns entries whose ResourceType starts with "hyperv/").

Output format defaults to tabular text with columns:
  TIMESTAMP  SEVERITY  ACTION  USER  RESULT

Use --format=json to receive the raw JSON array.`,
	RunE: runControllerAuditList,
}

func init() {
	controllerAuditListCmd.Flags().StringVar(&auditSince, "since", "", "Return entries at or after this time (RFC3339, e.g. 2026-01-01T00:00:00Z)")
	controllerAuditListCmd.Flags().StringVar(&auditUntil, "until", "", "Return entries at or before this time (RFC3339)")
	controllerAuditListCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of entries to return (1-500)")
	controllerAuditListCmd.Flags().IntVar(&auditOffset, "offset", 0, "Number of entries to skip (pagination)")
	controllerAuditListCmd.Flags().StringVar(&auditSeverity, "severity", "", "Filter by severity (low, medium, high, critical)")
	controllerAuditListCmd.Flags().StringVar(&auditAction, "action", "", "Filter by action string")
	controllerAuditListCmd.Flags().StringVar(&auditEventType, "event-type", "", "Filter by event type")
	controllerAuditListCmd.Flags().StringVar(&auditUserID, "user-id", "", "Filter by user ID")
	controllerAuditListCmd.Flags().StringVar(&auditResult, "result", "", "Filter by result (success, failure, error, denied)")
	controllerAuditListCmd.Flags().StringVar(&auditModule, "module", "", "Filter by resource-type prefix (e.g. hyperv)")

	controllerAuditCmd.AddCommand(controllerAuditListCmd)
	controllerCmd.AddCommand(controllerAuditCmd)
}

// auditEntry mirrors the fields of business.AuditEntry used for display.
// Defined locally to avoid importing the business package from the CLI layer.
type auditEntry struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"`
	Action       string    `json:"action"`
	UserID       string    `json:"user_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Result       string    `json:"result"`
	Severity     string    `json:"severity"`
	Source       string    `json:"source"`
}

func runControllerAuditList(_ *cobra.Command, _ []string) error {
	client, err := getControllerClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	params := url.Values{}
	if auditSince != "" {
		params.Set("since", auditSince)
	}
	if auditUntil != "" {
		params.Set("until", auditUntil)
	}
	params.Set("limit", strconv.Itoa(auditLimit))
	params.Set("offset", strconv.Itoa(auditOffset))
	if auditSeverity != "" {
		params.Set("severity", auditSeverity)
	}
	if auditAction != "" {
		params.Set("action", auditAction)
	}
	if auditEventType != "" {
		params.Set("event_type", auditEventType)
	}
	if auditUserID != "" {
		params.Set("user_id", auditUserID)
	}
	if auditResult != "" {
		params.Set("result", auditResult)
	}
	if auditModule != "" {
		params.Set("module", auditModule)
	}

	path := "/api/v1/audit/entries?" + params.Encode()
	resp, err := client.Get(context.Background(), path)
	if err != nil {
		return fmt.Errorf("failed to fetch audit entries: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to close response body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var apiResp struct {
		Data []auditEntry `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if healthFormat == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(apiResp.Data)
	}

	if len(apiResp.Data) == 0 {
		fmt.Println("No audit entries found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "TIMESTAMP\tSEVERITY\tACTION\tUSER\tRESULT"); err != nil {
		return err
	}
	for _, e := range apiResp.Data {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format(time.RFC3339),
			e.Severity,
			e.Action,
			e.UserID,
			e.Result,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}
