// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
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
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	jobURL         string
	jobAPIKey      string
	jobTLSCACert   string
	jobTLSInsecure bool

	jobSelector  string
	jobBatchSize int
)

// jobCmd is the parent command for job subcommands.
var jobCmd = &cobra.Command{
	Use:   "job",
	Short: "Submit and monitor rolling-batch jobs",
	Long:  `Commands for submitting and monitoring fleet-wide rolling batch update jobs.`,
}

// jobSubmitCmd submits a new rolling-batch job to the controller.
var jobSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a rolling-batch job",
	Long: `Resolve a fleet selector, partition stewards into batches, and dispatch a
ConfigSync command to each batch in sequence. Exits 0 after printing the job ID.

Examples:
  cfg job submit --selector "tag:prod" --batch-size 5 --url https://controller.example.com
  cfg job submit --selector "all" --url https://controller.example.com`,
	RunE: runJobSubmit,
}

// jobStatusCmd polls the status of an existing batch job.
var jobStatusCmd = &cobra.Command{
	Use:   "status <job-id>",
	Short: "Show the status of a batch job",
	Long: `Print the current status and step table for a batch job.

The job-id is returned by 'cfg job submit'.

Examples:
  cfg job status <job-id> --url https://controller.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runJobStatus,
}

func init() {
	jobSubmitCmd.Flags().StringVar(&jobURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	jobSubmitCmd.Flags().StringVar(&jobAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	jobSubmitCmd.Flags().StringVar(&jobTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	jobSubmitCmd.Flags().BoolVar(&jobTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
	jobSubmitCmd.Flags().StringVar(&jobSelector, "selector", "", "Fleet selector expression (required)")
	jobSubmitCmd.Flags().IntVar(&jobBatchSize, "batch-size", 10, "Number of stewards per batch wave")
	_ = jobSubmitCmd.MarkFlagRequired("selector")

	jobStatusCmd.Flags().StringVar(&jobURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	jobStatusCmd.Flags().StringVar(&jobAPIKey, "api-key", "", "API key for authentication (env: CFGMS_API_KEY)")
	jobStatusCmd.Flags().StringVar(&jobTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	jobStatusCmd.Flags().BoolVar(&jobTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	jobCmd.AddCommand(jobSubmitCmd, jobStatusCmd)
}

// getJobClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getJobClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(jobURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	client, err := resolveSessionOrBundleClient(apiURL)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	apiKey := jobAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := jobTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := jobTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

// jobSubmitBody is the JSON body for POST /api/v1/jobs.
type jobSubmitBody struct {
	Selector  string `json:"selector"`
	BatchSize int    `json:"batch_size"`
}

// jobStatusStep is one step entry from GET /api/v1/jobs/{id}.
type jobStatusStep struct {
	Index       int        `json:"Index"`
	StewardIDs  []string   `json:"StewardIDs"`
	Status      string     `json:"Status"`
	StartedAt   *time.Time `json:"StartedAt"`
	CompletedAt *time.Time `json:"CompletedAt"`
	FailedIDs   []string   `json:"FailedIDs"`
}

// jobStatusBody is the job record from GET /api/v1/jobs/{id}.
type jobStatusBody struct {
	ID        string          `json:"ID"`
	TenantID  string          `json:"TenantID"`
	Selector  string          `json:"Selector"`
	Status    string          `json:"Status"`
	Steps     []jobStatusStep `json:"Steps"`
	CreatedAt time.Time       `json:"CreatedAt"`
	UpdatedAt time.Time       `json:"UpdatedAt"`
}

func runJobSubmit(_ *cobra.Command, _ []string) error {
	client, err := getJobClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	body, err := json.Marshal(jobSubmitBody{
		Selector:  jobSelector,
		BatchSize: jobBatchSize,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to submit job: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("job submission failed (%s): %s", resp.Status, string(respBody))
	}

	// The controller wraps responses in APIResponse.Data.
	var envelope struct {
		Data struct {
			JobID       string `json:"job_id"`
			Status      string `json:"status"`
			TargetCount int    `json:"target_count"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("Job ID:       %s\n", envelope.Data.JobID)
	fmt.Printf("Status:       %s\n", envelope.Data.Status)
	fmt.Printf("Target count: %d\n", envelope.Data.TargetCount)
	return nil
}

func runJobStatus(_ *cobra.Command, args []string) error {
	jobID := args[0]

	// url.PathEscape prevents path-injection via the job ID.
	statusPath := "/api/v1/jobs/" + url.PathEscape(jobID)

	client, err := getJobClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.doRequest(context.Background(), http.MethodGet, statusPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("job %q not found", jobID)
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response (%s): %s", resp.Status, string(respBody))
	}

	// The job record fields are JSON-encoded directly as struct field names (Go default).
	var envelope struct {
		Data jobStatusBody `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	job := envelope.Data

	fmt.Printf("Job ID:  %s\n", job.ID)
	fmt.Printf("Status:  %s\n", job.Status)
	fmt.Printf("Tenant:  %s\n", job.TenantID)
	fmt.Printf("Selector: %s\n", job.Selector)
	fmt.Println()

	if len(job.Steps) == 0 {
		fmt.Println("No steps yet.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STEP\tSTATUS\tSTEWARDS\tFAILED IDS")
	for _, step := range job.Steps {
		failedStr := strings.Join(step.FailedIDs, ",")
		if failedStr == "" {
			failedStr = "-"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%d\t%s\n",
			step.Index,
			step.Status,
			len(step.StewardIDs),
			failedStr,
		)
	}
	_ = tw.Flush()
	return nil
}
