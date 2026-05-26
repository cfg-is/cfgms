// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Trace command flags
	traceURL         string
	traceAPIKey      string
	traceFormat      string
	traceTLSCACert   string
	traceTLSInsecure bool
)

// traceCmd represents the trace command
var traceCmd = &cobra.Command{
	Use:   "trace <request-id>",
	Short: "Show request trace details",
	Long: `Display detailed trace information for a specific request including:
- Request flow and timing
- Sub-operations (spans) with durations
- Operation status and errors
- Request metadata

Request IDs are included in controller logs and API responses for debugging.

Examples:
  # View trace for a specific request
  cfg trace abc123def456 --url=https://controller.example.com

  # Export trace as JSON
  cfg trace abc123def456 --url=https://controller.example.com --format=json`,
	Args: cobra.ExactArgs(1),
	RunE: runTrace,
}

func init() {
	traceCmd.Flags().StringVar(&traceURL, "url", "", "Controller API URL (required)")
	traceCmd.Flags().StringVar(&traceAPIKey, "api-key", "", "API key for authentication")
	traceCmd.Flags().StringVar(&traceFormat, "format", "text", "Output format (text, json)")
	traceCmd.Flags().StringVar(&traceTLSCACert, "tls-ca-cert", "", "Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT)")
	traceCmd.Flags().BoolVar(&traceTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")

	_ = traceCmd.MarkFlagRequired("url")
}

// getTraceClient creates an API client using bundle auth (mTLS) when available,
// falling back to API key auth when no bundle is found or discovery is opted out.
func getTraceClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(traceURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}

	// Try admin bundle first (mTLS auto-discovery)
	client, err := resolveBundleClient(apiURL)
	if err != nil {
		return nil, fmt.Errorf("bundle lookup failed: %w", err)
	}
	if client != nil {
		return client, nil
	}

	// Fallback: API key path
	apiKey := traceAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("CFGMS_API_KEY")
	}

	tlsInsecure := traceTLSInsecure
	if !tlsInsecure && os.Getenv("CFGMS_TLS_INSECURE") == "true" {
		tlsInsecure = true
	}

	tlsCACertPath := traceTLSCACert
	if tlsCACertPath == "" {
		tlsCACertPath = os.Getenv("CFGMS_TLS_CA_CERT")
	}

	return newClientFromFlags(apiURL, apiKey, tlsCACertPath, tlsInsecure)
}

func runTrace(cmd *cobra.Command, args []string) error {
	requestID := args[0]

	client, err := getTraceClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	resp, err := client.Get(context.Background(), "/api/v1/health/trace/"+requestID)
	if err != nil {
		return fmt.Errorf("failed to fetch trace: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("trace not found: %s (traces are retained for 24 hours)", requestID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var trace struct {
		RequestID       string                 `json:"request_id"`
		TraceID         string                 `json:"trace_id"`
		ParentRequestID string                 `json:"parent_request_id,omitempty"`
		StartTime       time.Time              `json:"start_time"`
		EndTime         *time.Time             `json:"end_time,omitempty"`
		DurationMs      float64                `json:"duration_ms,omitempty"`
		Operation       string                 `json:"operation"`
		Component       string                 `json:"component"`
		Status          string                 `json:"status"`
		Error           string                 `json:"error,omitempty"`
		Metadata        map[string]interface{} `json:"metadata,omitempty"`
		Spans           []spanType             `json:"spans,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&trace); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results
	if traceFormat == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(trace)
	}

	// Text format
	statusIcon := getTraceStatusIcon(trace.Status)
	fmt.Printf("\n%s Request Trace: %s\n", statusIcon, trace.RequestID)
	fmt.Printf("Operation: %s\n", trace.Operation)
	fmt.Printf("Component: %s\n", trace.Component)
	fmt.Printf("Status: %s\n", strings.ToUpper(trace.Status))

	if trace.TraceID != "" {
		fmt.Printf("Trace ID: %s\n", trace.TraceID)
	}
	if trace.ParentRequestID != "" {
		fmt.Printf("Parent Request: %s\n", trace.ParentRequestID)
	}

	fmt.Printf("Started: %s\n", trace.StartTime.Format("2006-01-02 15:04:05.000"))
	if trace.EndTime != nil {
		fmt.Printf("Ended: %s\n", trace.EndTime.Format("2006-01-02 15:04:05.000"))
		fmt.Printf("Duration: %.2f ms\n", trace.DurationMs)
	} else {
		fmt.Printf("Duration: In progress\n")
	}

	if trace.Error != "" {
		fmt.Printf("\n❌ Error: %s\n", trace.Error)
	}

	// Metadata
	if len(trace.Metadata) > 0 {
		fmt.Println("\n=== Metadata ===")
		for key, value := range trace.Metadata {
			fmt.Printf("%s: %v\n", formatKey(key), value)
		}
	}

	// Spans
	if len(trace.Spans) > 0 {
		fmt.Println("\n=== Sub-Operations (Spans) ===")
		printSpans(trace.Spans, "", make(map[string]bool))
	}

	fmt.Println()
	return nil
}

// spanType represents a trace span for printing
type spanType struct {
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Operation    string            `json:"operation"`
	StartTime    time.Time         `json:"start_time"`
	EndTime      *time.Time        `json:"end_time,omitempty"`
	DurationMs   float64           `json:"duration_ms,omitempty"`
	Status       string            `json:"status"`
	Tags         map[string]string `json:"tags,omitempty"`
}

func printSpans(spans []spanType, indent string, printed map[string]bool) {
	// Find root spans (no parent or parent not in list)
	parentIDs := make(map[string][]int)
	var rootSpans []int

	for i, span := range spans {
		if span.ParentSpanID == "" {
			rootSpans = append(rootSpans, i)
		} else {
			parentIDs[span.ParentSpanID] = append(parentIDs[span.ParentSpanID], i)
		}
	}

	// Print root spans first
	for _, idx := range rootSpans {
		if !printed[spans[idx].SpanID] {
			printSpan(spans[idx], indent, spans, parentIDs, printed)
		}
	}
}

func printSpan(span spanType, indent string, allSpans []spanType, children map[string][]int, printed map[string]bool) {
	printed[span.SpanID] = true

	statusIcon := getTraceStatusIcon(span.Status)
	fmt.Printf("%s%s %s (%.2f ms) - %s\n",
		indent, statusIcon, span.Operation, span.DurationMs, strings.ToUpper(span.Status))

	// Print tags if present
	if len(span.Tags) > 0 {
		for key, value := range span.Tags {
			fmt.Printf("%s  %s: %s\n", indent, key, value)
		}
	}

	// Print children recursively
	if childIndices, ok := children[span.SpanID]; ok {
		for _, childIdx := range childIndices {
			if childIdx < len(allSpans) {
				printSpan(allSpans[childIdx], indent+"  ", allSpans, children, printed)
			}
		}
	}
}

func getTraceStatusIcon(status string) string {
	switch strings.ToLower(status) {
	case "success":
		return "✓"
	case "error":
		return "✗"
	case "timeout":
		return "⏱"
	case "in_progress":
		return "⟳"
	default:
		return "?"
	}
}
