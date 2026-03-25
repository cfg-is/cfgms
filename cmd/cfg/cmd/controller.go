// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
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
	// Controller command flags
	healthURL    string
	healthAPIKey string
	healthFormat string
)

// controllerCmd represents the controller command
var controllerCmd = &cobra.Command{
	Use:   "controller",
	Short: "Controller health and monitoring commands",
	Long: `Monitor and inspect controller health, metrics, and performance.

Provides operational visibility into controller status including:
- Overall health status and component health
- Performance metrics (transport, storage, application, system)
- Active alerts and threshold breaches
- Request traces for debugging

Examples:
  # Check controller health status
  cfg controller status --url=https://controller.example.com

  # View detailed metrics
  cfg controller metrics --url=https://controller.example.com

  # Export metrics in JSON format
  cfg controller metrics --url=https://controller.example.com --format=json`,
}

// controllerStatusCmd represents the controller status command
var controllerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show controller health status",
	Long: `Display human-readable controller health status including:
- Overall health (healthy, degraded, unhealthy)
- Component status (transport, storage, application, system)
- Active alerts
- Uptime

Examples:
  # Check controller status
  cfg controller status --url=https://controller.example.com

  # With API key authentication
  cfg controller status --url=https://controller.example.com --api-key=your-key`,
	RunE: runControllerStatus,
}

// controllerMetricsCmd represents the controller metrics command
var controllerMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show detailed controller metrics",
	Long: `Display detailed controller performance metrics including:
- Transport: connected stewards, stream errors, message throughput
- Storage: latency, pool utilization, slow queries
- Application: workflow/script queue depths, active executions
- System: CPU, memory, goroutines

Output formats: text (default), json

Examples:
  # View metrics in human-readable format
  cfg controller metrics --url=https://controller.example.com

  # Export metrics as JSON
  cfg controller metrics --url=https://controller.example.com --format=json`,
	RunE: runControllerMetrics,
}

func init() {
	// Controller command flags
	controllerCmd.PersistentFlags().StringVar(&healthURL, "url", "", "Controller API URL (required)")
	controllerCmd.PersistentFlags().StringVar(&healthAPIKey, "api-key", "", "API key for authentication")
	controllerCmd.PersistentFlags().StringVar(&healthFormat, "format", "text", "Output format (text, json)")

	_ = controllerCmd.MarkPersistentFlagRequired("url")

	// Add subcommands
	controllerCmd.AddCommand(controllerStatusCmd)
	controllerCmd.AddCommand(controllerMetricsCmd)
}

func runControllerStatus(cmd *cobra.Command, args []string) error {
	// Make API request
	url := strings.TrimSuffix(healthURL, "/") + "/api/v1/health/detailed"
	resp, err := makeAPIRequest(url, healthAPIKey)
	if err != nil {
		return fmt.Errorf("failed to fetch health status: %w", err)
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

	// Parse response
	var healthStatus struct {
		Status        string    `json:"status"`
		Timestamp     time.Time `json:"timestamp"`
		UptimeSeconds int64     `json:"uptime_seconds"`
		Components    map[string]struct {
			Name      string                 `json:"name"`
			Status    string                 `json:"status"`
			Message   string                 `json:"message"`
			LastCheck time.Time              `json:"last_check"`
			Details   map[string]interface{} `json:"details"`
		} `json:"components"`
		Alerts []struct {
			ID             string    `json:"id"`
			Timestamp      time.Time `json:"timestamp"`
			Severity       string    `json:"severity"`
			Title          string    `json:"title"`
			Description    string    `json:"description"`
			MetricName     string    `json:"metric_name"`
			CurrentValue   float64   `json:"current_value"`
			ThresholdValue float64   `json:"threshold_value"`
			Status         string    `json:"status"`
		} `json:"alerts"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&healthStatus); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results
	if healthFormat == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(healthStatus)
	}

	// Text format
	statusIcon := getStatusIcon(healthStatus.Status)
	fmt.Printf("\n%s Controller Health Status: %s\n", statusIcon, strings.ToUpper(healthStatus.Status))
	fmt.Printf("Uptime: %s\n", formatDuration(time.Duration(healthStatus.UptimeSeconds)*time.Second))
	fmt.Printf("Checked: %s\n", healthStatus.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Println()

	// Component health
	fmt.Println("=== Component Health ===")
	for _, component := range healthStatus.Components {
		icon := getStatusIcon(component.Status)
		fmt.Printf("\n%s %s (%s)\n", icon, component.Name, strings.ToUpper(component.Status))
		fmt.Printf("  %s\n", component.Message)

		if len(component.Details) > 0 {
			fmt.Println("  Details:")
			for key, value := range component.Details {
				fmt.Printf("    %s: %v\n", formatKey(key), value)
			}
		}
	}

	// Active alerts
	if len(healthStatus.Alerts) > 0 {
		fmt.Println()
		fmt.Println("=== Active Alerts ===")
		for _, alert := range healthStatus.Alerts {
			severityIcon := getSeverityIcon(alert.Severity)
			fmt.Printf("\n%s %s [%s]\n", severityIcon, alert.Title, strings.ToUpper(alert.Severity))
			fmt.Printf("  %s\n", alert.Description)
			fmt.Printf("  Current: %.2f | Threshold: %.2f\n", alert.CurrentValue, alert.ThresholdValue)
			fmt.Printf("  Since: %s\n", alert.Timestamp.Format("2006-01-02 15:04:05"))
		}
	}

	fmt.Println()
	return nil
}

func runControllerMetrics(cmd *cobra.Command, args []string) error {
	// Make API request
	url := strings.TrimSuffix(healthURL, "/") + "/api/v1/health/metrics"
	resp, err := makeAPIRequest(url, healthAPIKey)
	if err != nil {
		return fmt.Errorf("failed to fetch metrics: %w", err)
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

	// Parse response
	var metrics struct {
		Timestamp time.Time `json:"timestamp"`
		Transport *struct {
			ConnectedStewards     int       `json:"connected_stewards"`
			StreamErrors          int64     `json:"stream_errors"`
			MessagesSent          int64     `json:"messages_sent"`
			MessagesReceived      int64     `json:"messages_received"`
			ReconnectionAttempts  int64     `json:"reconnection_attempts"`
			AvgLatencyNs          int64     `json:"avg_latency_ns"`
			CollectedAt           time.Time `json:"collected_at"`
		} `json:"transport"`
		Storage *struct {
			Provider          string    `json:"provider"`
			PoolUtilization   float64   `json:"pool_utilization"`
			AvgQueryLatencyMs float64   `json:"avg_query_latency_ms"`
			P95QueryLatencyMs float64   `json:"p95_query_latency_ms"`
			SlowQueryCount    int64     `json:"slow_query_count"`
			TotalQueries      int64     `json:"total_queries"`
			QueryErrors       int64     `json:"query_errors"`
			CollectedAt       time.Time `json:"collected_at"`
		} `json:"storage"`
		Application *struct {
			WorkflowQueueDepth  int64     `json:"workflow_queue_depth"`
			WorkflowMaxWaitTime float64   `json:"workflow_max_wait_time"`
			ActiveWorkflows     int64     `json:"active_workflows"`
			ScriptQueueDepth    int64     `json:"script_queue_depth"`
			ScriptMaxWaitTime   float64   `json:"script_max_wait_time"`
			ActiveScripts       int64     `json:"active_scripts"`
			ConfigQueueDepth    int64     `json:"config_queue_depth"`
			CollectedAt         time.Time `json:"collected_at"`
		} `json:"application"`
		System *struct {
			CPUPercent          float64   `json:"cpu_percent"`
			MemoryUsedBytes     int64     `json:"memory_used_bytes"`
			MemoryPercent       float64   `json:"memory_percent"`
			HeapBytes           int64     `json:"heap_bytes"`
			RSSBytes            int64     `json:"rss_bytes"`
			GoroutineCount      int64     `json:"goroutine_count"`
			OpenFileDescriptors int64     `json:"open_file_descriptors"`
			CollectedAt         time.Time `json:"collected_at"`
		} `json:"system"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display results
	if healthFormat == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(metrics)
	}

	// Text format
	fmt.Printf("\nController Metrics - %s\n", metrics.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Println()

	// Transport metrics
	if metrics.Transport != nil {
		fmt.Println("=== Transport (gRPC-over-QUIC) ===")
		fmt.Printf("Connected Stewards:     %d\n", metrics.Transport.ConnectedStewards)
		fmt.Printf("Stream Errors:          %d\n", metrics.Transport.StreamErrors)
		fmt.Printf("Messages Sent:          %d\n", metrics.Transport.MessagesSent)
		fmt.Printf("Messages Received:      %d\n", metrics.Transport.MessagesReceived)
		fmt.Printf("Reconnection Attempts:  %d\n", metrics.Transport.ReconnectionAttempts)
		fmt.Printf("Avg Latency:            %dns\n", metrics.Transport.AvgLatencyNs)
		fmt.Println()
	}

	// Storage metrics
	if metrics.Storage != nil {
		fmt.Println("=== Storage Provider ===")
		fmt.Printf("Provider:               %s\n", metrics.Storage.Provider)
		fmt.Printf("Pool Utilization:       %.1f%%\n", metrics.Storage.PoolUtilization*100)
		fmt.Printf("Avg Query Latency:      %.2f ms\n", metrics.Storage.AvgQueryLatencyMs)
		fmt.Printf("P95 Query Latency:      %.2f ms\n", metrics.Storage.P95QueryLatencyMs)
		fmt.Printf("Slow Queries (>1s):     %d\n", metrics.Storage.SlowQueryCount)
		fmt.Printf("Total Queries:          %d\n", metrics.Storage.TotalQueries)
		fmt.Printf("Query Errors:           %d\n", metrics.Storage.QueryErrors)
		fmt.Println()
	}

	// Application metrics
	if metrics.Application != nil {
		fmt.Println("=== Application ===")
		fmt.Printf("Workflow Queue Depth:   %d\n", metrics.Application.WorkflowQueueDepth)
		fmt.Printf("Workflow Max Wait:      %.2f sec\n", metrics.Application.WorkflowMaxWaitTime)
		fmt.Printf("Active Workflows:       %d\n", metrics.Application.ActiveWorkflows)
		fmt.Printf("Script Queue Depth:     %d\n", metrics.Application.ScriptQueueDepth)
		fmt.Printf("Script Max Wait:        %.2f sec\n", metrics.Application.ScriptMaxWaitTime)
		fmt.Printf("Active Scripts:         %d\n", metrics.Application.ActiveScripts)
		fmt.Printf("Config Queue Depth:     %d\n", metrics.Application.ConfigQueueDepth)
		fmt.Println()
	}

	// System metrics
	if metrics.System != nil {
		fmt.Println("=== System Resources ===")
		fmt.Printf("CPU Usage:              %.1f%%\n", metrics.System.CPUPercent)
		fmt.Printf("Memory Usage:           %.1f%% (%s)\n",
			metrics.System.MemoryPercent, formatBytes(metrics.System.MemoryUsedBytes))
		fmt.Printf("Heap Memory:            %s\n", formatBytes(metrics.System.HeapBytes))
		fmt.Printf("RSS Memory:             %s\n", formatBytes(metrics.System.RSSBytes))
		fmt.Printf("Goroutines:             %d\n", metrics.System.GoroutineCount)
		fmt.Printf("Open File Descriptors:  %d\n", metrics.System.OpenFileDescriptors)
		fmt.Println()
	}

	return nil
}

func makeAPIRequest(url, apiKey string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Do(req)
}

func getStatusIcon(status string) string {
	switch strings.ToLower(status) {
	case "healthy":
		return "✓"
	case "degraded":
		return "⚠"
	case "unhealthy":
		return "✗"
	default:
		return "?"
	}
}

func getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "warning":
		return "🟡"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

func formatKey(key string) string {
	// Convert snake_case to Title Case
	parts := strings.Split(key, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}
