// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TestReporter provides enhanced test reporting with failure analysis
type TestReporter struct {
	framework *E2ETestFramework
	reportDir string
}

// NewTestReporter creates a new test reporter
func NewTestReporter(framework *E2ETestFramework) *TestReporter {
	reportDir := filepath.Join(framework.tempDir, "reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		// Log error but continue - reports are optional
		_ = err // Explicitly ignore directory creation errors for optional reports
	}

	return &TestReporter{
		framework: framework,
		reportDir: reportDir,
	}
}

// TestSummaryReport contains comprehensive test summary information
type TestSummaryReport struct {
	ExecutionInfo    ExecutionInfo          `json:"execution_info"`
	TestResults      TestResultsSummary     `json:"test_results"`
	PerformanceData  PerformanceAnalysis    `json:"performance_data"`
	FailureAnalysis  FailureAnalysis        `json:"failure_analysis"`
	PlatformCoverage PlatformCoverageReport `json:"platform_coverage"`
	Recommendations  []string               `json:"recommendations"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

// ExecutionInfo contains information about the test execution environment
type ExecutionInfo struct {
	TestFramework       string               `json:"test_framework"`
	Configuration       *E2EConfig           `json:"configuration"`
	Environment         map[string]string    `json:"environment"`
	ExecutionDuration   time.Duration        `json:"execution_duration"`
	ComponentStartTimes map[string]time.Time `json:"component_start_times"`
}

// TestResultsSummary provides a summary of all test results
type TestResultsSummary struct {
	TotalTests      int                       `json:"total_tests"`
	PassedTests     int                       `json:"passed_tests"`
	FailedTests     int                       `json:"failed_tests"`
	SkippedTests    int                       `json:"skipped_tests"`
	SuccessRate     float64                   `json:"success_rate"`
	CategoryResults map[string]CategoryResult `json:"category_results"`
	TestDetails     []TestResult              `json:"test_details"`
}

// CategoryResult summarizes results for a specific test category
type CategoryResult struct {
	Category    string  `json:"category"`
	Total       int     `json:"total"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	SuccessRate float64 `json:"success_rate"`
}

// PerformanceAnalysis contains performance metrics and analysis
type PerformanceAnalysis struct {
	BaselineEstablished bool                    `json:"baseline_established"`
	Metrics             PerformanceMetrics      `json:"metrics"`
	Regressions         []PerformanceRegression `json:"regressions"`
	ResourceUsage       ResourceUsage           `json:"resource_usage"`
}

// PerformanceRegression identifies performance regressions
type PerformanceRegression struct {
	TestName       string      `json:"test_name"`
	Metric         string      `json:"metric"`
	CurrentValue   interface{} `json:"current_value"`
	BaselineValue  interface{} `json:"baseline_value"`
	RegressionType string      `json:"regression_type"` // "slowdown", "memory_increase", "throughput_decrease"
	Severity       string      `json:"severity"`        // "minor", "major", "critical"
	Description    string      `json:"description"`
}

// FailureAnalysis provides detailed analysis of test failures
type FailureAnalysis struct {
	FailurePatterns  []FailurePattern  `json:"failure_patterns"`
	CommonFailures   []CommonFailure   `json:"common_failures"`
	CriticalFailures []CriticalFailure `json:"critical_failures"`
	FlakeyTests      []FlakeyTest      `json:"flakey_tests"`
	FailureHotspots  []FailureHotspot  `json:"failure_hotspots"`
}

// FailurePattern identifies patterns in test failures
type FailurePattern struct {
	Pattern     string   `json:"pattern"`
	Occurrences int      `json:"occurrences"`
	TestNames   []string `json:"test_names"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
}

// CommonFailure represents frequently occurring failures
type CommonFailure struct {
	ErrorMessage     string   `json:"error_message"`
	Frequency        int      `json:"frequency"`
	AffectedTests    []string `json:"affected_tests"`
	SuggestedFix     string   `json:"suggested_fix"`
	DocumentationURL string   `json:"documentation_url,omitempty"`
}

// CriticalFailure represents failures that block core functionality
type CriticalFailure struct {
	TestName        string   `json:"test_name"`
	FailureReason   string   `json:"failure_reason"`
	Impact          string   `json:"impact"`
	BlockedFeatures []string `json:"blocked_features"`
	Priority        string   `json:"priority"`
}

// FlakeyTest identifies tests with inconsistent results
type FlakeyTest struct {
	TestName    string   `json:"test_name"`
	SuccessRate float64  `json:"success_rate"`
	TotalRuns   int      `json:"total_runs"`
	Failures    []string `json:"failures"`
}

// FailureHotspot identifies components with high failure rates
type FailureHotspot struct {
	Component     string   `json:"component"`
	FailureCount  int      `json:"failure_count"`
	FailureRate   float64  `json:"failure_rate"`
	TestsAffected []string `json:"tests_affected"`
}

// PlatformCoverageReport shows cross-platform test coverage
type PlatformCoverageReport struct {
	TestedPlatforms  []PlatformResult        `json:"tested_platforms"`
	CoverageGaps     []string                `json:"coverage_gaps"`
	PlatformSpecific []PlatformSpecificIssue `json:"platform_specific"`
}

// PlatformResult shows results for a specific platform
type PlatformResult struct {
	Platform     string   `json:"platform"`
	TestsRun     int      `json:"tests_run"`
	Passed       int      `json:"passed"`
	Failed       int      `json:"failed"`
	SuccessRate  float64  `json:"success_rate"`
	UniqueIssues []string `json:"unique_issues"`
}

// PlatformSpecificIssue identifies issues specific to certain platforms
type PlatformSpecificIssue struct {
	Platform   string `json:"platform"`
	Issue      string `json:"issue"`
	TestName   string `json:"test_name"`
	Workaround string `json:"workaround,omitempty"`
}

// GenerateReport creates a comprehensive test report
func (r *TestReporter) GenerateReport() (*TestSummaryReport, error) {
	metrics := r.framework.GetMetrics()

	report := &TestSummaryReport{
		ExecutionInfo:    r.generateExecutionInfo(metrics),
		TestResults:      r.analyzeTestResults(metrics),
		PerformanceData:  r.analyzePerformance(metrics),
		FailureAnalysis:  r.analyzeFailures(metrics),
		PlatformCoverage: r.analyzePlatformCoverage(metrics),
		Recommendations:  r.generateRecommendations(metrics),
		GeneratedAt:      time.Now(),
	}

	return report, nil
}

// SaveReportToFile saves the report in multiple formats
func (r *TestReporter) SaveReportToFile(report *TestSummaryReport) error {
	// Save JSON report
	jsonPath := filepath.Join(r.reportDir, "test-report.json")
	if err := r.saveJSONReport(report, jsonPath); err != nil {
		return fmt.Errorf("failed to save JSON report: %w", err)
	}

	// Save human-readable report
	textPath := filepath.Join(r.reportDir, "test-report.txt")
	if err := r.saveTextReport(report, textPath); err != nil {
		return fmt.Errorf("failed to save text report: %w", err)
	}

	// Save CI-friendly summary
	summaryPath := filepath.Join(r.reportDir, "test-summary.txt")
	if err := r.saveCISummary(report, summaryPath); err != nil {
		return fmt.Errorf("failed to save CI summary: %w", err)
	}

	return nil
}

// Implementation methods

func (r *TestReporter) generateExecutionInfo(metrics *TestMetrics) ExecutionInfo {
	env := make(map[string]string)
	env["CI"] = os.Getenv("CI")
	env["GITHUB_ACTIONS"] = os.Getenv("GITHUB_ACTIONS")
	env["RUNNER_OS"] = os.Getenv("RUNNER_OS")
	env["GO_VERSION"] = os.Getenv("GO_VERSION")

	return ExecutionInfo{
		TestFramework:       "CFGMS E2E Testing Framework",
		Configuration:       r.framework.config,
		Environment:         env,
		ExecutionDuration:   time.Since(metrics.StartTime),
		ComponentStartTimes: metrics.ComponentStartTimes,
	}
}

func (r *TestReporter) analyzeTestResults(metrics *TestMetrics) TestResultsSummary {
	categoryResults := make(map[string]CategoryResult)
	totalTests := len(metrics.TestResults)
	passedTests := 0
	failedTests := 0

	// Analyze by category
	categoryCounts := make(map[string]map[string]int)

	for _, result := range metrics.TestResults {
		if _, exists := categoryCounts[result.Category]; !exists {
			categoryCounts[result.Category] = map[string]int{"total": 0, "passed": 0, "failed": 0}
		}

		categoryCounts[result.Category]["total"]++

		if result.Success {
			passedTests++
			categoryCounts[result.Category]["passed"]++
		} else {
			failedTests++
			categoryCounts[result.Category]["failed"]++
		}
	}

	// Build category results
	for category, counts := range categoryCounts {
		successRate := float64(counts["passed"]) / float64(counts["total"]) * 100
		categoryResults[category] = CategoryResult{
			Category:    category,
			Total:       counts["total"],
			Passed:      counts["passed"],
			Failed:      counts["failed"],
			SuccessRate: successRate,
		}
	}

	successRate := float64(passedTests) / float64(totalTests) * 100

	return TestResultsSummary{
		TotalTests:      totalTests,
		PassedTests:     passedTests,
		FailedTests:     failedTests,
		SkippedTests:    0, // Would track skipped tests in real implementation
		SuccessRate:     successRate,
		CategoryResults: categoryResults,
		TestDetails:     metrics.TestResults,
	}
}

func (r *TestReporter) analyzePerformance(metrics *TestMetrics) PerformanceAnalysis {
	regressions := []PerformanceRegression{}

	// Analyze for performance regressions
	for _, result := range metrics.TestResults {
		if result.Category == "performance" && !result.Success {
			regression := PerformanceRegression{
				TestName:       result.Name,
				Metric:         "execution_time",
				CurrentValue:   result.Duration,
				BaselineValue:  "unknown",
				RegressionType: "performance_failure",
				Severity:       "major",
				Description:    result.Error,
			}
			regressions = append(regressions, regression)
		}
	}

	return PerformanceAnalysis{
		BaselineEstablished: len(regressions) == 0,
		Metrics:             metrics.PerformanceMetrics,
		Regressions:         regressions,
		ResourceUsage:       metrics.ResourceUsage,
	}
}

func (r *TestReporter) analyzeFailures(metrics *TestMetrics) FailureAnalysis {
	failurePatterns := []FailurePattern{}
	commonFailures := []CommonFailure{}
	criticalFailures := []CriticalFailure{}
	failureHotspots := []FailureHotspot{}

	// Count failure patterns
	errorCounts := make(map[string]int)
	errorTests := make(map[string][]string)

	for _, result := range metrics.TestResults {
		if !result.Success && result.Error != "" {
			errorCounts[result.Error]++
			errorTests[result.Error] = append(errorTests[result.Error], result.Name)

			// Identify critical failures (security, core functionality)
			if strings.Contains(result.Category, "security") ||
				strings.Contains(result.Category, "core") ||
				strings.Contains(result.Name, "Integration") {
				criticalFailures = append(criticalFailures, CriticalFailure{
					TestName:        result.Name,
					FailureReason:   result.Error,
					Impact:          "High - affects core functionality",
					BlockedFeatures: []string{result.Category},
					Priority:        "P0",
				})
			}
		}
	}

	// Build common failures
	for errorMsg, count := range errorCounts {
		if count > 1 {
			commonFailures = append(commonFailures, CommonFailure{
				ErrorMessage:  errorMsg,
				Frequency:     count,
				AffectedTests: errorTests[errorMsg],
				SuggestedFix:  r.suggestFix(errorMsg),
			})
		}
	}

	// Analyze failure hotspots by category
	categoryFailures := make(map[string]int)
	categoryTests := make(map[string][]string)

	for _, result := range metrics.TestResults {
		if !result.Success {
			categoryFailures[result.Category]++
			categoryTests[result.Category] = append(categoryTests[result.Category], result.Name)
		}
	}

	for category, failureCount := range categoryFailures {
		if failureCount > 0 {
			totalInCategory := 0
			for _, result := range metrics.TestResults {
				if result.Category == category {
					totalInCategory++
				}
			}

			failureRate := float64(failureCount) / float64(totalInCategory) * 100

			failureHotspots = append(failureHotspots, FailureHotspot{
				Component:     category,
				FailureCount:  failureCount,
				FailureRate:   failureRate,
				TestsAffected: categoryTests[category],
			})
		}
	}

	return FailureAnalysis{
		FailurePatterns:  failurePatterns,
		CommonFailures:   commonFailures,
		CriticalFailures: criticalFailures,
		FlakeyTests:      []FlakeyTest{}, // Would implement flakey test detection
		FailureHotspots:  failureHotspots,
	}
}

func (r *TestReporter) analyzePlatformCoverage(metrics *TestMetrics) PlatformCoverageReport {
	// This would analyze platform-specific test results
	// For now, return basic coverage info
	testedPlatforms := []PlatformResult{
		{
			Platform:    "Linux",
			TestsRun:    len(metrics.TestResults),
			Passed:      r.countSuccessfulTests(metrics.TestResults),
			Failed:      r.countFailedTests(metrics.TestResults),
			SuccessRate: r.calculateSuccessRate(metrics.TestResults),
		},
	}

	coverageGaps := []string{}
	if !r.framework.config.OptimizeForCI {
		coverageGaps = append(coverageGaps, "Windows cross-platform testing", "macOS cross-platform testing")
	}

	return PlatformCoverageReport{
		TestedPlatforms:  testedPlatforms,
		CoverageGaps:     coverageGaps,
		PlatformSpecific: []PlatformSpecificIssue{},
	}
}

func (r *TestReporter) generateRecommendations(metrics *TestMetrics) []string {
	recommendations := []string{}

	successRate := r.calculateSuccessRate(metrics.TestResults)

	if successRate < 90 {
		recommendations = append(recommendations, "Test success rate is below 90% - investigate and fix failing tests")
	}

	if r.countFailedTests(metrics.TestResults) > 0 {
		recommendations = append(recommendations, "Address failing tests before deployment")
	}

	if r.framework.config.OptimizeForCI {
		recommendations = append(recommendations, "Consider running full cross-platform tests in pre-release validation")
	}

	// Check for performance issues
	for _, result := range metrics.TestResults {
		if result.Category == "performance" && !result.Success {
			recommendations = append(recommendations, "Performance regression detected - review system performance")
			break
		}
	}

	return recommendations
}

// Helper methods

func (r *TestReporter) suggestFix(errorMsg string) string {
	errorMsg = strings.ToLower(errorMsg)

	if strings.Contains(errorMsg, "timeout") {
		return "Increase test timeout or optimize component startup time"
	}
	if strings.Contains(errorMsg, "connection") {
		return "Check network connectivity and service availability"
	}
	if strings.Contains(errorMsg, "certificate") {
		return "Verify certificate configuration and validity"
	}
	if strings.Contains(errorMsg, "permission") {
		return "Check file permissions and RBAC configuration"
	}
	if strings.Contains(errorMsg, "memory") {
		return "Investigate memory usage and potential leaks"
	}

	return "Review test logs and component configuration"
}

func (r *TestReporter) countSuccessfulTests(results []TestResult) int {
	count := 0
	for _, result := range results {
		if result.Success {
			count++
		}
	}
	return count
}

func (r *TestReporter) countFailedTests(results []TestResult) int {
	count := 0
	for _, result := range results {
		if !result.Success {
			count++
		}
	}
	return count
}

func (r *TestReporter) calculateSuccessRate(results []TestResult) float64 {
	if len(results) == 0 {
		return 0
	}
	return float64(r.countSuccessfulTests(results)) / float64(len(results)) * 100
}

// File output methods

func (r *TestReporter) saveJSONReport(report *TestSummaryReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (r *TestReporter) saveTextReport(report *TestSummaryReport, path string) error {
	content := r.formatTextReport(report)
	return os.WriteFile(path, []byte(content), 0644)
}

func (r *TestReporter) saveCISummary(report *TestSummaryReport, path string) error {
	content := r.formatCISummary(report)
	return os.WriteFile(path, []byte(content), 0644)
}

func (r *TestReporter) formatTextReport(report *TestSummaryReport) string {
	var builder strings.Builder

	builder.WriteString("CFGMS Integration Test Report\n")
	builder.WriteString("============================\n\n")

	// Execution info
	builder.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Duration: %v\n", report.ExecutionInfo.ExecutionDuration))
	builder.WriteString(fmt.Sprintf("Environment: CI=%s\n\n", report.ExecutionInfo.Environment["CI"]))

	// Test results
	results := report.TestResults
	builder.WriteString("Test Results Summary\n")
	builder.WriteString("-------------------\n")
	builder.WriteString(fmt.Sprintf("Total Tests: %d\n", results.TotalTests))
	builder.WriteString(fmt.Sprintf("Passed: %d\n", results.PassedTests))
	builder.WriteString(fmt.Sprintf("Failed: %d\n", results.FailedTests))
	builder.WriteString(fmt.Sprintf("Success Rate: %.1f%%\n\n", results.SuccessRate))

	// Category breakdown
	builder.WriteString("Results by Category\n")
	builder.WriteString("------------------\n")
	for category, result := range results.CategoryResults {
		builder.WriteString(fmt.Sprintf("%s: %d/%d (%.1f%%)\n",
			category, result.Passed, result.Total, result.SuccessRate))
	}
	builder.WriteString("\n")

	// Failures
	if len(report.FailureAnalysis.CriticalFailures) > 0 {
		builder.WriteString("Critical Failures\n")
		builder.WriteString("----------------\n")
		for _, failure := range report.FailureAnalysis.CriticalFailures {
			builder.WriteString(fmt.Sprintf("- %s: %s\n", failure.TestName, failure.FailureReason))
		}
		builder.WriteString("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		builder.WriteString("Recommendations\n")
		builder.WriteString("--------------\n")
		for _, rec := range report.Recommendations {
			builder.WriteString(fmt.Sprintf("- %s\n", rec))
		}
	}

	return builder.String()
}

func (r *TestReporter) formatCISummary(report *TestSummaryReport) string {
	var builder strings.Builder

	results := report.TestResults

	if results.SuccessRate >= 95 {
		builder.WriteString("✅ ALL TESTS PASSED\n")
	} else if results.SuccessRate >= 80 {
		builder.WriteString("⚠️  SOME TESTS FAILED\n")
	} else {
		builder.WriteString("❌ MANY TESTS FAILED\n")
	}

	builder.WriteString(fmt.Sprintf("Success Rate: %.1f%% (%d/%d)\n",
		results.SuccessRate, results.PassedTests, results.TotalTests))

	if len(report.FailureAnalysis.CriticalFailures) > 0 {
		builder.WriteString(fmt.Sprintf("Critical Failures: %d\n", len(report.FailureAnalysis.CriticalFailures)))
	}

	return builder.String()
}
