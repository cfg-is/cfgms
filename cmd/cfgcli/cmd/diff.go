// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package cmd implements the diff command for cfgcli
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/features/config/diff"
)

var (
	// Diff command flags
	ignoreWhitespace bool
	ignoreComments   bool
	ignoreOrder      bool
	contextLines     int
	semanticDiff     bool
	impactAnalysis   bool
	filterByImpact   []string
	filterByCategory []string
	maxEntries       int
	includeSummary   bool
	includeMetadata  bool
	includeContext   bool
	colorizeOutput   bool
	lineNumbers      bool
	threeWay         bool
	baseRef          string
)

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff [FROM] [TO]",
	Short: "Compare configuration files or references",
	Long: `Compare configuration files, commits, or references and show differences.

The diff command supports various output formats and provides intelligent
analysis of configuration changes including impact assessment and semantic
understanding of configuration structures.

Examples:
  # Compare two files
  cfgcli diff config-old.yaml config-new.yaml

  # Compare with different output format
  cfgcli diff --output json config-old.yaml config-new.yaml

  # Three-way comparison
  cfgcli diff --three-way --base-ref main config-branch-1.yaml config-branch-2.yaml

  # Show only high impact changes
  cfgcli diff --filter-by-impact high,critical config-old.yaml config-new.yaml

  # Include impact analysis
  cfgcli diff --impact-analysis config-old.yaml config-new.yaml`,
	Args: cobra.RangeArgs(2, 3), // 2 for two-way, 3 for three-way
	RunE: runDiff,
}

func init() {
	// Diff options
	diffCmd.Flags().BoolVar(&ignoreWhitespace, "ignore-whitespace", false, "ignore whitespace differences")
	diffCmd.Flags().BoolVar(&ignoreComments, "ignore-comments", false, "ignore changes in comments")
	diffCmd.Flags().BoolVar(&ignoreOrder, "ignore-order", false, "ignore order changes in arrays/lists")
	diffCmd.Flags().IntVar(&contextLines, "context-lines", 3, "number of context lines to include")
	diffCmd.Flags().BoolVar(&semanticDiff, "semantic-diff", true, "enable semantic understanding of configuration")
	diffCmd.Flags().BoolVar(&impactAnalysis, "impact-analysis", true, "enable change impact analysis")

	// Filtering options
	diffCmd.Flags().StringSliceVar(&filterByImpact, "filter-by-impact", []string{}, "filter changes by impact level (low,medium,high,critical)")
	diffCmd.Flags().StringSliceVar(&filterByCategory, "filter-by-category", []string{}, "filter changes by category (structural,value,security,network,access,policy)")
	diffCmd.Flags().IntVar(&maxEntries, "max-entries", 0, "limit the number of entries in output (0 = no limit)")

	// Output options
	diffCmd.Flags().BoolVar(&includeSummary, "include-summary", true, "include summary in output")
	diffCmd.Flags().BoolVar(&includeMetadata, "include-metadata", false, "include metadata in output")
	diffCmd.Flags().BoolVar(&includeContext, "include-context", true, "include context information")
	diffCmd.Flags().BoolVar(&colorizeOutput, "colorize", true, "add color to output (for text formats)")
	diffCmd.Flags().BoolVar(&lineNumbers, "line-numbers", false, "include line numbers in output")

	// Three-way diff options
	diffCmd.Flags().BoolVar(&threeWay, "three-way", false, "perform three-way comparison")
	diffCmd.Flags().StringVar(&baseRef, "base-ref", "", "base reference for three-way comparison")
}

func runDiff(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Validate arguments
	if threeWay && len(args) != 3 {
		return fmt.Errorf("three-way comparison requires exactly 3 arguments: base, left, right")
	}
	if !threeWay && len(args) != 2 {
		return fmt.Errorf("two-way comparison requires exactly 2 arguments: from, to")
	}

	// Create diff engine with analyzers
	semanticAnalyzer := diff.NewDefaultSemanticAnalyzer()
	impactAnalyzer := diff.NewDefaultImpactAnalyzer()
	exporter := diff.NewDefaultExporter()
	engine := diff.NewDefaultEngine(semanticAnalyzer, impactAnalyzer, exporter)

	// Parse impact filter
	impactLevels, err := parseImpactLevels(filterByImpact)
	if err != nil {
		return fmt.Errorf("invalid impact filter: %w", err)
	}

	// Parse category filter
	categories, err := parseCategories(filterByCategory)
	if err != nil {
		return fmt.Errorf("invalid category filter: %w", err)
	}

	// Parse output format
	exportFormat, err := parseExportFormat(output)
	if err != nil {
		return fmt.Errorf("invalid output format: %w", err)
	}

	// Create diff options
	diffOptions := diff.DiffOptions{
		IgnoreWhitespace: ignoreWhitespace,
		IgnoreComments:   ignoreComments,
		IgnoreOrder:      ignoreOrder,
		ContextLines:     contextLines,
		SemanticDiff:     semanticDiff,
		ImpactAnalysis:   impactAnalysis,
	}

	// Create export options
	exportOptions := diff.ExportOptions{
		Format:           exportFormat,
		IncludeSummary:   includeSummary,
		IncludeMetadata:  includeMetadata,
		IncludeContext:   includeContext,
		ColorizeOutput:   colorizeOutput,
		LineNumbers:      lineNumbers,
		FilterByImpact:   impactLevels,
		FilterByCategory: categories,
		MaxEntries:       maxEntries,
	}

	if threeWay {
		return runThreeWayDiff(ctx, engine, args, diffOptions, exportOptions)
	}

	return runTwoWayDiff(ctx, engine, args, diffOptions, exportOptions)
}

func runTwoWayDiff(ctx context.Context, engine diff.DiffEngine, args []string, diffOptions diff.DiffOptions, exportOptions diff.ExportOptions) error {
	// Create configuration references
	fromRef, err := createConfigurationReference(args[0])
	if err != nil {
		return fmt.Errorf("failed to create from reference: %w", err)
	}

	toRef, err := createConfigurationReference(args[1])
	if err != nil {
		return fmt.Errorf("failed to create to reference: %w", err)
	}

	// Perform comparison
	if verbose {
		fmt.Fprintf(os.Stderr, "Comparing %s to %s...\n", args[0], args[1])
	}

	result, err := engine.Compare(ctx, *fromRef, *toRef, diffOptions)
	if err != nil {
		return fmt.Errorf("comparison failed: %w", err)
	}

	// Export results
	output, err := engine.Export(ctx, result, exportOptions)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Print results
	fmt.Print(string(output))

	// Exit with non-zero code if there are changes (for scripting)
	if result.Summary.TotalChanges > 0 {
		os.Exit(1)
	}

	return nil
}

func runThreeWayDiff(ctx context.Context, engine diff.DiffEngine, args []string, diffOptions diff.DiffOptions, exportOptions diff.ExportOptions) error {
	// Create configuration references
	baseRefObj, err := createConfigurationReference(args[0])
	if err != nil {
		return fmt.Errorf("failed to create base reference: %w", err)
	}

	leftRef, err := createConfigurationReference(args[1])
	if err != nil {
		return fmt.Errorf("failed to create left reference: %w", err)
	}

	rightRef, err := createConfigurationReference(args[2])
	if err != nil {
		return fmt.Errorf("failed to create right reference: %w", err)
	}

	// Perform three-way comparison
	if verbose {
		fmt.Fprintf(os.Stderr, "Three-way comparing %s, %s, %s...\n", args[0], args[1], args[2])
	}

	result, err := engine.ThreeWayCompare(ctx, *baseRefObj, *leftRef, *rightRef, diffOptions)
	if err != nil {
		return fmt.Errorf("three-way comparison failed: %w", err)
	}

	// Export results
	output, err := engine.ExportThreeWay(ctx, result, exportOptions)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Print results
	fmt.Print(string(output))

	// Exit with non-zero code if there are conflicts (for scripting)
	if result.Summary.Conflicts > 0 {
		os.Exit(1)
	}

	return nil
}

// Helper functions

func createConfigurationReference(path string) (*diff.ConfigurationReference, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", path)
	}

	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Get file info
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Create reference
	ref := &diff.ConfigurationReference{
		Repository: "local",
		Branch:     "current",
		Commit:     fmt.Sprintf("file-%d", info.ModTime().Unix()),
		Path:       absPath,
		Timestamp:  info.ModTime(),
		Author:     "local-user",
		Message:    fmt.Sprintf("Local file: %s", filepath.Base(path)),
	}

	return ref, nil
}

func parseImpactLevels(levels []string) ([]diff.ImpactLevel, error) {
	var impactLevels []diff.ImpactLevel

	for _, level := range levels {
		switch strings.ToLower(level) {
		case "low":
			impactLevels = append(impactLevels, diff.ImpactLevelLow)
		case "medium":
			impactLevels = append(impactLevels, diff.ImpactLevelMedium)
		case "high":
			impactLevels = append(impactLevels, diff.ImpactLevelHigh)
		case "critical":
			impactLevels = append(impactLevels, diff.ImpactLevelCritical)
		default:
			return nil, fmt.Errorf("invalid impact level: %s", level)
		}
	}

	return impactLevels, nil
}

func parseCategories(categories []string) ([]diff.ChangeCategory, error) {
	var changeCategories []diff.ChangeCategory

	for _, category := range categories {
		switch strings.ToLower(category) {
		case "structural":
			changeCategories = append(changeCategories, diff.ChangeCategoryStructural)
		case "value":
			changeCategories = append(changeCategories, diff.ChangeCategoryValue)
		case "security":
			changeCategories = append(changeCategories, diff.ChangeCategorySecurity)
		case "network":
			changeCategories = append(changeCategories, diff.ChangeCategoryNetwork)
		case "access":
			changeCategories = append(changeCategories, diff.ChangeCategoryAccess)
		case "policy":
			changeCategories = append(changeCategories, diff.ChangeCategoryPolicy)
		default:
			return nil, fmt.Errorf("invalid category: %s", category)
		}
	}

	return changeCategories, nil
}

func parseExportFormat(format string) (diff.ExportFormat, error) {
	switch strings.ToLower(format) {
	case "text":
		return diff.ExportFormatText, nil
	case "json":
		return diff.ExportFormatJSON, nil
	case "html":
		return diff.ExportFormatHTML, nil
	case "unified":
		return diff.ExportFormatUnified, nil
	case "side-by-side", "sidebyside":
		return diff.ExportFormatSideBySide, nil
	case "markdown", "md":
		return diff.ExportFormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}
