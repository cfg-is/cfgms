// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package diff implements the core DiffEngine for configuration comparison and analysis
package diff

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultEngine implements the DiffEngine interface with comprehensive
// configuration comparison capabilities
type DefaultEngine struct {
	semanticAnalyzer SemanticAnalyzer
	impactAnalyzer   ImpactAnalyzer
	exporter         Exporter
}

// NewDefaultEngine creates a new DefaultEngine with the provided analyzers
func NewDefaultEngine(semantic SemanticAnalyzer, impact ImpactAnalyzer, exporter Exporter) *DefaultEngine {
	return &DefaultEngine{
		semanticAnalyzer: semantic,
		impactAnalyzer:   impact,
		exporter:         exporter,
	}
}

// Compare performs a two-way comparison between configurations
func (e *DefaultEngine) Compare(ctx context.Context, from, to ConfigurationReference, options DiffOptions) (*ComparisonResult, error) {
	start := time.Now()

	// Generate unique comparison ID
	comparisonID := generateComparisonID(from, to)

	// Load configuration content
	fromContent, err := e.loadConfiguration(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("failed to load source configuration: %w", err)
	}

	toContent, err := e.loadConfiguration(ctx, to)
	if err != nil {
		return nil, fmt.Errorf("failed to load target configuration: %w", err)
	}

	// Parse configurations based on format
	fromData, err := e.parseConfiguration(fromContent, detectFormat(from.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to parse source configuration: %w", err)
	}

	toData, err := e.parseConfiguration(toContent, detectFormat(to.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to parse target configuration: %w", err)
	}

	// Perform the comparison
	entries := e.compareData("", fromData, toData, options)

	// Calculate summary
	summary := e.calculateSummary(entries)

	// Create comparison result
	result := &ComparisonResult{
		ID:      comparisonID,
		FromRef: from,
		ToRef:   to,
		Summary: summary,
		Entries: entries,
		Metadata: ComparisonMetadata{
			CreatedAt: start,
			Duration:  time.Since(start),
			Engine:    "DefaultEngine",
			Version:   "1.0.0",
			Options:   options,
		},
	}

	// Perform impact analysis if enabled
	if options.ImpactAnalysis && e.impactAnalyzer != nil {
		if err := e.AnalyzeImpact(ctx, result); err != nil {
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				fmt.Sprintf("Impact analysis failed: %v", err))
		}
	}

	return result, nil
}

// ThreeWayCompare performs a three-way comparison
func (e *DefaultEngine) ThreeWayCompare(ctx context.Context, base, left, right ConfigurationReference, options DiffOptions) (*ThreeWayDiffResult, error) {
	start := time.Now()

	// Perform base to left comparison
	baseToLeft, err := e.Compare(ctx, base, left, options)
	if err != nil {
		return nil, fmt.Errorf("failed to compare base to left: %w", err)
	}

	// Perform base to right comparison
	baseToRight, err := e.Compare(ctx, base, right, options)
	if err != nil {
		return nil, fmt.Errorf("failed to compare base to right: %w", err)
	}

	// Detect conflicts
	conflicts := e.detectConflicts(baseToLeft.Entries, baseToRight.Entries)

	// Calculate three-way summary
	summary := ThreeWayDiffSummary{
		LeftChanges:      len(baseToLeft.Entries),
		RightChanges:     len(baseToRight.Entries),
		Conflicts:        len(conflicts),
		AutoResolvable:   e.countAutoResolvable(conflicts),
		ManualResolution: e.countManualResolution(conflicts),
	}

	return &ThreeWayDiffResult{
		BaseRef:     base,
		LeftRef:     left,
		RightRef:    right,
		BaseToLeft:  baseToLeft.Entries,
		BaseToRight: baseToRight.Entries,
		Conflicts:   conflicts,
		Summary:     summary,
		Metadata: ComparisonMetadata{
			CreatedAt: start,
			Duration:  time.Since(start),
			Engine:    "DefaultEngine",
			Version:   "1.0.0",
			Options:   options,
		},
	}, nil
}

// AnalyzeImpact analyzes the impact of changes
func (e *DefaultEngine) AnalyzeImpact(ctx context.Context, result *ComparisonResult) error {
	if e.impactAnalyzer == nil {
		return fmt.Errorf("no impact analyzer configured")
	}

	// Get configuration structure for analysis
	var structure *ConfigStructure
	if e.semanticAnalyzer != nil {
		fromContent, err := e.loadConfiguration(ctx, result.FromRef)
		if err != nil {
			return fmt.Errorf("failed to load configuration for impact analysis: %w", err)
		}

		structure, err = e.semanticAnalyzer.AnalyzeStructure(ctx, fromContent, detectFormat(result.FromRef.Path))
		if err != nil {
			return fmt.Errorf("failed to analyze configuration structure: %w", err)
		}
	}

	// Analyze impact for each entry
	for i := range result.Entries {
		impact, err := e.impactAnalyzer.AnalyzeChange(ctx, &result.Entries[i], structure)
		if err != nil {
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				fmt.Sprintf("Impact analysis failed for %s: %v", result.Entries[i].Path, err))
			continue
		}
		result.Entries[i].Impact = *impact
	}

	// Update summary with impact information
	result.Summary = e.calculateSummaryWithImpact(result.Entries)

	return nil
}

// Export exports diff results in various formats
func (e *DefaultEngine) Export(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	if e.exporter == nil {
		return nil, fmt.Errorf("no exporter configured")
	}

	switch options.Format {
	case ExportFormatText:
		return e.exporter.ExportText(ctx, result, options)
	case ExportFormatJSON:
		return e.exporter.ExportJSON(ctx, result, options)
	case ExportFormatHTML:
		return e.exporter.ExportHTML(ctx, result, options)
	case ExportFormatUnified:
		return e.exporter.ExportUnified(ctx, result, options)
	case ExportFormatSideBySide:
		return e.exporter.ExportSideBySide(ctx, result, options)
	case ExportFormatMarkdown:
		return e.exporter.ExportMarkdown(ctx, result, options)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", options.Format)
	}
}

// ExportThreeWay exports three-way diff results
func (e *DefaultEngine) ExportThreeWay(ctx context.Context, result *ThreeWayDiffResult, options ExportOptions) ([]byte, error) {
	// Convert three-way result to comparison result for export
	comparisonResult := &ComparisonResult{
		ID: fmt.Sprintf("3way-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s",
			result.BaseRef.Commit, result.LeftRef.Commit, result.RightRef.Commit)))),
		FromRef: result.LeftRef,
		ToRef:   result.RightRef,
		Summary: DiffSummary{
			TotalChanges: result.Summary.LeftChanges + result.Summary.RightChanges,
		},
		Entries:  append(result.BaseToLeft, result.BaseToRight...),
		Metadata: result.Metadata,
	}

	return e.Export(ctx, comparisonResult, options)
}

// compareData recursively compares two data structures
func (e *DefaultEngine) compareData(path string, from, to interface{}, options DiffOptions) []DiffEntry {
	var entries []DiffEntry

	// Handle nil cases
	if from == nil && to == nil {
		return entries
	}
	if from == nil {
		entries = append(entries, DiffEntry{
			Path:     path,
			Type:     DiffTypeAdd,
			NewValue: to,
			Context: DiffContext{
				ParentPath: getParentPath(path),
			},
		})
		return entries
	}
	if to == nil {
		entries = append(entries, DiffEntry{
			Path:     path,
			Type:     DiffTypeDelete,
			OldValue: from,
			Context: DiffContext{
				ParentPath: getParentPath(path),
			},
		})
		return entries
	}

	// Get reflection values
	fromVal := reflect.ValueOf(from)
	toVal := reflect.ValueOf(to)

	// Handle different types
	if fromVal.Type() != toVal.Type() {
		entries = append(entries, DiffEntry{
			Path:     path,
			Type:     DiffTypeModify,
			OldValue: from,
			NewValue: to,
			Context: DiffContext{
				ParentPath: getParentPath(path),
			},
		})
		return entries
	}

	switch fromVal.Kind() {
	case reflect.Map:
		entries = append(entries, e.compareMaps(path, fromVal, toVal, options)...)
	case reflect.Slice, reflect.Array:
		entries = append(entries, e.compareSlices(path, fromVal, toVal, options)...)
	default:
		// Compare primitive values
		if !reflect.DeepEqual(from, to) {
			entries = append(entries, DiffEntry{
				Path:     path,
				Type:     DiffTypeModify,
				OldValue: from,
				NewValue: to,
				Context: DiffContext{
					ParentPath: getParentPath(path),
				},
			})
		}
	}

	return entries
}

// compareMaps compares two maps
func (e *DefaultEngine) compareMaps(path string, from, to reflect.Value, options DiffOptions) []DiffEntry {
	var entries []DiffEntry

	fromMap := from.Interface().(map[string]interface{})
	toMap := to.Interface().(map[string]interface{})

	// Track all keys
	allKeys := make(map[string]bool)
	for key := range fromMap {
		allKeys[key] = true
	}
	for key := range toMap {
		allKeys[key] = true
	}

	// Compare each key
	for key := range allKeys {
		keyPath := buildPath(path, key)
		fromVal, fromExists := fromMap[key]
		toVal, toExists := toMap[key]

		if !fromExists {
			// Key added
			entries = append(entries, DiffEntry{
				Path:     keyPath,
				Type:     DiffTypeAdd,
				NewValue: toVal,
				Context: DiffContext{
					ParentPath: path,
					Section:    key,
				},
			})
		} else if !toExists {
			// Key deleted
			entries = append(entries, DiffEntry{
				Path:     keyPath,
				Type:     DiffTypeDelete,
				OldValue: fromVal,
				Context: DiffContext{
					ParentPath: path,
					Section:    key,
				},
			})
		} else {
			// Key exists in both, compare values
			entries = append(entries, e.compareData(keyPath, fromVal, toVal, options)...)
		}
	}

	return entries
}

// compareSlices compares two slices
func (e *DefaultEngine) compareSlices(path string, from, to reflect.Value, options DiffOptions) []DiffEntry {
	var entries []DiffEntry

	fromLen := from.Len()
	toLen := to.Len()
	maxLen := fromLen
	if toLen > maxLen {
		maxLen = toLen
	}

	// Handle ignore order option
	if options.IgnoreOrder {
		return e.compareSlicesIgnoreOrder(path, from, to, options)
	}

	// Compare each element by index
	for i := 0; i < maxLen; i++ {
		indexPath := fmt.Sprintf("%s[%d]", path, i)

		if i >= fromLen {
			// Element added
			entries = append(entries, DiffEntry{
				Path:     indexPath,
				Type:     DiffTypeAdd,
				NewValue: to.Index(i).Interface(),
				Context: DiffContext{
					ParentPath: path,
				},
			})
		} else if i >= toLen {
			// Element deleted
			entries = append(entries, DiffEntry{
				Path:     indexPath,
				Type:     DiffTypeDelete,
				OldValue: from.Index(i).Interface(),
				Context: DiffContext{
					ParentPath: path,
				},
			})
		} else {
			// Element exists in both, compare
			entries = append(entries, e.compareData(indexPath,
				from.Index(i).Interface(), to.Index(i).Interface(), options)...)
		}
	}

	return entries
}

// compareSlicesIgnoreOrder compares slices while ignoring order
func (e *DefaultEngine) compareSlicesIgnoreOrder(path string, from, to reflect.Value, options DiffOptions) []DiffEntry {
	var entries []DiffEntry

	// Convert slices to comparable format
	fromItems := make([]interface{}, from.Len())
	toItems := make([]interface{}, to.Len())

	for i := 0; i < from.Len(); i++ {
		fromItems[i] = from.Index(i).Interface()
	}
	for i := 0; i < to.Len(); i++ {
		toItems[i] = to.Index(i).Interface()
	}

	// Find matching items
	used := make([]bool, len(toItems))

	for i, fromItem := range fromItems {
		found := false
		for j, toItem := range toItems {
			if used[j] {
				continue
			}
			if reflect.DeepEqual(fromItem, toItem) {
				used[j] = true
				found = true
				break
			}
		}

		if !found {
			// Item deleted
			entries = append(entries, DiffEntry{
				Path:     fmt.Sprintf("%s[%d]", path, i),
				Type:     DiffTypeDelete,
				OldValue: fromItem,
				Context: DiffContext{
					ParentPath: path,
				},
			})
		}
	}

	// Find added items
	for j, toItem := range toItems {
		if !used[j] {
			entries = append(entries, DiffEntry{
				Path:     fmt.Sprintf("%s[%d]", path, j),
				Type:     DiffTypeAdd,
				NewValue: toItem,
				Context: DiffContext{
					ParentPath: path,
				},
			})
		}
	}

	return entries
}

// detectConflicts detects conflicts between left and right changes
func (e *DefaultEngine) detectConflicts(leftEntries, rightEntries []DiffEntry) []MergeConflict {
	var conflicts []MergeConflict

	// Group entries by path
	leftByPath := make(map[string]DiffEntry)
	rightByPath := make(map[string]DiffEntry)

	for _, entry := range leftEntries {
		leftByPath[entry.Path] = entry
	}
	for _, entry := range rightEntries {
		rightByPath[entry.Path] = entry
	}

	// Find conflicting paths
	for path, leftEntry := range leftByPath {
		if rightEntry, exists := rightByPath[path]; exists {
			conflict := e.analyzeConflict(path, leftEntry, rightEntry)
			if conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	return conflicts
}

// analyzeConflict analyzes a potential conflict between two changes
func (e *DefaultEngine) analyzeConflict(path string, left, right DiffEntry) *MergeConflict {
	// If both changes are identical, no conflict
	if reflect.DeepEqual(left, right) {
		return nil
	}

	var conflictType ConflictType
	var strategy ResolutionStrategy

	switch {
	case left.Type == DiffTypeModify && right.Type == DiffTypeModify:
		conflictType = ConflictTypeModifyModify
		strategy = ResolutionStrategyManual
	case left.Type == DiffTypeAdd && right.Type == DiffTypeAdd:
		conflictType = ConflictTypeAddAdd
		if reflect.DeepEqual(left.NewValue, right.NewValue) {
			strategy = ResolutionStrategyMerge
		} else {
			strategy = ResolutionStrategyManual
		}
	case left.Type == DiffTypeDelete && right.Type == DiffTypeModify:
		conflictType = ConflictTypeDeleteModify
		strategy = ResolutionStrategyManual
	case left.Type == DiffTypeModify && right.Type == DiffTypeDelete:
		conflictType = ConflictTypeModifyDelete
		strategy = ResolutionStrategyManual
	default:
		return nil
	}

	return &MergeConflict{
		Path:               path,
		LeftValue:          getChangeValue(left),
		RightValue:         getChangeValue(right),
		ConflictType:       conflictType,
		ResolutionStrategy: strategy,
	}
}

// Helper functions

func generateComparisonID(from, to ConfigurationReference) string {
	data := fmt.Sprintf("%s-%s-%s-%s", from.Repository, from.Commit, to.Repository, to.Commit)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

func (e *DefaultEngine) loadConfiguration(ctx context.Context, ref ConfigurationReference) ([]byte, error) {
	// For local files, read directly from filesystem
	if ref.Repository == "local" {
		content, err := os.ReadFile(ref.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", ref.Path, err)
		}
		return content, nil
	}

	// For Git repositories, this would integrate with Git backend
	// For now, return error for unsupported repositories
	return nil, fmt.Errorf("repository loading not implemented for: %s", ref.Repository)
}

func (e *DefaultEngine) parseConfiguration(content []byte, format string) (interface{}, error) {
	var data interface{}

	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(content, &data); err != nil {
			return nil, err
		}
	case "yaml", "yml":
		if err := yaml.Unmarshal(content, &data); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return data, nil
}

func detectFormat(path string) string {
	if strings.HasSuffix(path, ".json") {
		return "json"
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return "yaml"
	}
	return "json" // default
}

func (e *DefaultEngine) calculateSummary(entries []DiffEntry) DiffSummary {
	summary := DiffSummary{
		TotalChanges:      len(entries),
		ImpactBreakdown:   make(map[ImpactLevel]int),
		CategoryBreakdown: make(map[ChangeCategory]int),
	}

	for _, entry := range entries {
		switch entry.Type {
		case DiffTypeAdd:
			summary.AddedItems++
		case DiffTypeDelete:
			summary.DeletedItems++
		case DiffTypeModify:
			summary.ModifiedItems++
		case DiffTypeMove:
			summary.MovedItems++
		}

		// Count impact and category (will be filled by impact analysis)
		summary.ImpactBreakdown[entry.Impact.Level]++
		summary.CategoryBreakdown[entry.Impact.Category]++

		if entry.Impact.BreakingChange {
			summary.BreakingChanges++
		}
		if entry.Impact.Category == ChangeCategorySecurity {
			summary.SecurityChanges++
		}
	}

	return summary
}

func (e *DefaultEngine) calculateSummaryWithImpact(entries []DiffEntry) DiffSummary {
	return e.calculateSummary(entries) // Same implementation for now
}

func (e *DefaultEngine) countAutoResolvable(conflicts []MergeConflict) int {
	count := 0
	for _, conflict := range conflicts {
		if conflict.ResolutionStrategy != ResolutionStrategyManual {
			count++
		}
	}
	return count
}

func (e *DefaultEngine) countManualResolution(conflicts []MergeConflict) int {
	count := 0
	for _, conflict := range conflicts {
		if conflict.ResolutionStrategy == ResolutionStrategyManual {
			count++
		}
	}
	return count
}

func buildPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func getParentPath(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

func getChangeValue(entry DiffEntry) interface{} {
	switch entry.Type {
	case DiffTypeAdd:
		return entry.NewValue
	case DiffTypeDelete:
		return entry.OldValue
	case DiffTypeModify:
		return entry.NewValue
	default:
		return entry.NewValue
	}
}
