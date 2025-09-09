// Package diff implements export functionality for configuration diffs
package diff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// DefaultExporter implements the Exporter interface with support
// for multiple output formats
type DefaultExporter struct {
	// templates store HTML templates for rendering
	templates map[string]*template.Template
}

// NewDefaultExporter creates a new DefaultExporter
func NewDefaultExporter() *DefaultExporter {
	exporter := &DefaultExporter{
		templates: make(map[string]*template.Template),
	}
	exporter.initializeTemplates()
	return exporter
}

// ExportText exports as plain text
func (e *DefaultExporter) ExportText(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	
	// Apply filters
	filteredEntries := e.filterEntries(result.Entries, options)
	
	// Write header
	if options.IncludeSummary {
		buf.WriteString("Configuration Diff Report\n")
		buf.WriteString("========================\n\n")
		buf.WriteString(fmt.Sprintf("From: %s (%s)\n", result.FromRef.Repository, result.FromRef.Commit[:8]))
		buf.WriteString(fmt.Sprintf("To:   %s (%s)\n", result.ToRef.Repository, result.ToRef.Commit[:8]))
		buf.WriteString(fmt.Sprintf("Generated: %s\n\n", result.Metadata.CreatedAt.Format(time.RFC3339)))
		
		buf.WriteString("Summary:\n")
		buf.WriteString(fmt.Sprintf("  Total Changes: %d\n", result.Summary.TotalChanges))
		buf.WriteString(fmt.Sprintf("  Added:         %d\n", result.Summary.AddedItems))
		buf.WriteString(fmt.Sprintf("  Modified:      %d\n", result.Summary.ModifiedItems))
		buf.WriteString(fmt.Sprintf("  Deleted:       %d\n", result.Summary.DeletedItems))
		buf.WriteString(fmt.Sprintf("  Breaking:      %d\n", result.Summary.BreakingChanges))
		buf.WriteString("\n")
	}
	
	// Write changes
	buf.WriteString("Changes:\n")
	buf.WriteString("--------\n\n")
	
	for i, entry := range filteredEntries {
		if options.MaxEntries > 0 && i >= options.MaxEntries {
			buf.WriteString(fmt.Sprintf("... and %d more changes\n", len(filteredEntries)-i))
			break
		}
		
		// Format change entry
		e.formatTextEntry(&buf, entry, options)
		buf.WriteString("\n")
	}
	
	// Write metadata
	if options.IncludeMetadata {
		buf.WriteString("\nMetadata:\n")
		buf.WriteString("---------\n")
		buf.WriteString(fmt.Sprintf("Engine: %s v%s\n", result.Metadata.Engine, result.Metadata.Version))
		buf.WriteString(fmt.Sprintf("Duration: %v\n", result.Metadata.Duration))
		if len(result.Metadata.Warnings) > 0 {
			buf.WriteString("Warnings:\n")
			for _, warning := range result.Metadata.Warnings {
				buf.WriteString(fmt.Sprintf("  - %s\n", warning))
			}
		}
	}
	
	return buf.Bytes(), nil
}

// ExportJSON exports as JSON
func (e *DefaultExporter) ExportJSON(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	// Apply filters
	filteredResult := *result
	filteredResult.Entries = e.filterEntries(result.Entries, options)
	
	// Limit entries if specified
	if options.MaxEntries > 0 && len(filteredResult.Entries) > options.MaxEntries {
		filteredResult.Entries = filteredResult.Entries[:options.MaxEntries]
	}
	
	// Create export structure based on options
	export := make(map[string]interface{})
	
	if options.IncludeSummary {
		export["summary"] = filteredResult.Summary
	}
	
	export["entries"] = filteredResult.Entries
	
	if options.IncludeMetadata {
		export["metadata"] = filteredResult.Metadata
	}
	
	// Always include references
	export["from_ref"] = filteredResult.FromRef
	export["to_ref"] = filteredResult.ToRef
	export["id"] = filteredResult.ID
	
	return json.MarshalIndent(export, "", "  ")
}

// ExportHTML exports as HTML
func (e *DefaultExporter) ExportHTML(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	// Apply filters
	filteredEntries := e.filterEntries(result.Entries, options)
	
	// Limit entries if specified
	if options.MaxEntries > 0 && len(filteredEntries) > options.MaxEntries {
		filteredEntries = filteredEntries[:options.MaxEntries]
	}
	
	// Prepare template data
	data := struct {
		Result          *ComparisonResult
		Entries         []DiffEntry
		Options         ExportOptions
		GeneratedAt     string
		IncludeSummary  bool
		IncludeMetadata bool
	}{
		Result:          result,
		Entries:         filteredEntries,
		Options:         options,
		GeneratedAt:     time.Now().Format(time.RFC3339),
		IncludeSummary:  options.IncludeSummary,
		IncludeMetadata: options.IncludeMetadata,
	}
	
	// Render template
	var buf bytes.Buffer
	if err := e.templates["html"].Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to render HTML template: %w", err)
	}
	
	return buf.Bytes(), nil
}

// ExportUnified exports as unified diff format
func (e *DefaultExporter) ExportUnified(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	
	// Apply filters
	filteredEntries := e.filterEntries(result.Entries, options)
	
	// Write unified diff header
	buf.WriteString(fmt.Sprintf("--- %s\t%s\n", result.FromRef.Path, result.FromRef.Timestamp.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("+++ %s\t%s\n", result.ToRef.Path, result.ToRef.Timestamp.Format(time.RFC3339)))
	
	// Group changes by file/section for unified format
	changesByPath := e.groupChangesByPath(filteredEntries)
	
	for path, entries := range changesByPath {
		if options.MaxEntries > 0 && len(entries) > options.MaxEntries {
			entries = entries[:options.MaxEntries]
		}
		
		buf.WriteString(fmt.Sprintf("@@ %s @@\n", path))
		
		for _, entry := range entries {
			e.formatUnifiedEntry(&buf, entry, options)
		}
		buf.WriteString("\n")
	}
	
	return buf.Bytes(), nil
}

// ExportSideBySide exports as side-by-side diff
func (e *DefaultExporter) ExportSideBySide(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	
	// Apply filters
	filteredEntries := e.filterEntries(result.Entries, options)
	
	// Write header
	buf.WriteString(fmt.Sprintf("%-50s | %s\n", "OLD ("+result.FromRef.Commit[:8]+")", "NEW ("+result.ToRef.Commit[:8]+")"))
	buf.WriteString(strings.Repeat("-", 50) + " | " + strings.Repeat("-", 50) + "\n")
	
	for i, entry := range filteredEntries {
		if options.MaxEntries > 0 && i >= options.MaxEntries {
			buf.WriteString(fmt.Sprintf("... and %d more changes\n", len(filteredEntries)-i))
			break
		}
		
		e.formatSideBySideEntry(&buf, entry, options)
	}
	
	return buf.Bytes(), nil
}

// ExportMarkdown exports as Markdown
func (e *DefaultExporter) ExportMarkdown(ctx context.Context, result *ComparisonResult, options ExportOptions) ([]byte, error) {
	var buf bytes.Buffer
	
	// Apply filters
	filteredEntries := e.filterEntries(result.Entries, options)
	
	// Write header
	buf.WriteString("# Configuration Diff Report\n\n")
	
	if options.IncludeSummary {
		buf.WriteString("## Summary\n\n")
		buf.WriteString(fmt.Sprintf("- **From**: %s (`%s`)\n", result.FromRef.Repository, result.FromRef.Commit[:8]))
		buf.WriteString(fmt.Sprintf("- **To**: %s (`%s`)\n", result.ToRef.Repository, result.ToRef.Commit[:8]))
		buf.WriteString(fmt.Sprintf("- **Generated**: %s\n\n", result.Metadata.CreatedAt.Format(time.RFC3339)))
		
		buf.WriteString("### Change Statistics\n\n")
		buf.WriteString("| Type | Count |\n")
		buf.WriteString("|------|-------|\n")
		buf.WriteString(fmt.Sprintf("| Total | %d |\n", result.Summary.TotalChanges))
		buf.WriteString(fmt.Sprintf("| Added | %d |\n", result.Summary.AddedItems))
		buf.WriteString(fmt.Sprintf("| Modified | %d |\n", result.Summary.ModifiedItems))
		buf.WriteString(fmt.Sprintf("| Deleted | %d |\n", result.Summary.DeletedItems))
		buf.WriteString(fmt.Sprintf("| Breaking | %d |\n", result.Summary.BreakingChanges))
		buf.WriteString("\n")
	}
	
	// Write changes
	buf.WriteString("## Changes\n\n")
	
	for i, entry := range filteredEntries {
		if options.MaxEntries > 0 && i >= options.MaxEntries {
			buf.WriteString(fmt.Sprintf("*... and %d more changes*\n", len(filteredEntries)-i))
			break
		}
		
		e.formatMarkdownEntry(&buf, entry, options)
	}
	
	// Write metadata
	if options.IncludeMetadata {
		buf.WriteString("## Metadata\n\n")
		buf.WriteString(fmt.Sprintf("- **Engine**: %s v%s\n", result.Metadata.Engine, result.Metadata.Version))
		buf.WriteString(fmt.Sprintf("- **Duration**: %v\n", result.Metadata.Duration))
		
		if len(result.Metadata.Warnings) > 0 {
			buf.WriteString("- **Warnings**:\n")
			for _, warning := range result.Metadata.Warnings {
				buf.WriteString(fmt.Sprintf("  - %s\n", warning))
			}
		}
	}
	
	return buf.Bytes(), nil
}

// Helper methods

// filterEntries filters diff entries based on export options
func (e *DefaultExporter) filterEntries(entries []DiffEntry, options ExportOptions) []DiffEntry {
	var filtered []DiffEntry
	
	for _, entry := range entries {
		// Filter by impact level
		if len(options.FilterByImpact) > 0 {
			found := false
			for _, level := range options.FilterByImpact {
				if entry.Impact.Level == level {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Filter by category
		if len(options.FilterByCategory) > 0 {
			found := false
			for _, category := range options.FilterByCategory {
				if entry.Impact.Category == category {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		filtered = append(filtered, entry)
	}
	
	return filtered
}

// groupChangesByPath groups changes by their path prefix
func (e *DefaultExporter) groupChangesByPath(entries []DiffEntry) map[string][]DiffEntry {
	groups := make(map[string][]DiffEntry)
	
	for _, entry := range entries {
		// Use the parent path or the path itself as the group key
		groupKey := entry.Context.ParentPath
		if groupKey == "" {
			groupKey = entry.Path
		}
		
		groups[groupKey] = append(groups[groupKey], entry)
	}
	
	return groups
}

// formatTextEntry formats a diff entry for text output
func (e *DefaultExporter) formatTextEntry(buf *bytes.Buffer, entry DiffEntry, options ExportOptions) {
	// Write path and change type
	symbol := e.getChangeSymbol(entry.Type)
	fmt.Fprintf(buf, "%s %s", symbol, entry.Path)
	
	if options.LineNumbers && entry.Context.LineNumber > 0 {
		fmt.Fprintf(buf, " (line %d)", entry.Context.LineNumber)
	}
	buf.WriteString("\n")
	
	// Write change details
	switch entry.Type {
	case DiffTypeAdd:
		fmt.Fprintf(buf, "  + %v\n", formatValue(entry.NewValue))
	case DiffTypeDelete:
		fmt.Fprintf(buf, "  - %v\n", formatValue(entry.OldValue))
	case DiffTypeModify:
		fmt.Fprintf(buf, "  - %v\n", formatValue(entry.OldValue))
		fmt.Fprintf(buf, "  + %v\n", formatValue(entry.NewValue))
	case DiffTypeMove:
		fmt.Fprintf(buf, "  moved from: %s\n", entry.OldPath)
	}
	
	// Write impact information if requested
	if options.IncludeContext && entry.Impact.Level != ImpactLevelLow {
		fmt.Fprintf(buf, "  Impact: %s (%s)\n", entry.Impact.Level, entry.Impact.Category)
		if entry.Impact.Description != "" {
			fmt.Fprintf(buf, "  %s\n", entry.Impact.Description)
		}
	}
}

// formatUnifiedEntry formats a diff entry for unified diff output
func (e *DefaultExporter) formatUnifiedEntry(buf *bytes.Buffer, entry DiffEntry, options ExportOptions) {
	switch entry.Type {
	case DiffTypeAdd:
		fmt.Fprintf(buf, "+%s = %v\n", entry.Path, formatValue(entry.NewValue))
	case DiffTypeDelete:
		fmt.Fprintf(buf, "-%s = %v\n", entry.Path, formatValue(entry.OldValue))
	case DiffTypeModify:
		fmt.Fprintf(buf, "-%s = %v\n", entry.Path, formatValue(entry.OldValue))
		fmt.Fprintf(buf, "+%s = %v\n", entry.Path, formatValue(entry.NewValue))
	case DiffTypeMove:
		fmt.Fprintf(buf, "-%s\n", entry.OldPath)
		fmt.Fprintf(buf, "+%s\n", entry.Path)
	}
}

// formatSideBySideEntry formats a diff entry for side-by-side output
func (e *DefaultExporter) formatSideBySideEntry(buf *bytes.Buffer, entry DiffEntry, options ExportOptions) {
	leftSide := ""
	rightSide := ""
	
	switch entry.Type {
	case DiffTypeAdd:
		leftSide = ""
		rightSide = fmt.Sprintf("%s = %v", entry.Path, formatValue(entry.NewValue))
	case DiffTypeDelete:
		leftSide = fmt.Sprintf("%s = %v", entry.Path, formatValue(entry.OldValue))
		rightSide = ""
	case DiffTypeModify:
		leftSide = fmt.Sprintf("%s = %v", entry.Path, formatValue(entry.OldValue))
		rightSide = fmt.Sprintf("%s = %v", entry.Path, formatValue(entry.NewValue))
	case DiffTypeMove:
		leftSide = entry.OldPath
		rightSide = entry.Path
	}
	
	// Truncate if too long
	if len(leftSide) > 48 {
		leftSide = leftSide[:45] + "..."
	}
	if len(rightSide) > 48 {
		rightSide = rightSide[:45] + "..."
	}
	
	fmt.Fprintf(buf, "%-50s | %s\n", leftSide, rightSide)
}

// formatMarkdownEntry formats a diff entry for Markdown output
func (e *DefaultExporter) formatMarkdownEntry(buf *bytes.Buffer, entry DiffEntry, options ExportOptions) {
	// Write change header
	changeIcon := e.getChangeIcon(entry.Type)
	impactBadge := e.getImpactBadge(entry.Impact.Level)
	
	fmt.Fprintf(buf, "### %s `%s` %s\n\n", changeIcon, entry.Path, impactBadge)
	
	// Write change details
	switch entry.Type {
	case DiffTypeAdd:
		buf.WriteString("```diff\n")
		fmt.Fprintf(buf, "+ %v\n", formatValue(entry.NewValue))
		buf.WriteString("```\n\n")
	case DiffTypeDelete:
		buf.WriteString("```diff\n")
		fmt.Fprintf(buf, "- %v\n", formatValue(entry.OldValue))
		buf.WriteString("```\n\n")
	case DiffTypeModify:
		buf.WriteString("```diff\n")
		fmt.Fprintf(buf, "- %v\n", formatValue(entry.OldValue))
		fmt.Fprintf(buf, "+ %v\n", formatValue(entry.NewValue))
		buf.WriteString("```\n\n")
	case DiffTypeMove:
		fmt.Fprintf(buf, "**Moved from**: `%s`\n\n", entry.OldPath)
	}
	
	// Write impact information
	if options.IncludeContext && entry.Impact.Level != ImpactLevelLow {
		buf.WriteString("**Impact Details:**\n")
		fmt.Fprintf(buf, "- **Level**: %s\n", entry.Impact.Level)
		fmt.Fprintf(buf, "- **Category**: %s\n", entry.Impact.Category)
		if entry.Impact.Description != "" {
			fmt.Fprintf(buf, "- **Description**: %s\n", entry.Impact.Description)
		}
		if entry.Impact.BreakingChange {
			buf.WriteString("- **⚠️ Breaking Change**\n")
		}
		if len(entry.Impact.SecurityImplications) > 0 {
			buf.WriteString("- **🔒 Security Implications**: " + strings.Join(entry.Impact.SecurityImplications, ", ") + "\n")
		}
		buf.WriteString("\n")
	}
}

// getChangeSymbol returns a symbol for the change type
func (e *DefaultExporter) getChangeSymbol(changeType DiffType) string {
	switch changeType {
	case DiffTypeAdd:
		return "+"
	case DiffTypeDelete:
		return "-"
	case DiffTypeModify:
		return "~"
	case DiffTypeMove:
		return "→"
	default:
		return "?"
	}
}

// getChangeIcon returns an icon for the change type (for Markdown)
func (e *DefaultExporter) getChangeIcon(changeType DiffType) string {
	switch changeType {
	case DiffTypeAdd:
		return "✅"
	case DiffTypeDelete:
		return "❌"
	case DiffTypeModify:
		return "📝"
	case DiffTypeMove:
		return "📦"
	default:
		return "❓"
	}
}

// getImpactBadge returns a badge for the impact level (for Markdown)
func (e *DefaultExporter) getImpactBadge(level ImpactLevel) string {
	switch level {
	case ImpactLevelCritical:
		return "🔴 **Critical**"
	case ImpactLevelHigh:
		return "🟠 **High**"
	case ImpactLevelMedium:
		return "🟡 **Medium**"
	case ImpactLevelLow:
		return "🔵 **Low**"
	default:
		return ""
	}
}

// formatValue formats a value for display
func formatValue(value interface{}) string {
	if value == nil {
		return "<nil>"
	}
	
	switch v := value.(type) {
	case string:
		// Quote strings if they contain spaces or special characters
		if strings.ContainsAny(v, " \t\n\r\"'") {
			return fmt.Sprintf("%q", v)
		}
		return v
	case []interface{}:
		if len(v) <= 3 {
			var items []string
			for _, item := range v {
				items = append(items, formatValue(item))
			}
			return "[" + strings.Join(items, ", ") + "]"
		}
		return fmt.Sprintf("[%s, ... (%d items)]", formatValue(v[0]), len(v))
	case map[string]interface{}:
		if len(v) <= 2 {
			var items []string
			for key, val := range v {
				items = append(items, fmt.Sprintf("%s: %s", key, formatValue(val)))
			}
			return "{" + strings.Join(items, ", ") + "}"
		}
		return fmt.Sprintf("{...} (%d keys)", len(v))
	default:
		return fmt.Sprintf("%v", value)
	}
}

// initializeTemplates initializes HTML templates
func (e *DefaultExporter) initializeTemplates() {
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>Configuration Diff Report</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .header { border-bottom: 2px solid #ccc; padding-bottom: 10px; margin-bottom: 20px; }
        .summary { background: #f5f5f5; padding: 10px; margin: 10px 0; }
        .change { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }
        .add { border-left-color: #4CAF50; background: #f1f8e9; }
        .delete { border-left-color: #f44336; background: #ffebee; }
        .modify { border-left-color: #ff9800; background: #fff3e0; }
        .move { border-left-color: #2196f3; background: #e3f2fd; }
        .path { font-weight: bold; }
        .value { margin: 5px 0; padding: 5px; background: white; }
        .impact { font-size: 0.9em; color: #666; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #1976d2; }
        .low { color: #388e3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Configuration Diff Report</h1>
        <p>From: {{.Result.FromRef.Repository}} ({{printf "%.8s" .Result.FromRef.Commit}})</p>
        <p>To: {{.Result.ToRef.Repository}} ({{printf "%.8s" .Result.ToRef.Commit}})</p>
        <p>Generated: {{.GeneratedAt}}</p>
    </div>
    
    {{if .IncludeSummary}}
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Total Changes: {{.Result.Summary.TotalChanges}}</li>
            <li>Added: {{.Result.Summary.AddedItems}}</li>
            <li>Modified: {{.Result.Summary.ModifiedItems}}</li>
            <li>Deleted: {{.Result.Summary.DeletedItems}}</li>
            <li>Breaking Changes: {{.Result.Summary.BreakingChanges}}</li>
        </ul>
    </div>
    {{end}}
    
    <h2>Changes</h2>
    {{range .Entries}}
    <div class="change {{.Type}}">
        <div class="path">{{.Path}}</div>
        {{if eq .Type "add"}}
            <div class="value">+ {{printf "%v" .NewValue}}</div>
        {{else if eq .Type "delete"}}
            <div class="value">- {{printf "%v" .OldValue}}</div>
        {{else if eq .Type "modify"}}
            <div class="value">- {{printf "%v" .OldValue}}</div>
            <div class="value">+ {{printf "%v" .NewValue}}</div>
        {{else if eq .Type "move"}}
            <div class="value">Moved from: {{.OldPath}}</div>
        {{end}}
        <div class="impact {{.Impact.Level}}">
            Impact: {{.Impact.Level}} ({{.Impact.Category}})
            {{if .Impact.Description}} - {{.Impact.Description}}{{end}}
        </div>
    </div>
    {{end}}
    
    {{if .IncludeMetadata}}
    <div class="summary">
        <h2>Metadata</h2>
        <ul>
            <li>Engine: {{.Result.Metadata.Engine}} v{{.Result.Metadata.Version}}</li>
            <li>Duration: {{.Result.Metadata.Duration}}</li>
            {{if .Result.Metadata.Warnings}}
            <li>Warnings:
                <ul>
                {{range .Result.Metadata.Warnings}}
                    <li>{{.}}</li>
                {{end}}
                </ul>
            </li>
            {{end}}
        </ul>
    </div>
    {{end}}
</body>
</html>`
	
	tmpl, err := template.New("html").Parse(htmlTemplate)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse HTML template: %v", err))
	}
	
	e.templates["html"] = tmpl
}