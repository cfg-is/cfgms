// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import (
	"path/filepath"
	"strings"
)

// annotationPrefix introduces a justification comment.
const annotationPrefix = "//duplication:justified"

// InvalidAnnotation is a justification comment that exempts nothing.
type InvalidAnnotation struct {
	File   string
	Line   int
	Reason string
}

// annotation is a parsed justification comment. err is non-empty when the
// comment is malformed.
type annotation struct {
	line   int
	path   string
	reason string
	err    string
}

// parseAnnotations extracts annotations from comments. Grammar:
//
//	//duplication:justified <repo-relative-path> -- <reason>
func parseAnnotations(comments []comment) []annotation {
	var out []annotation
	for _, c := range comments {
		rest, ok := strings.CutPrefix(c.text, annotationPrefix)
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		a := annotation{line: c.line}
		rest = strings.TrimSpace(rest)
		fields := strings.Fields(rest)
		switch {
		case len(fields) == 0:
			a.err = "malformed annotation: missing path"
		case len(fields) < 2 || fields[1] != "--":
			a.err = "malformed annotation: expected '<path> -- <reason>'"
		default:
			a.path = filepath.ToSlash(fields[0])
			after := strings.TrimSpace(strings.TrimPrefix(rest, fields[0]))
			a.reason = strings.TrimSpace(strings.TrimPrefix(after, "--"))
			if a.reason == "" {
				a.err = "empty reason"
			}
		}
		out = append(out, a)
	}
	return out
}

// attachWindow is how many lines below a comment its run may start.
const attachWindow = 3

// attachRun returns the index of the run the comment line belongs to, or -1.
// A run containing the line wins; otherwise the run whose first token line is
// within attachWindow lines below it (nearest first). Runs are in source order.
func attachRun(runs []runSpan, line int) int {
	for i, r := range runs {
		if r.startLine <= line && line <= r.endLine {
			return i
		}
	}
	best, bestDist := -1, attachWindow+1
	for i, r := range runs {
		if d := r.startLine - line; d >= 1 && d < bestDist {
			best, bestDist = i, d
		}
	}
	return best
}
