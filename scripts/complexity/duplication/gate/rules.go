// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package gate holds the duplication no-worsening rules as pure functions over
// detector Results. It performs no IO and runs no git commands.
//
// Runs are compared by token count, never by line span, so adding a comment or
// an annotation inside a clone does not read as growth. Annotated runs are
// already excluded from Result.Runs and Result.Mult by the detector, and a copy
// with an invalid annotation is an ordinary run there, so no rule here looks at
// annotations.
package gate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/duplication/detector"
)

// Finding is one gate failure.
type Finding struct {
	Rule   int // 1, 2 or 3
	File   string
	Line   int
	Detail string
	Base   int // rule 1 only: previous duplicated lines
	Cur    int // rule 1 only: current duplicated lines
}

// String renders the finding as `<file>:<line>: rule N: <detail>`.
func (f Finding) String() string {
	if f.Rule == 1 {
		return fmt.Sprintf("aggregate: rule 1: duplicated lines %d -> %d", f.Base, f.Cur)
	}
	return fmt.Sprintf("%s:%d: rule %d: %s", f.File, f.Line, f.Rule, f.Detail)
}

// slash normalises a path to forward slashes. filepath.ToSlash alone is a
// no-op on Linux, so backslashes are replaced explicitly as well.
func slash(p string) string { return strings.ReplaceAll(filepath.ToSlash(p), "\\", "/") }

func touchedSet(touched []string) map[string]bool {
	set := make(map[string]bool, len(touched))
	for _, t := range touched {
		set[slash(t)] = true
	}
	return set
}

// Rule1Aggregate fails when current has more duplicated lines than previous.
func Rule1Aggregate(previous, current detector.Result) []Finding {
	if current.DuplicatedLines <= previous.DuplicatedLines {
		return nil
	}
	return []Finding{{Rule: 1, Base: previous.DuplicatedLines, Cur: current.DuplicatedLines}}
}

// isNewClone reports whether no window of r existed as duplicated content in
// previous.
func isNewClone(previous detector.Result, r detector.Run) bool {
	for _, h := range r.Windows {
		if previous.Mult[h] > 0 {
			return false
		}
	}
	return true
}

// Rule2NewClone fails for every current run in a touched file none of whose
// windows were duplicated in previous (entirely new duplicated content).
func Rule2NewClone(previous, current detector.Result, touched []string) []Finding {
	set := touchedSet(touched)
	var out []Finding
	for _, r := range current.Runs {
		if !set[slash(r.File)] || !isNewClone(previous, r) {
			continue
		}
		out = append(out, Finding{Rule: 2, File: r.File, Line: r.StartLine,
			Detail: fmt.Sprintf("new duplicated block of %d tokens", r.Tokens)})
	}
	sortFindings(out)
	return out
}

// Rule3Growth fails for every current run in a touched file, not already a
// rule 2 finding, that either has a window with more copies than in previous
// (3a) or is longer in tokens than the longest previous run of the same path
// sharing a window with it (3b).
func Rule3Growth(previous, current detector.Result, touched []string) []Finding {
	set := touchedSet(touched)
	prevByPath := map[string][]detector.Run{}
	for _, p := range previous.Runs {
		k := slash(p.File)
		prevByPath[k] = append(prevByPath[k], p)
	}
	var out []Finding
	for _, r := range current.Runs {
		if !set[slash(r.File)] || isNewClone(previous, r) {
			continue
		}
		if detail, ok := growth(previous, current, prevByPath[slash(r.File)], r); ok {
			out = append(out, Finding{Rule: 3, File: r.File, Line: r.StartLine, Detail: detail})
		}
	}
	sortFindings(out)
	return out
}

func growth(previous, current detector.Result, samePath []detector.Run, r detector.Run) (string, bool) {
	for _, h := range r.Windows {
		if pm := previous.Mult[h]; pm > 0 && current.Mult[h] > pm {
			return fmt.Sprintf("extra copy of existing duplicated block (%d -> %d copies)", pm, current.Mult[h]), true
		}
	}
	cur := make(map[uint64]bool, len(r.Windows))
	for _, h := range r.Windows {
		cur[h] = true
	}
	longest := -1
	for _, p := range samePath {
		for _, h := range p.Windows {
			if cur[h] {
				if p.Tokens > longest {
					longest = p.Tokens
				}
				break
			}
		}
	}
	if longest >= 0 && r.Tokens > longest {
		return fmt.Sprintf("duplicated block grew %d -> %d tokens", longest, r.Tokens), true
	}
	return "", false
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].File != f[j].File {
			return f[i].File < f[j].File
		}
		if f[i].Line != f[j].Line {
			return f[i].Line < f[j].Line
		}
		return f[i].Rule < f[j].Rule
	})
}
