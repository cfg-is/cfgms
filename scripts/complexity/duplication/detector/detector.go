// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package detector finds Type-1/2 clones in Go source with hashed K-token
// windows. It is a pure library: it performs no IO and runs no git commands.
//
// Unit: go/scanner tokens with comments dropped from the stream, the package
// clause and import declarations skipped, every identifier one IDENT token,
// literals one token per kind, keywords and operators verbatim.
//
// Algorithm: every K-token window of every file gets a rolling 64-bit hash
// (K is the threshold). Windows are bucketed tree-wide by hash and each bucket
// is verified by comparing the actual tokens, so a hash collision never creates
// a clone. A window is in a clone iff its verified bucket holds another window
// that is in a different file or whose token range does not intersect its own.
// A run is a maximal sequence of consecutive in-clone windows of one file.
//
// Annotations: "//duplication:justified <repo-relative-path> -- <reason>"
// attaches to the run containing the comment line, else to the run starting
// within the 3 lines below it (nearest wins). It is valid iff the reason is
// non-empty and the named path is the file of another position in the same
// verified bucket as some window of the run. Validity is judged on buckets
// built from all positions, so mutual annotation (A names B, B names A) is
// valid for both. Annotated runs are then removed and Runs, Mult and the line
// totals are recomputed from the remaining windows. An invalid annotation
// exempts nothing and is reported in Result.InvalidAnnotations.
package detector

import (
	"fmt"
	"slices"
	"sort"
)

// DefaultThreshold is the starting window size in tokens.
const DefaultThreshold = 150

// File is one Go source file.
type File struct {
	Path string
	Src  []byte
}

// Run is a maximal sequence of consecutive in-clone windows in one file.
type Run struct {
	File      string
	StartLine int
	EndLine   int
	Tokens    int      // last window end minus first window start
	Windows   []uint64 // window hashes in order; len == Tokens-K+1
}

// Result is the outcome of Detect.
type Result struct {
	Runs               []Run
	DuplicatedLines    int            // distinct (file, line) pairs in unannotated runs
	AnnotatedLines     int            // the same measure over annotated runs
	Mult               map[uint64]int // window hash -> unannotated in-clone positions
	InvalidAnnotations []InvalidAnnotation
}

// runSpan is a run in window indexes and lines.
type runSpan struct {
	startWin, endWin   int
	startLine, endLine int
}

// entry is one window position.
type entry struct {
	hash  uint64
	file  int32
	start int32
}

// group is a verified bucket: members have identical tokens. Members are
// ordered by (file, start).
type group struct {
	hash    uint64
	members []entry
}

// Detect finds clone runs across files using windows of threshold tokens.
func Detect(files []File, threshold int) (Result, error) {
	if threshold < 2 {
		return Result{}, fmt.Errorf("detector: threshold %d below 2", threshold)
	}
	ordered := slices.Clone(files)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return string(ordered[i].Src) < string(ordered[j].Src)
	})

	fts := make([]fileTokens, len(ordered))
	var entries []entry
	for i, f := range ordered {
		fts[i] = tokenize(f.Path, f.Src)
		for s, h := range windowHashes(fts[i].kinds, threshold) {
			entries = append(entries, entry{hash: h, file: int32(i), start: int32(s)})
		}
	}
	groups := buildGroups(fts, entries, threshold)

	groupOf := make([][]int32, len(fts))
	for i := range fts {
		groupOf[i] = make([]int32, max(len(fts[i].kinds)-threshold+1, 0))
		for j := range groupOf[i] {
			groupOf[i][j] = -1
		}
	}
	for gi, g := range groups {
		for _, m := range g.members {
			groupOf[m.file][m.start] = int32(gi)
		}
	}

	d := &detection{fts: fts, groups: groups, groupOf: groupOf, k: threshold}
	inClone := d.evaluate(nil)
	runs1 := d.runs(inClone)

	annotated, invalid := d.resolveAnnotations(runs1)

	removed := make([][]bool, len(fts))
	for i := range fts {
		removed[i] = make([]bool, len(groupOf[i]))
		for ri, r := range runs1[i] {
			if annotated[[2]int{i, ri}] {
				for w := r.startWin; w <= r.endWin; w++ {
					removed[i][w] = true
				}
			}
		}
	}
	inClone2 := d.evaluate(removed)
	runs2 := d.runs(inClone2)

	res := Result{Mult: map[uint64]int{}, InvalidAnnotations: invalid}
	for i := range fts {
		for _, r := range runs2[i] {
			hs := make([]uint64, 0, r.endWin-r.startWin+1)
			for w := r.startWin; w <= r.endWin; w++ {
				h := groups[groupOf[i][w]].hash
				hs = append(hs, h)
				res.Mult[h]++
			}
			res.Runs = append(res.Runs, Run{
				File: fts[i].path, StartLine: r.startLine, EndLine: r.endLine,
				Tokens: r.endWin + threshold - r.startWin, Windows: hs,
			})
		}
		res.DuplicatedLines += d.countLines(i, runs2[i])
		var ann []runSpan
		for ri, r := range runs1[i] {
			if annotated[[2]int{i, ri}] {
				ann = append(ann, r)
			}
		}
		res.AnnotatedLines += d.countLines(i, ann)
	}
	sort.SliceStable(res.InvalidAnnotations, func(a, b int) bool {
		x, y := res.InvalidAnnotations[a], res.InvalidAnnotations[b]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Reason < y.Reason
	})
	return res, nil
}

// buildGroups buckets entries by hash and splits each bucket by verified token
// content. Groups with a single member are dropped.
func buildGroups(fts []fileTokens, entries []entry, k int) []group {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.hash != b.hash {
			return a.hash < b.hash
		}
		if a.file != b.file {
			return a.file < b.file
		}
		return a.start < b.start
	})
	same := func(a, b entry) bool {
		return slices.Equal(fts[a.file].kinds[a.start:int(a.start)+k], fts[b.file].kinds[b.start:int(b.start)+k])
	}
	var groups []group
	for lo := 0; lo < len(entries); {
		hi := lo + 1
		for hi < len(entries) && entries[hi].hash == entries[lo].hash {
			hi++
		}
		bucket := entries[lo:hi]
		lo = hi
		if len(bucket) < 2 {
			continue
		}
		allSame := true
		for _, e := range bucket[1:] {
			if !same(bucket[0], e) {
				allSame = false
				break
			}
		}
		if allSame {
			groups = append(groups, group{hash: bucket[0].hash, members: bucket})
			continue
		}
		// Collision: split by content, preserving member order.
		var split []group
	next:
		for _, e := range bucket {
			for i := range split {
				if same(split[i].members[0], e) {
					split[i].members = append(split[i].members, e)
					continue next
				}
			}
			split = append(split, group{hash: e.hash, members: []entry{e}})
		}
		for _, g := range split {
			if len(g.members) >= 2 {
				groups = append(groups, g)
			}
		}
	}
	return groups
}

type detection struct {
	fts     []fileTokens
	groups  []group
	groupOf [][]int32
	k       int
}

// evaluate reports, per file and window, whether the window is in a clone,
// ignoring windows marked removed (nil removes nothing).
func (d *detection) evaluate(removed [][]bool) [][]bool {
	out := make([][]bool, len(d.fts))
	for i := range out {
		out[i] = make([]bool, len(d.groupOf[i]))
	}
	for _, g := range d.groups {
		alive := func(m entry) bool { return removed == nil || !removed[m.file][m.start] }
		first, last := -1, -1
		multi := false
		var firstFile int32
		var minStart, maxStart int32
		for idx, m := range g.members {
			if !alive(m) {
				continue
			}
			if first < 0 {
				first, firstFile, minStart = idx, m.file, m.start
			} else if m.file != firstFile {
				multi = true
			}
			last, maxStart = idx, m.start
		}
		if first < 0 || first == last && !multi {
			continue
		}
		for _, m := range g.members {
			if !alive(m) {
				continue
			}
			if multi || int(m.start-minStart) >= d.k || int(maxStart-m.start) >= d.k {
				out[m.file][m.start] = true
			}
		}
	}
	return out
}

// runs derives the runs of every file from the in-clone flags.
func (d *detection) runs(inClone [][]bool) [][]runSpan {
	out := make([][]runSpan, len(d.fts))
	for i, flags := range inClone {
		lines := d.fts[i].lines
		for w := 0; w < len(flags); {
			if !flags[w] {
				w++
				continue
			}
			e := w
			for e+1 < len(flags) && flags[e+1] {
				e++
			}
			out[i] = append(out[i], runSpan{
				startWin: w, endWin: e,
				startLine: lines[w], endLine: lines[e+d.k-1],
			})
			w = e + 1
		}
	}
	return out
}

// countLines counts the distinct lines of file i carrying a token of the runs.
func (d *detection) countLines(i int, runs []runSpan) int {
	lines := d.fts[i].lines
	n, next, lastLine := 0, 0, -1
	for _, r := range runs {
		for t := max(r.startWin, next); t < r.endWin+d.k; t++ {
			if lines[t] != lastLine {
				n++
				lastLine = lines[t]
			}
		}
		next = max(next, r.endWin+d.k)
	}
	return n
}

// resolveAnnotations attaches and validates annotations against the runs and
// returns the set of annotated runs (file index, run index) plus the invalid ones.
func (d *detection) resolveAnnotations(runs [][]runSpan) (map[[2]int]bool, []InvalidAnnotation) {
	annotated := map[[2]int]bool{}
	var invalid []InvalidAnnotation
	fileIdx := map[string]int{}
	for i, ft := range d.fts {
		fileIdx[ft.path] = i
	}
	for i, ft := range d.fts {
		for _, a := range parseAnnotations(ft.comments) {
			bad := func(reason string) {
				invalid = append(invalid, InvalidAnnotation{File: ft.path, Line: a.line, Reason: reason})
			}
			if a.err != "" {
				bad(a.err)
				continue
			}
			ri := attachRun(runs[i], a.line)
			if ri < 0 {
				bad("annotation attaches to no clone run")
				continue
			}
			target, ok := fileIdx[a.path]
			if !ok || !d.hasPartnerIn(i, runs[i][ri], target) {
				bad("named path is not a duplicate partner of the annotated run")
				continue
			}
			annotated[[2]int{i, ri}] = true
		}
	}
	return annotated, invalid
}

// hasPartnerIn reports whether some window of the run has a verified partner
// position in file target (all positions considered).
func (d *detection) hasPartnerIn(file int, r runSpan, target int) bool {
	for w := r.startWin; w <= r.endWin; w++ {
		ms := d.groups[d.groupOf[file][w]].members
		lo := sort.Search(len(ms), func(x int) bool { return int(ms[x].file) >= target })
		hi := sort.Search(len(ms), func(x int) bool { return int(ms[x].file) > target })
		if lo == hi {
			continue
		}
		if target != file {
			return true
		}
		if w-int(ms[lo].start) >= d.k || int(ms[hi-1].start)-w >= d.k {
			return true
		}
	}
	return false
}
