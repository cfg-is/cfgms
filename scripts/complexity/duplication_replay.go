// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/duplication/detector"
	"github.com/cfgis/cfgms/scripts/complexity/duplication/gate"
)

// maxPartners bounds how many other copies are listed beside a firing.
const maxPartners = 3

type duplicationReplayOptions struct {
	root, baseline string
	n, threshold   int
}

// duplicationReplayResult is the outcome of replaying the duplication gate
// against one commit.
type duplicationReplayResult struct {
	commit       replayCommit
	pr           string
	files        int
	findings     []gate.Finding
	current      detector.Result
	unmeasurable string // non-empty: analysis failed; never counted as pass
}

func (r duplicationReplayResult) fires(rule int) bool {
	for _, f := range r.findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func duplicationReplayCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("duplication replay", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o duplicationReplayOptions
	fset.StringVar(&o.root, "root", ".", "repository root to replay")
	fset.IntVar(&o.n, "n", 30, "number of merged develop commits to replay")
	fset.IntVar(&o.threshold, "threshold", detector.DefaultThreshold, "clone window size in tokens")
	fset.StringVar(&o.baseline, "baseline", "", "ref to measure and print as the baseline (optional)")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := duplicationReplay(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

// duplicationReplay replays all three duplication rules over the last N
// first-parent commits of develop, each measured as parent -> commit through
// the same measureDuplication and gate.Evaluate path the check verb uses.
func duplicationReplay(o duplicationReplayOptions, stdout, stderr *printer) int {
	fail := func(err error) int {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	if o.n < 1 {
		return fail(fmt.Errorf("-n must be at least 1"))
	}
	tip, commits, err := replayWindow(o.root, o.n)
	if err != nil {
		return fail(err)
	}
	if o.baseline != "" {
		// Fail on a missing baseline before the long replay starts.
		if strings.HasPrefix(o.baseline, "-") {
			return fail(fmt.Errorf("-baseline %q is not a ref", o.baseline))
		}
		if _, err := git(o.root, "rev-parse", "--verify", "--quiet", o.baseline+"^{commit}"); err != nil {
			return fail(fmt.Errorf("baseline %q is not in this checkout's history: %w", o.baseline, errShallow))
		}
	}

	type measured struct {
		res detector.Result
		err error
	}
	cache := map[string]measured{}
	measure := func(sha string) (detector.Result, error) {
		if c, ok := cache[sha]; ok {
			return c.res, c.err
		}
		res, err := measureDuplicationRef(o.root, sha, o.threshold)
		cache[sha] = measured{res, err}
		return res, err
	}

	results := make([]duplicationReplayResult, 0, len(commits))
	for _, c := range commits {
		r := duplicationReplayResult{commit: c}
		if m := prNumber.FindStringSubmatch(c.subject); m != nil {
			r.pr = m[1]
		}
		touched, err := changedFiles(o.root, c.parent, c.sha)
		if err != nil {
			return fail(err)
		}
		r.files = len(touched)
		prev, perr := measure(c.parent)
		cur, cerr := measure(c.sha)
		switch {
		case perr != nil:
			r.unmeasurable = fmt.Sprintf("parent %s: %v", short(c.parent), perr)
		case cerr != nil:
			r.unmeasurable = fmt.Sprintf("commit %s: %v", short(c.sha), cerr)
		default:
			r.findings = gate.Evaluate(prev, cur, touched).Findings
			r.current = cur
		}
		results = append(results, r)
	}
	printDuplicationReplay(stdout, tip, o.threshold, results)

	if o.baseline != "" {
		return printDuplicationBaseline(o, stdout, stderr)
	}
	return exitOK
}

// measureDuplicationRef measures the production tree of ref.
func measureDuplicationRef(root, ref string, threshold int) (detector.Result, error) {
	fsys, cleanup, err := materializeRef(root, ref)
	if err != nil {
		return detector.Result{}, err
	}
	defer cleanup()
	_, _, res, err := measureDuplication(fsys, threshold)
	return res, err
}

// printDuplicationBaseline measures o.baseline with the report path and prints
// the aggregate and every package's duplicated lines.
func printDuplicationBaseline(o duplicationReplayOptions, stdout, stderr *printer) int {
	fsys, cleanup, err := materializeRef(o.root, o.baseline)
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	defer cleanup()
	files, prodLines, res, err := measureDuplication(fsys, o.threshold)
	if err != nil {
		stderr.printf("complexity: baseline %s: %v\n", o.baseline, err)
		return exitError
	}
	rep := buildDuplicationReport(duplicationReportOptions{threshold: o.threshold, baseCommit: o.baseline}, res, files, prodLines)
	stdout.printf("\nbaseline %s:\n", o.baseline)
	printDuplicationSummary(stdout, rep)
	stdout.printf("by_package (all %d):\n", len(rep.ByPackage))
	pkgs := make([]string, 0, len(rep.ByPackage))
	for p := range rep.ByPackage {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		stdout.printf("  %6d  %s\n", rep.ByPackage[p], p)
	}
	return exitOK
}

// partnerRanges lists the other current runs that share a window with the run
// a finding points at, as file:start-end, so each firing records both copies.
func partnerRanges(cur detector.Result, f gate.Finding) string {
	var self *detector.Run
	for i := range cur.Runs {
		if cur.Runs[i].File == f.File && cur.Runs[i].StartLine == f.Line {
			self = &cur.Runs[i]
			break
		}
	}
	if self == nil {
		return ""
	}
	mine := make(map[uint64]bool, len(self.Windows))
	for _, h := range self.Windows {
		mine[h] = true
	}
	var out []string
	more := 0
	for i := range cur.Runs {
		r := &cur.Runs[i]
		if r == self {
			continue
		}
		for _, h := range r.Windows {
			if mine[h] {
				if len(out) < maxPartners {
					out = append(out, fmt.Sprintf("%s:%d-%d", r.File, r.StartLine, r.EndLine))
				} else {
					more++
				}
				break
			}
		}
	}
	s := fmt.Sprintf("%s:%d-%d", self.File, self.StartLine, self.EndLine)
	if len(out) == 0 {
		return s
	}
	s += " copies " + strings.Join(out, ", ")
	if more > 0 {
		s += fmt.Sprintf(" (+%d more)", more)
	}
	return s
}

func printDuplicationReplay(w *printer, tip string, threshold int, results []duplicationReplayResult) {
	w.printf("develop: %s\n", tip)
	w.printf("threshold: %d tokens\n", threshold)
	w.printf("%-10s  %-6s  %5s  %5s  %5s  %5s  %s\n", "commit", "PR", "files", "rule1", "rule2", "rule3", "outcome")
	fired, unmeasurable := 0, 0
	for _, r := range results {
		pr := "-"
		if r.pr != "" {
			pr = "#" + r.pr
		}
		if r.unmeasurable != "" {
			unmeasurable++
			w.printf("%-10s  %-6s  %5d  %5s  %5s  %5s  unmeasurable: %s\n", short(r.commit.sha), pr, r.files, "-", "-", "-", r.unmeasurable)
			continue
		}
		outcome := "pass"
		if len(r.findings) > 0 {
			outcome = "fires"
			fired++
		}
		count := func(rule int) int {
			n := 0
			for _, f := range r.findings {
				if f.Rule == rule {
					n++
				}
			}
			return n
		}
		w.printf("%-10s  %-6s  %5d  %5d  %5d  %5d  %s\n", short(r.commit.sha), pr, r.files, count(1), count(2), count(3), outcome)
	}
	w.printf("\nfindings:\n")
	for _, r := range results {
		for _, f := range r.findings {
			if f.Rule == 1 {
				w.printf("  %s %s\n", short(r.commit.sha), f)
				continue
			}
			w.printf("  %s %s [%s]\n", short(r.commit.sha), f, partnerRanges(r.current, f))
		}
	}
	byRule := [4]int{}
	for _, r := range results {
		for rule := 1; rule <= 3; rule++ {
			if r.fires(rule) {
				byRule[rule]++
			}
		}
	}
	rate := 0.0
	if len(results) > 0 {
		rate = 100 * float64(fired) / float64(len(results))
	}
	w.printf("\nsummary: PRs replayed %d, fires on %d (%.1f%%), rule 1 on %d, rule 2 on %d, rule 3 on %d, unmeasurable %d\n",
		len(results), fired, rate, byRule[1], byRule[2], byRule[3], unmeasurable)
}
