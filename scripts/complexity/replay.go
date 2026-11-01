// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
	"github.com/cfgis/cfgms/scripts/complexity/gate"
	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// prNumber matches the squash-merge "(#NNNN)" suffix of a develop subject.
var prNumber = regexp.MustCompile(`\(#(\d+)\)\s*$`)

type replayOptions struct {
	root string
	n    int
}

// replayCommit is one first-parent commit of the replay window.
type replayCommit struct {
	sha, parent, subject string
}

// replayResult is the outcome of replaying the gate against one commit.
type replayResult struct {
	commit       replayCommit
	pr           string
	files        int
	funcs        int
	rule1        []gate.Finding
	rule2        []gate.Finding
	rule3        []gate.Finding
	unmeasurable string // non-empty: analysis failed; never counted as pass
}

// replayCmd replays gate rule 3 (and lists rules 1 and 2) against the last N
// first-parent commits of develop, each measured as parent -> commit through
// the same analyzer and gate.Evaluate path the check subcommand uses. The
// partition check is deliberately not applied: old trees predate the manifest.
func replayCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("replay", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o replayOptions
	fset.StringVar(&o.root, "root", ".", "repository root to replay")
	fset.IntVar(&o.n, "n", 30, "number of merged develop commits to replay")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := replayTo(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func replayTo(o replayOptions, stdout, stderr *printer) int {
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

	type measured struct {
		m   metrics.Measurement
		err error
	}
	cache := map[string]measured{}
	measure := func(sha string) (metrics.Measurement, error) {
		if c, ok := cache[sha]; ok {
			return c.m, c.err
		}
		m, err := measureRef(o.root, sha)
		cache[sha] = measured{m, err}
		return m, err
	}

	results := make([]replayResult, 0, len(commits))
	for _, c := range commits {
		r := replayResult{commit: c}
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
			res := gate.Evaluate(prev, cur, touched)
			for _, f := range res.Findings {
				switch f.Rule {
				case 1:
					r.rule1 = append(r.rule1, f)
				case 2:
					r.rule2 = append(r.rule2, f)
				case 3:
					r.rule3 = append(r.rule3, f)
				}
			}
			r.funcs = changedFunctionCount(prev, cur, touched)
		}
		results = append(results, r)
	}
	printReplay(stdout, tip, results)
	return exitOK
}

// replayWindow resolves the base ref and returns its SHA and the last n
// first-parent commits. A shallow repository, or one with fewer than n
// reachable commits (or a window reaching a parentless commit), fails closed
// with the same history message the check subcommand gives.
func replayWindow(root string, n int) (string, []replayCommit, error) {
	out, err := git(root, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(string(out)) == "true" {
		return "", nil, errShallow
	}
	ref := ""
	for _, r := range baseRefs {
		if _, err := git(root, "rev-parse", "--verify", "--quiet", r+"^{commit}"); err == nil {
			ref = r
			break
		}
	}
	if ref == "" {
		return "", nil, fmt.Errorf("neither %s resolves; fetch the base branch", strings.Join(baseRefs, " nor "))
	}
	tipOut, err := git(root, "rev-parse", ref+"^{commit}")
	if err != nil {
		return "", nil, err
	}
	tip := strings.TrimSpace(string(tipOut))
	logOut, err := git(root, "log", "--first-parent", fmt.Sprintf("--max-count=%d", n), "-z",
		"--format=%H%x1f%P%x1f%s", tip, "--")
	if err != nil {
		return "", nil, err
	}
	var commits []replayCommit
	for _, rec := range strings.Split(string(logOut), "\x00") {
		rec = strings.TrimLeft(rec, "\n")
		if rec == "" {
			continue
		}
		f := strings.SplitN(rec, "\x1f", 3)
		if len(f) != 3 {
			return "", nil, fmt.Errorf("unexpected git log record %q", rec)
		}
		parents := strings.Fields(f[1])
		if len(parents) == 0 {
			return "", nil, errShallow
		}
		commits = append(commits, replayCommit{sha: f[0], parent: parents[0], subject: f[2]})
	}
	if len(commits) < n {
		return "", nil, errShallow
	}
	return tip, commits, nil
}

func changedFiles(root, parent, sha string) ([]string, error) {
	out, err := git(root, "diff", "--name-only", "-z", parent, sha, "--")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	return files, nil
}

// measureRef analyses the tree of ref with the analyzer the gate uses.
func measureRef(root, ref string) (metrics.Measurement, error) {
	fsys, cleanup, err := materializeRef(root, ref)
	if err != nil {
		return metrics.Measurement{}, err
	}
	defer cleanup()
	fns, err := analyzer.Analyze(fsys, []string{"."})
	if err != nil {
		return metrics.Measurement{}, err
	}
	recs := make([]metrics.FuncRecord, 0, len(fns))
	for _, fn := range fns {
		recs = append(recs, toRecord(fn, ""))
	}
	return metrics.Measurement{Aggregate: metrics.Summarize(recs), Functions: recs}, nil
}

// changedFunctionCount counts functions in touched files that are new or whose
// metrics differ from prev.
func changedFunctionCount(prev, cur metrics.Measurement, touched []string) int {
	set := map[string]bool{}
	for _, t := range touched {
		set[t] = true
	}
	old := map[string]metrics.FuncRecord{}
	for _, r := range prev.Functions {
		old[r.Identity] = r
	}
	n := 0
	for _, c := range cur.Functions {
		if !set[c.File] {
			continue
		}
		if p, ok := old[c.Identity]; !ok || norm(p) != norm(c) {
			n++
		}
	}
	return n
}

// norm drops position fields so a function that only moved is not "changed".
func norm(r metrics.FuncRecord) metrics.FuncRecord {
	r.File, r.Line, r.Segment = "", 0, ""
	return r
}

func short(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

func printReplay(w *printer, tip string, results []replayResult) {
	w.printf("develop: %s\n", tip)
	w.printf("%-10s  %-6s  %5s  %9s  %-7s  %s\n", "commit", "PR", "files", "functions", "rule3", "outcome")
	fired, unmeasurable, total := 0, 0, 0
	top := map[string]int{}
	for _, r := range results {
		pr := "-"
		if r.pr != "" {
			pr = "#" + r.pr
		}
		outcome := "pass"
		switch {
		case r.unmeasurable != "":
			outcome = "unmeasurable: " + r.unmeasurable
			unmeasurable++
			w.printf("%-10s  %-6s  %5d  %9s  %-7s  %s\n", short(r.commit.sha), pr, r.files, "-", "-", outcome)
			continue
		case len(r.rule3) > 0:
			outcome = "fires"
			fired++
		}
		total += len(r.rule3)
		for _, f := range r.rule3 {
			top[f.Identity]++
		}
		w.printf("%-10s  %-6s  %5d  %9d  %-7d  %s\n", short(r.commit.sha), pr, r.files, r.funcs, len(r.rule3), outcome)
	}
	w.printf("\nrule 3 findings:\n")
	for _, r := range results {
		for _, f := range r.rule3 {
			w.printf("  %s %s\n", short(r.commit.sha), f)
		}
	}
	w.printf("\nrules 1 and 2 (listed, not the headline):\n")
	for _, r := range results {
		for _, f := range append(append([]gate.Finding{}, r.rule1...), r.rule2...) {
			w.printf("  %s %s\n", short(r.commit.sha), f)
		}
	}
	w.printf("\nsummary: PRs replayed %d, rule 3 fires on %d, total rule 3 findings %d, unmeasurable %d\n",
		len(results), fired, total, unmeasurable)
	type kv struct {
		id string
		n  int
	}
	var ids []kv
	for id, n := range top {
		ids = append(ids, kv{id, n})
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].n != ids[j].n {
			return ids[i].n > ids[j].n
		}
		return ids[i].id < ids[j].id
	})
	if len(ids) > 10 {
		ids = ids[:10]
	}
	w.printf("top identities:\n")
	for _, e := range ids {
		w.printf("  %d  %s\n", e.n, e.id)
	}
}
