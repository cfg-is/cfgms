// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
	"github.com/cfgis/cfgms/scripts/complexity/duplication/detector"
	dupmetrics "github.com/cfgis/cfgms/scripts/complexity/duplication/metrics"
)

// topPackages is how many package directories the summary lists.
const topPackages = 25

type duplicationReportOptions struct {
	root, out, baseCommit string
	threshold             int
}

// duplicationCmd routes the duplication subcommand's verbs.
func duplicationCmd(args []string, stdout, stderr io.Writer) int {
	errOut := &printer{w: stderr}
	if len(args) == 0 {
		// A failed write to stderr cannot change the outcome: this path
		// already exits with exitError.
		errOut.printf("complexity: duplication: missing verb (want: report, check)\n")
		return exitError
	}
	switch args[0] {
	case "report":
		return duplicationReportCmd(args[1:], stdout, stderr)
	case "check":
		return duplicationCheckCmd(args[1:], stdout, stderr)
	}
	errOut.printf("complexity: duplication: unknown verb %q\n", args[0])
	return exitError
}

func duplicationReportCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("duplication report", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o duplicationReportOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.StringVar(&o.out, "out", "bin/duplication/metrics.json", "metric file to write")
	fset.IntVar(&o.threshold, "threshold", detector.DefaultThreshold, "clone window size in tokens")
	fset.StringVar(&o.baseCommit, "base-commit", "", "base commit SHA recorded in the file (default: git rev-parse origin/develop)")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := duplicationReport(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func duplicationReport(o duplicationReportOptions, stdout, stderr *printer) int {
	if o.baseCommit == "" {
		o.baseCommit = gitBaseCommit(o.root)
		if o.baseCommit == "unknown" {
			stderr.printf("complexity: WARN: could not resolve origin/develop; base_commit recorded as unknown\n")
		}
	}
	files, prodLines, res, err := measureDuplication(os.DirFS(o.root), o.threshold)
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}

	rep := buildDuplicationReport(o, res, files, prodLines)
	if err := writeDuplicationMetrics(o.out, rep); err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	printDuplicationSummary(stdout, rep)
	stdout.printf("metric file: %s\n", filepath.ToSlash(o.out))
	return exitOK
}

// measureDuplication walks the production population of fsys and runs the
// detector over it. It is the one measurement step shared by report and check.
func measureDuplication(fsys fs.FS, threshold int) ([]detector.File, int, detector.Result, error) {
	var files []detector.File
	prodLines := 0
	err := analyzer.WalkProduction(fsys, []string{"."}, func(p string, src []byte) error {
		files = append(files, detector.File{Path: p, Src: src})
		prodLines += countSourceLines(src)
		return nil
	})
	if err != nil {
		return nil, 0, detector.Result{}, ioReason(err)
	}
	res, err := detector.Detect(files, threshold)
	if err != nil {
		return nil, 0, detector.Result{}, err
	}
	return files, prodLines, res, nil
}

func buildDuplicationReport(o duplicationReportOptions, res detector.Result, files []detector.File, prodLines int) dupmetrics.Report {
	rep := dupmetrics.Report{
		Version: dupmetrics.Version, Threshold: o.threshold, BaseCommit: o.baseCommit,
		Aggregate: dupmetrics.Aggregate{
			DuplicatedLines: res.DuplicatedLines, AnnotatedLines: res.AnnotatedLines,
			ProductionLines: prodLines, ProductionFiles: len(files), Runs: len(res.Runs),
		},
		ByPackage:          map[string]int{},
		Runs:               []dupmetrics.Run{},
		InvalidAnnotations: []dupmetrics.InvalidAnnotation{},
	}
	src := map[string][]byte{}
	for _, f := range files {
		src[f.Path] = f.Src
	}
	spans := map[string][]detector.Run{}
	for _, r := range res.Runs {
		rep.Runs = append(rep.Runs, dupmetrics.Run{File: r.File, StartLine: r.StartLine, EndLine: r.EndLine, Tokens: r.Tokens})
		spans[r.File] = append(spans[r.File], r)
	}
	for file, runs := range spans {
		if n := dupLinesInFile(src[file], runs); n > 0 {
			rep.ByPackage[path.Dir(file)] += n
		}
	}
	for _, a := range res.InvalidAnnotations {
		rep.InvalidAnnotations = append(rep.InvalidAnnotations, dupmetrics.InvalidAnnotation{File: a.File, Line: a.Line, Reason: a.Reason})
	}
	return rep
}

// dupLinesInFile counts the distinct lines of src that carry a token inside
// one of the runs, the same measure the detector totals.
func dupLinesInFile(src []byte, runs []detector.Run) int {
	fset := token.NewFileSet()
	file := fset.AddFile("", -1, len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0)
	n, last := 0, -1
	for {
		pos, tok, _ := s.Scan()
		if tok == token.EOF {
			return n
		}
		line := file.Line(pos)
		if line == last {
			continue
		}
		for _, r := range runs {
			if line >= r.StartLine && line <= r.EndLine {
				n++
				last = line
				break
			}
		}
	}
}

func countSourceLines(src []byte) int {
	if len(src) == 0 {
		return 0
	}
	n := bytes.Count(src, []byte{'\n'})
	if src[len(src)-1] != '\n' {
		n++
	}
	return n
}

func writeDuplicationMetrics(out string, rep dupmetrics.Report) error {
	var buf bytes.Buffer
	if err := dupmetrics.Write(&buf, rep); err != nil {
		return fmt.Errorf("encode metric file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return fmt.Errorf("create %s: %v", filepath.ToSlash(filepath.Dir(out)), ioReason(err))
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %v", filepath.ToSlash(out), ioReason(err))
	}
	return nil
}

func printDuplicationSummary(w *printer, rep dupmetrics.Report) {
	a := rep.Aggregate
	pct := func(n int) float64 {
		if a.ProductionLines == 0 {
			return 0
		}
		return 100 * float64(n) / float64(a.ProductionLines)
	}
	w.printf("threshold: %d tokens, %d production files, %d production lines\n", rep.Threshold, a.ProductionFiles, a.ProductionLines)
	w.printf("duplicated lines: %d (%.2f%% of production lines) in %d runs\n", a.DuplicatedLines, pct(a.DuplicatedLines), a.Runs)
	w.printf("annotated lines:  %d (%.2f%% of production lines)\n", a.AnnotatedLines, pct(a.AnnotatedLines))

	type row struct {
		dir   string
		lines int
	}
	rows := make([]row, 0, len(rep.ByPackage))
	for d, n := range rep.ByPackage {
		rows = append(rows, row{d, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].lines != rows[j].lines {
			return rows[i].lines > rows[j].lines
		}
		return rows[i].dir < rows[j].dir
	})
	if len(rows) > topPackages {
		rows = rows[:topPackages]
	}
	if len(rows) > 0 {
		w.printf("duplicated lines per package (top %d):\n", topPackages)
		for _, r := range rows {
			w.printf("  %6d  %s\n", r.lines, r.dir)
		}
	}
	for _, ia := range rep.InvalidAnnotations {
		w.printf("INVALID ANNOTATION: %s:%d: %s\n", ia.File, ia.Line, ia.Reason)
	}
}
