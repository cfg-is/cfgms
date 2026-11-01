// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// AnalyzerVersion identifies the counting rules; bump it when they change.
const AnalyzerVersion = "1"

// Exit codes of the report subcommand.
const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
)

type reportOptions struct {
	root, manifest, out, baseCommit string
}

func reportCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("report", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o reportOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.StringVar(&o.manifest, "manifest", "scripts/complexity/manifest.json", "population manifest")
	fset.StringVar(&o.out, "out", "bin/complexity/metrics.json", "metric file to write")
	fset.StringVar(&o.baseCommit, "base-commit", "", "base commit SHA recorded in the file (default: git rev-parse origin/develop)")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	return report(o, stdout, stderr)
}

// printer writes formatted output and keeps the first write error, so a
// closed or full stdout/stderr turns into a non-zero exit instead of silently
// truncated output.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, a...)
}

func report(o reportOptions, stdout, stderr io.Writer) int {
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := reportTo(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func reportTo(o reportOptions, stdout, stderr *printer) int {
	m := metrics.Measurement{
		SchemaVersion:    metrics.SchemaVersion,
		BaseCommit:       o.baseCommit,
		AnalyzerVersion:  AnalyzerVersion,
		HotspotThreshold: metrics.HotspotThreshold,
		Status:           metrics.StatusError,
		Form:             metrics.FormFull,
		Violations:       []string{},
		Segments:         map[string]metrics.Totals{},
	}
	if m.BaseCommit == "" {
		m.BaseCommit = gitBaseCommit(o.root)
		if m.BaseCommit == "unknown" {
			stderr.printf("complexity: WARN: could not resolve origin/develop; base_commit recorded as unknown\n")
		}
	}
	fail := func(err error) int {
		stderr.printf("complexity: %v\n", err)
		m.Status = metrics.StatusError
		m.Violations = append(m.Violations, err.Error())
		if werr := writeMetrics(o.out, m); werr != nil {
			stderr.printf("complexity: %v\n", werr)
		}
		return exitError
	}

	raw, err := os.ReadFile(o.manifest)
	if err != nil {
		return fail(fmt.Errorf("read manifest %s: %v", filepath.ToSlash(o.manifest), ioReason(err)))
	}
	sum := sha256.Sum256(raw)
	m.ManifestSHA256 = hex.EncodeToString(sum[:])
	man, err := LoadManifest(raw)
	if err != nil {
		return fail(err)
	}

	fns, err := analyzer.Analyze(os.DirFS(o.root), []string{"."})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate identity") {
			m.Status = metrics.StatusFail
			m.Violations = append(m.Violations, err.Error())
			stderr.printf("complexity: %v\n", err)
			if werr := writeMetrics(o.out, m); werr != nil {
				stderr.printf("complexity: %v\n", werr)
				return exitError
			}
			return exitViolation
		}
		return fail(err)
	}

	bySeg := man.BySegment(fns)
	violations := CheckPartition(fns, bySeg)
	segOf := map[string]string{}
	for name, list := range bySeg {
		for _, fn := range list {
			segOf[fn.Identity] = name
		}
	}
	recs := make([]metrics.FuncRecord, 0, len(fns))
	bySegRecs := map[string][]metrics.FuncRecord{}
	for _, fn := range fns {
		r := toRecord(fn, segOf[fn.Identity])
		recs = append(recs, r)
		bySegRecs[r.Segment] = append(bySegRecs[r.Segment], r)
	}
	m.Aggregate = metrics.Summarize(recs)
	for _, s := range man.Segments {
		m.Segments[s.Name] = metrics.Summarize(bySegRecs[s.Name])
	}
	m.Functions = recs
	m.Status = metrics.StatusPass
	for _, v := range violations {
		m.Status = metrics.StatusFail
		m.Violations = append(m.Violations, v.String())
	}
	if err := writeMetrics(o.out, m); err != nil {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}

	for _, u := range man.UnusedPrefixes(fns) {
		stdout.printf("WARN: manifest path has no production function: %s\n", u)
	}
	printSummary(stdout, m)
	for _, v := range m.Violations {
		stderr.printf("VIOLATION: %s\n", v)
	}
	stdout.printf("metric file: %s (status %s)\n", filepath.ToSlash(o.out), m.Status)
	if m.Status != metrics.StatusPass {
		return exitViolation
	}
	return exitOK
}

func toRecord(fn analyzer.Function, segment string) metrics.FuncRecord {
	return metrics.FuncRecord{
		Identity: fn.Identity, File: fn.File, Line: fn.Line, Segment: segment,
		CC: fn.CC, N1: fn.DistinctOperators, N2: fn.DistinctOperands,
		TotalN1: fn.TotalOperators, TotalN2: fn.TotalOperands,
		Volume:     metrics.Round(fn.Volume),
		Difficulty: metrics.Round(fn.Difficulty),
		Effort:     metrics.Round(fn.Effort),
	}
}

func writeMetrics(out string, m metrics.Measurement) error {
	var buf bytes.Buffer
	if err := metrics.Write(&buf, m); err != nil {
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

func printSummary(w *printer, m metrics.Measurement) {
	names := make([]string, 0, len(m.Segments))
	for n := range m.Segments {
		names = append(names, n)
	}
	sort.Strings(names)
	w.printf("%-16s %9s %8s %7s %7s\n", "segment", "functions", "hotspots", "excess", "mean_cc")
	row := func(n string, t metrics.Totals) {
		w.printf("%-16s %9d %8d %7d %7.2f\n", n, t.Functions, t.Hotspots, t.AggregateExcess, t.MeanCC)
	}
	for _, n := range names {
		row(n, m.Segments[n])
	}
	row("aggregate", m.Aggregate)
}

func gitBaseCommit(root string) string {
	// Make the directory absolute so it can never be parsed as a git option.
	dir, err := filepath.Abs(root)
	if err != nil {
		return "unknown"
	}
	// #nosec G204 -- fixed argv with no shell; dir is an absolute path (cannot start with '-') passed as the -C operand.
	cmd := exec.Command("git", "-C", dir, "rev-parse", "origin/develop")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// ioReason strips the path an OS error embeds, so messages carry only the
// path the caller passed on the command line.
func ioReason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
