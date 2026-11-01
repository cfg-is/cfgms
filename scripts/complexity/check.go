// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
	"github.com/cfgis/cfgms/scripts/complexity/gate"
	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

type checkOptions struct {
	root, manifest, baseline, current string
}

func checkCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("check", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o checkOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.StringVar(&o.manifest, "manifest", "scripts/complexity/manifest.json", "population manifest")
	fset.StringVar(&o.baseline, "baseline", "", "ratchet baseline metric file (required)")
	fset.StringVar(&o.current, "current", "", "metric file to use as the current measurement (tests only)")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := checkTo(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func checkTo(o checkOptions, stdout, stderr *printer) int {
	fail := func(err error) int {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	if o.baseline == "" {
		return fail(fmt.Errorf("-baseline is required"))
	}
	baseline, err := readBaselineFile(o.baseline)
	if err != nil {
		return fail(err)
	}
	if reasons, err := Staleness(baseline, o.manifest); err != nil {
		return fail(err)
	} else if len(reasons) > 0 {
		for _, r := range reasons {
			stderr.printf("complexity: stale baseline: %s\n", r)
		}
		stderr.printf("complexity: %s\n", staleRemedy)
		return exitViolation
	}
	_, code := runGate(o, baseline, stdout, stderr)
	if code == exitOK {
		stdout.printf("complexity gate: pass\n")
	}
	return code
}

// runGate measures the current tree and the merge-base tree and evaluates the
// gate rules against baseline, printing partition violations, warnings and
// findings. It returns the current measurement alongside the exit code.
func runGate(o checkOptions, baseline metrics.Measurement, stdout, stderr *printer) (metrics.Measurement, int) {
	fail := func(err error) (metrics.Measurement, int) {
		stderr.printf("complexity: %v\n", err)
		return metrics.Measurement{}, exitError
	}

	// Resolve git state first: a shallow clone must fail before any work.
	mergeBase, err := MergeBase(o.root)
	if err != nil {
		return fail(err)
	}
	touched, err := TouchedFiles(o.root, mergeBase)
	if err != nil {
		return fail(err)
	}

	var partition []string
	var current metrics.Measurement
	if o.current != "" {
		if current, err = readMetricFile(o.current); err != nil {
			return fail(err)
		}
	} else {
		tmp, err := os.MkdirTemp("", "complexity-check-")
		if err != nil {
			return fail(err)
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		outFile := filepath.Join(tmp, "current.json")
		code := reportTo(reportOptions{root: o.root, manifest: o.manifest, out: outFile, baseCommit: mergeBase},
			&printer{w: io.Discard}, &printer{w: io.Discard})
		if code == exitError {
			return fail(fmt.Errorf("measure current tree failed"))
		}
		if current, err = readMetricFile(outFile); err != nil {
			return fail(err)
		}
		partition = current.Violations
	}

	fsys, cleanup, err := materializeRef(o.root, mergeBase)
	if err != nil {
		return fail(err)
	}
	defer cleanup()
	fns, err := analyzer.Analyze(fsys, []string{"."})
	if err != nil {
		return fail(fmt.Errorf("measure merge-base tree: %w", err))
	}
	recs := make([]metrics.FuncRecord, 0, len(fns))
	for _, fn := range fns {
		recs = append(recs, toRecord(fn, ""))
	}
	previous := metrics.Measurement{Aggregate: metrics.Summarize(recs), Functions: recs}

	res := gate.Evaluate(baseline, previous, current, touched)
	for _, v := range partition {
		stdout.printf("partition: %s\n", v)
	}
	for _, w := range res.Warnings {
		stdout.printf("WARN: %s\n", w)
	}
	for _, f := range res.Findings {
		stdout.printf("%s\n", f)
	}
	if len(res.Findings) > 0 || len(partition) > 0 {
		return current, exitViolation
	}
	return current, exitOK
}

func readMetricFile(path string) (metrics.Measurement, error) {
	return readMetricFileWith(path, metrics.Read)
}

// readBaselineFile reads a baseline without rejecting a foreign schema_version,
// which staleness and the ratchet report as their own condition.
func readBaselineFile(path string) (metrics.Measurement, error) {
	return readMetricFileWith(path, metrics.ReadAny)
}

func readMetricFileWith(path string, read func(io.Reader) (metrics.Measurement, error)) (metrics.Measurement, error) {
	// #nosec G304 -- path is the operator-supplied -baseline/-current CLI flag
	// of a local dev tool run by the operator against their own checkout.
	f, err := os.Open(path)
	if err != nil {
		return metrics.Measurement{}, fmt.Errorf("read %s: %v", filepath.ToSlash(path), ioReason(err))
	}
	defer func() { _ = f.Close() }()
	m, err := read(f)
	if err != nil {
		return metrics.Measurement{}, fmt.Errorf("%s: %w", filepath.ToSlash(path), err)
	}
	return m, nil
}
