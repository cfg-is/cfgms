// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// ratchetCmd moves the ratchet baseline. It runs the gate against the current
// baseline and writes the new one only when no rule fails. It never reads or
// writes the frozen baseline.
func ratchetCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("ratchet", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o checkOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.StringVar(&o.manifest, "manifest", "scripts/complexity/manifest.json", "population manifest")
	fset.StringVar(&o.baseline, "baseline", "", "ratchet baseline metric file to move (required)")
	fset.StringVar(&o.current, "current", "", "metric file to use as the current measurement (tests only)")
	initFlag := fset.Bool("init", false, "create the baseline; refuses when it already exists")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := ratchetTo(o, *initFlag, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

func ratchetTo(o checkOptions, initMode bool, stdout, stderr *printer) int {
	fail := func(err error) int {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	if o.baseline == "" {
		return fail(fmt.Errorf("-baseline is required"))
	}
	_, statErr := os.Stat(o.baseline)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return fail(fmt.Errorf("stat %s: %v", filepath.ToSlash(o.baseline), ioReason(statErr)))
	}

	if initMode {
		if exists {
			stderr.printf("complexity: %s already exists; -init writes only when it is absent\n", filepath.ToSlash(o.baseline))
			return exitViolation
		}
		cur, code := measureCurrent(o, stdout, stderr)
		if code != exitOK {
			return code
		}
		return writeBaseline(o.baseline, cur, stdout, stderr)
	}

	if !exists {
		return fail(fmt.Errorf("%s does not exist; create it with COMPLEXITY_INIT=1 (flag -init)", filepath.ToSlash(o.baseline)))
	}
	baseline, err := readBaselineFile(o.baseline)
	if err != nil {
		return fail(err)
	}
	if drift := RulesDrift(baseline); len(drift) > 0 {
		for _, d := range drift {
			stderr.printf("complexity: %s\n", d)
		}
		stderr.printf("complexity: %s\n", rulesChangedMsg)
		return exitViolation
	}
	cur, code := runGate(o, baseline, stdout, stderr)
	if code != exitOK {
		stderr.printf("complexity: ratchet refused; baseline unchanged\n")
		return code
	}
	return writeBaseline(o.baseline, cur, stdout, stderr)
}

// measureCurrent measures the current tree (or reads -current) without
// evaluating any rule. A partition violation refuses.
func measureCurrent(o checkOptions, stdout, stderr *printer) (metrics.Measurement, int) {
	if o.current != "" {
		m, err := readMetricFile(o.current)
		if err != nil {
			stderr.printf("complexity: %v\n", err)
			return m, exitError
		}
		return m, exitOK
	}
	tmp, err := os.MkdirTemp("", "complexity-ratchet-")
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return metrics.Measurement{}, exitError
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	outFile := filepath.Join(tmp, "current.json")
	code := reportTo(reportOptions{root: o.root, manifest: o.manifest, out: outFile}, stdout, stderr)
	if code != exitOK {
		return metrics.Measurement{}, code
	}
	m, err := readMetricFile(outFile)
	if err != nil {
		stderr.printf("complexity: %v\n", err)
		return m, exitError
	}
	return m, exitOK
}

// writeBaseline writes m in the hotspot-only form.
func writeBaseline(path string, m metrics.Measurement, stdout, stderr *printer) int {
	m.Form = metrics.FormHotspots
	m.Functions = metrics.HotspotsOnly(m.Functions)
	m.AnalyzerVersion = AnalyzerVersion
	var buf bytes.Buffer
	if err := metrics.Write(&buf, m); err != nil {
		stderr.printf("complexity: encode baseline: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		stderr.printf("complexity: create %s: %v\n", filepath.ToSlash(filepath.Dir(path)), ioReason(err))
		return exitError
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		stderr.printf("complexity: write %s: %v\n", filepath.ToSlash(path), ioReason(err))
		return exitError
	}
	stdout.printf("ratchet baseline written: %s\n", filepath.ToSlash(path))
	return exitOK
}
