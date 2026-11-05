// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cfgis/cfgms/scripts/complexity/duplication/detector"
	"github.com/cfgis/cfgms/scripts/complexity/duplication/gate"
)

type duplicationCheckOptions struct {
	root      string
	threshold int
}

func duplicationCheckCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("duplication check", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o duplicationCheckOptions
	fset.StringVar(&o.root, "root", ".", "repository root to analyse")
	fset.IntVar(&o.threshold, "threshold", detector.DefaultThreshold, "clone window size in tokens")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := duplicationCheck(o, out, errOut)
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}

// duplicationCheck measures the working tree and a fresh materialisation of
// the merge-base and prints the duplication gate findings. Like the complexity
// check it fails closed (exit 2) when the merge-base cannot be computed.
func duplicationCheck(o duplicationCheckOptions, stdout, stderr *printer) int {
	fail := func(err error) int {
		stderr.printf("complexity: %v\n", err)
		return exitError
	}
	mergeBase, err := MergeBase(o.root)
	if err != nil {
		return fail(err)
	}
	touched, err := TouchedFiles(o.root, mergeBase)
	if err != nil {
		return fail(err)
	}
	_, _, current, err := measureDuplication(os.DirFS(o.root), o.threshold)
	if err != nil {
		return fail(fmt.Errorf("measure current tree: %w", err))
	}
	fsys, cleanup, err := materializeRef(o.root, mergeBase)
	if err != nil {
		return fail(err)
	}
	defer cleanup()
	_, _, previous, err := measureDuplication(fsys, o.threshold)
	if err != nil {
		return fail(fmt.Errorf("measure merge-base tree: %w", err))
	}

	res := gate.Evaluate(previous, current, touched)
	for _, ia := range current.InvalidAnnotations {
		stdout.printf("invalid annotation: %s:%d: %s\n", ia.File, ia.Line, ia.Reason)
	}
	for _, f := range res.Findings {
		stdout.printf("%s\n", f)
	}
	if len(res.Findings) > 0 {
		return exitViolation
	}
	stdout.printf("duplication gate: pass\n")
	return exitOK
}
