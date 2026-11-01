// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

const (
	staleRemedy = "run `make complexity-ratchet` in a reviewed diff to refresh the baseline"
	// rulesChangedMsg is printed when the ratchet baseline was counted under
	// different rules, so its numbers cannot be compared to the current ones.
	rulesChangedMsg = "counting rules changed: delete baselines/ratchet.json in a reviewed diff and run `make complexity-ratchet COMPLEXITY_INIT=1`"
)

// RulesDrift lists the counting-rule fields of baseline that differ from the
// running tool. A non-empty result means counts are not comparable.
func RulesDrift(baseline metrics.Measurement) []string {
	var out []string
	if baseline.SchemaVersion != metrics.SchemaVersion {
		out = append(out, fmt.Sprintf("schema_version %d, tool %d", baseline.SchemaVersion, metrics.SchemaVersion))
	}
	if baseline.AnalyzerVersion != AnalyzerVersion {
		out = append(out, fmt.Sprintf("analyzer_version %q, tool %q", baseline.AnalyzerVersion, AnalyzerVersion))
	}
	if baseline.HotspotThreshold != metrics.HotspotThreshold {
		out = append(out, fmt.Sprintf("hotspot_threshold %d, tool %d", baseline.HotspotThreshold, metrics.HotspotThreshold))
	}
	return out
}

// ManifestSHA returns the sha256 of the manifest file bytes, hex encoded.
func ManifestSHA(manifestPath string) (string, error) {
	raw, err := os.ReadFile(manifestPath) // #nosec G304 -- operator-supplied -manifest flag of a local dev tool
	if err != nil {
		return "", fmt.Errorf("read manifest %s: %v", filepath.ToSlash(manifestPath), ioReason(err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Staleness returns one reason per stale condition. There are exactly four:
// schema_version, analyzer_version, hotspot_threshold and manifest_sha256
// differ from the running tool and the committed manifest. Nothing else
// makes a baseline stale.
func Staleness(baseline metrics.Measurement, manifestPath string) ([]string, error) {
	sha, err := ManifestSHA(manifestPath)
	if err != nil {
		return nil, err
	}
	reasons := RulesDrift(baseline)
	if baseline.ManifestSHA256 != sha {
		reasons = append(reasons, fmt.Sprintf("manifest_sha256 %q, manifest %q", baseline.ManifestSHA256, sha))
	}
	return reasons, nil
}

func stalenessCmd(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("staleness", flag.ContinueOnError)
	fset.SetOutput(stderr)
	baseline := fset.String("baseline", "", "ratchet baseline metric file (required)")
	manifest := fset.String("manifest", "scripts/complexity/manifest.json", "population manifest")
	if err := fset.Parse(args); err != nil {
		return exitError
	}
	out, errOut := &printer{w: stdout}, &printer{w: stderr}
	code := func() int {
		if *baseline == "" {
			errOut.printf("complexity: -baseline is required\n")
			return exitError
		}
		b, err := readBaselineFile(*baseline)
		if err != nil {
			errOut.printf("complexity: %v\n", err)
			return exitError
		}
		reasons, err := Staleness(b, *manifest)
		if err != nil {
			errOut.printf("complexity: %v\n", err)
			return exitError
		}
		for _, r := range reasons {
			errOut.printf("complexity: stale baseline: %s\n", r)
		}
		if len(reasons) > 0 {
			errOut.printf("complexity: %s\n", staleRemedy)
			return exitViolation
		}
		out.printf("baseline fresh\n")
		return exitOK
	}()
	if out.err != nil || errOut.err != nil {
		return exitError
	}
	return code
}
