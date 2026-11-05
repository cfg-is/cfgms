// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package metrics is the duplication metric-file model: the Report type, its
// writer and its reader. Window hashes are not serialised.
package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Version is the metric-file version.
const Version = 1

// Aggregate holds the tree-wide totals.
type Aggregate struct {
	DuplicatedLines int `json:"duplicated_lines"`
	AnnotatedLines  int `json:"annotated_lines"`
	ProductionLines int `json:"production_lines"`
	ProductionFiles int `json:"production_files"`
	Runs            int `json:"runs"`
}

// Run is one unannotated clone run.
type Run struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Tokens    int    `json:"tokens"`
}

// InvalidAnnotation is a justification comment that exempts nothing.
type InvalidAnnotation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// Report is the duplication metric file.
type Report struct {
	Version            int                 `json:"version"`
	Threshold          int                 `json:"threshold"`
	BaseCommit         string              `json:"base_commit"`
	Aggregate          Aggregate           `json:"aggregate"`
	ByPackage          map[string]int      `json:"by_package"`
	Runs               []Run               `json:"runs"`
	InvalidAnnotations []InvalidAnnotation `json:"invalid_annotations"`
}

// Write writes r as indented JSON. Nil collections are written as empty.
func Write(w io.Writer, r Report) error {
	if r.ByPackage == nil {
		r.ByPackage = map[string]int{}
	}
	if r.Runs == nil {
		r.Runs = []Run{}
	}
	if r.InvalidAnnotations == nil {
		r.InvalidAnnotations = []InvalidAnnotation{}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = io.Copy(w, bytes.NewReader(b))
	return err
}

// Read parses a duplication metric file and checks its version.
func Read(rd io.Reader) (Report, error) {
	var r Report
	dec := json.NewDecoder(rd)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Report{}, fmt.Errorf("parse duplication metric file: %w", err)
	}
	if r.Version != Version {
		return Report{}, fmt.Errorf("duplication metric file version %d, want %d", r.Version, Version)
	}
	return r, nil
}
