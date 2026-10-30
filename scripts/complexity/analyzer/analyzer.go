// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Function is the measurement record for one production function or method
// that has a body. Function literals are folded into their declaring
// function and never get a record of their own.
type Function struct {
	Package           string  `json:"package"`          // import dir, repo-relative
	File              string  `json:"file"`             // repo-relative path
	Line              int     `json:"line"`             // line of the func keyword
	Recv              string  `json:"recv"`             // base receiver type name; empty for functions
	Name              string  `json:"name"`             //
	Identity          string  `json:"identity"`         // see identity.go
	BuildConstraint   string  `json:"build_constraint"` // empty if none
	CC                int     `json:"cc"`
	DistinctOperators int     `json:"distinct_operators"` // n1
	DistinctOperands  int     `json:"distinct_operands"`  // n2
	TotalOperators    int     `json:"total_operators"`    // N1
	TotalOperands     int     `json:"total_operands"`     // N2
	Volume            float64 `json:"volume"`
	Difficulty        float64 `json:"difficulty"`
	Effort            float64 `json:"effort"`
}

// skippedDirs are build/runtime artifact and vendored directories, never
// CFGMS code under measurement.
var skippedDirs = map[string]bool{
	"bin": true, "build": true, "data": true, "node_modules": true, "vendor": true,
}

// skippedTopLevel are excluded only at the top of the analysed tree: tests,
// the frontend and dev tooling are not measured.
var skippedTopLevel = map[string]bool{"test": true, "web": true, "scripts": true}

// Analyze walks each root inside fsys and returns one record per production
// function or method, sorted by identity. It only parses source; analysed
// code is never executed. Overlapping roots yield the same file twice and are
// reported as a duplicate-identity error.
func Analyze(fsys fs.FS, roots []string) ([]Function, error) {
	var out []Function
	for _, root := range roots {
		root = path.Clean(root)
		err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return dirDecision(fsys, root, p, d.Name())
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, ".pb.go") {
				return nil
			}
			fns, err := analyzeFile(fsys, p)
			if err != nil {
				return err
			}
			out = append(out, fns...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := checkDuplicates(out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out, nil
}

// dirDecision returns fs.SkipDir for directories that are never measured.
func dirDecision(fsys fs.FS, root, p, name string) error {
	if p == "." {
		return nil
	}
	if !strings.Contains(p, "/") && skippedTopLevel[name] {
		return fs.SkipDir
	}
	if p != root && (strings.HasPrefix(name, ".") || skippedDirs[name]) {
		return fs.SkipDir
	}
	// A directory with its own go.mod is a separate module (examples/...).
	if p != root && p != "." {
		if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
			return fs.SkipDir
		}
	}
	return nil
}

func analyzeFile(fsys fs.FS, p string) ([]Function, error) {
	src, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if ast.IsGenerated(f) {
		return nil, nil
	}
	constraint := buildConstraint(p, f)
	ordinals := map[string]int{}
	var out []Function
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		recv := receiverName(fd)
		key := recv + "." + fd.Name.Name
		fn := Function{
			Package:         path.Dir(p),
			File:            p,
			Line:            fset.Position(fd.Pos()).Line,
			Recv:            recv,
			Name:            fd.Name.Name,
			BuildConstraint: constraint,
			CC:              cyclomatic(fd),
		}
		fn.Identity = identityKey(p, recv, fd.Name.Name, ordinals[key])
		ordinals[key]++
		applyHalstead(&fn, src, fset, fd)
		out = append(out, fn)
	}
	return out, nil
}
