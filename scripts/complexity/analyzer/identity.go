// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"strings"
)

// Identity is `<repo-relative file>::<Recv>.<Name>#<ordinal>`, where ordinal
// is the 0-based index of this receiver+name within its file in source order.
// The ordinal makes several init() in one file unique. The file path is part
// of the key, so x_windows.go and x_linux.go definitions never collide.
//
// Recorded limitation: identity is stable under moving a function (its line
// changes, its identity does not), but NOT under inserting an earlier
// same-name declaration in the same file: a new init() above another shifts
// the later one's ordinal. Do not claim stronger stability than that.
func identityKey(file, recv, name string, ordinal int) string {
	return fmt.Sprintf("%s::%s.%s#%d", file, recv, name, ordinal)
}

// checkDuplicates fails when two records share an identity, naming both
// File:Line locations. Distinct real files cannot collide; it fires when
// Analyze is given overlapping roots and sees one file twice.
func checkDuplicates(fns []Function) error {
	seen := make(map[string]Function, len(fns))
	for _, fn := range fns {
		if prev, ok := seen[fn.Identity]; ok {
			return fmt.Errorf("duplicate identity %q at %s:%d and %s:%d",
				fn.Identity, prev.File, prev.Line, fn.File, fn.Line)
		}
		seen[fn.Identity] = fn
	}
	return nil
}

// receiverName returns the base receiver type name with pointer and type
// parameters stripped; empty for plain functions.
func receiverName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
		case *ast.ParenExpr:
			t = x.X
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

var knownOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true,
	"hurd": true, "illumos": true, "ios": true, "js": true, "linux": true, "nacl": true,
	"netbsd": true, "openbsd": true, "plan9": true, "solaris": true, "wasip1": true,
	"windows": true, "zos": true,
}

var knownArch = map[string]bool{
	"386": true, "amd64": true, "amd64p32": true, "arm": true, "armbe": true, "arm64": true,
	"arm64be": true, "loong64": true, "mips": true, "mipsle": true, "mips64": true,
	"mips64le": true, "mips64p32": true, "mips64p32le": true, "ppc": true, "ppc64": true,
	"ppc64le": true, "riscv": true, "riscv64": true, "s390": true, "s390x": true,
	"sparc": true, "sparc64": true, "wasm": true,
}

// buildConstraint combines the //go:build expression (before the package
// clause) with the constraint implied by a _GOOS / _GOARCH / _GOOS_GOARCH
// filename suffix. Both mechanisms are recorded; if both exist they are
// joined with &&. Empty when neither applies.
func buildConstraint(file string, f *ast.File) string {
	var parts []string
	for _, cg := range f.Comments {
		if cg.End() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if constraint.IsGoBuild(c.Text) {
				if expr, err := constraint.Parse(c.Text); err == nil {
					parts = append(parts, expr.String())
				}
			}
		}
	}
	if s := filenameConstraint(file); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, " && ")
}

func filenameConstraint(file string) string {
	base := file
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".go")
	segs := strings.Split(base, "_")
	n := len(segs)
	if n >= 3 && knownOS[segs[n-2]] && knownArch[segs[n-1]] {
		return segs[n-2] + " && " + segs[n-1]
	}
	if n >= 2 && (knownOS[segs[n-1]] || knownArch[segs[n-1]]) {
		return segs[n-1]
	}
	return ""
}
