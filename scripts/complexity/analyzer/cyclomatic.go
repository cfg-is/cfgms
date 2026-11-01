// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import "go/ast"

// Cyclomatic counting rules. The count is 1 plus the number of decision
// points inside the function, closures included (a closure's branches are
// paths through the declaring function's source).
//
//	+1 per if, for, range     each is a conditional or loop back-edge
//	+1 per non-default case   of switch and type switch; one path per case
//	+1 per non-default comm   clause of select, same reasoning
//	+1 per && and ||          short-circuit operators are hidden branches
//
//	+0 for else               it is the other arm of the if already counted
//	+0 for default            the fall-through arm, not an added decision
//	+0 for switch/select      the statement itself; its cases carry the count
//	+0 for defer and go       they do not branch the function's own control flow
//
// Recorded decision (founder-approved): `if err != nil { return err }` counts
// +1 like any other if. It is not special-cased. This is the conventional
// gocyclo rule; Go's explicit error handling is real branching, and an
// exemption would make the metric depend on a naming convention.
func cyclomatic(fd *ast.FuncDecl) int {
	cc := 1
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			cc++
		case *ast.CaseClause:
			if n.List != nil { // nil List is `default`
				cc++
			}
		case *ast.CommClause:
			if n.Comm != nil { // nil Comm is `default`
				cc++
			}
		case *ast.BinaryExpr:
			if n.Op.String() == "&&" || n.Op.String() == "||" {
				cc++
			}
		}
		return true
	})
	return cc
}
