// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"math"
)

// Halstead classification. go/scanner runs over the function BODY only
// (between the outermost braces, exclusive), so the signature does not
// influence the metric and an empty body yields all zeros.
//
//	operands   identifiers and literals (int, float, imaginary, char, string);
//	           distinct by exact source text
//	operators  every keyword, operator and delimiter token, distinct by token
//
// Edge tokens:
//   - Bracket pairs ( ) [ ] { } count as ONE operator, taken at the opening
//     token ("()", "[]", "{}"); closing tokens are not counted again.
//   - `,` and an explicit `;` are operators. Semicolons the scanner inserts
//     at newlines (literal "\n") are formatting, not source, and are skipped.
//   - Comments are skipped.
//
// n=n1+n2, N=N1+N2, volume=N*log2(n), difficulty=(n1/2)*(N2/n2),
// effort=difficulty*volume. n==0 or n2==0 yields 0, never NaN or Inf.
func applyHalstead(fn *Function, src []byte, fset *token.FileSet, fd *ast.FuncDecl) {
	start := fset.Position(fd.Body.Lbrace).Offset + 1
	end := fset.Position(fd.Body.Rbrace).Offset
	if start > end {
		return
	}
	body := src[start:end]

	ops := map[string]int{}
	opnds := map[string]int{}
	sfset := token.NewFileSet()
	file := sfset.AddFile("", sfset.Base(), len(body))
	var s scanner.Scanner
	s.Init(file, body, func(token.Position, string) {}, 0)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		switch tok {
		case token.IDENT, token.INT, token.FLOAT, token.IMAG, token.CHAR, token.STRING:
			opnds[lit]++
		case token.RPAREN, token.RBRACK, token.RBRACE:
			// closing half of a pair already counted at the opener
		case token.SEMICOLON:
			if lit != "\n" {
				ops[";"]++
			}
		case token.LPAREN:
			ops["()"]++
		case token.LBRACK:
			ops["[]"]++
		case token.LBRACE:
			ops["{}"]++
		default:
			ops[tok.String()]++
		}
	}
	fn.DistinctOperators, fn.DistinctOperands = len(ops), len(opnds)
	fn.TotalOperators, fn.TotalOperands = sum(ops), sum(opnds)
	fn.Volume, fn.Difficulty, fn.Effort = halsteadMetrics(fn.DistinctOperators, fn.DistinctOperands, fn.TotalOperators, fn.TotalOperands)
}

func sum(m map[string]int) int {
	t := 0
	for _, v := range m {
		t += v
	}
	return t
}

func halsteadMetrics(n1, n2, bigN1, bigN2 int) (volume, difficulty, effort float64) {
	n := n1 + n2
	if n == 0 {
		return 0, 0, 0
	}
	volume = float64(bigN1+bigN2) * math.Log2(float64(n))
	if n2 == 0 {
		return volume, 0, 0
	}
	difficulty = (float64(n1) / 2) * (float64(bigN2) / float64(n2))
	return volume, difficulty, difficulty * volume
}
