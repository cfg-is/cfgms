// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package detector

import (
	"go/scanner"
	"go/token"
)

// comment is a source comment retained for annotation parsing.
type comment struct {
	line int
	text string
}

// fileTokens is the normalized token stream of one file. kinds[i] is the
// go/token kind of token i; every identifier is token.IDENT and every literal
// is one token of its own kind, so renamed identifiers and changed literal
// values produce identical streams. lines[i] is the source line of token i.
type fileTokens struct {
	path     string
	kinds    []token.Token
	lines    []int
	comments []comment
}

// tokenize scans src. Comments are removed from the token stream and returned
// separately; the package clause and import declarations are skipped.
// Scan errors are ignored: malformed input still yields a deterministic stream.
func tokenize(path string, src []byte) fileTokens {
	ft := fileTokens{path: path}
	fset := token.NewFileSet()
	file := fset.AddFile(path, -1, len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, scanner.ScanComments)

	depth := 0        // brace depth
	skipping := false // inside a package clause or import declaration
	parens := 0       // paren depth while skipping
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return ft
		}
		line := file.Line(pos)
		if tok == token.COMMENT {
			ft.comments = append(ft.comments, comment{line: line, text: lit})
			continue
		}
		if skipping {
			switch tok {
			case token.LPAREN:
				parens++
			case token.RPAREN:
				parens--
			case token.SEMICOLON:
				if parens <= 0 {
					skipping = false
				}
			}
			continue
		}
		switch tok {
		case token.LBRACE:
			depth++
		case token.RBRACE:
			depth--
		case token.PACKAGE, token.IMPORT:
			if depth <= 0 {
				skipping, parens = true, 0
				continue
			}
		}
		ft.kinds = append(ft.kinds, tok)
		ft.lines = append(ft.lines, line)
	}
}

const hashBase uint64 = 0x9E3779B97F4A7C15 | 1

// windowHashMask is applied to every stored window hash. It is all ones in
// production; tests narrow it to force collisions.
var windowHashMask = ^uint64(0)

// mix spreads a token kind over 64 bits (splitmix64 finalizer). It is a pure
// function, so hashes are identical across calls and processes.
func mix(k token.Token) uint64 {
	x := uint64(k) + 1 // #nosec G115 -- token.Token kinds are small non-negative constants; value only feeds a hash mixer
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// windowHashes returns the rolling hash of every k-token window of kinds
// (len(kinds)-k+1 values, none when there are fewer than k tokens).
func windowHashes(kinds []token.Token, k int) []uint64 {
	if len(kinds) < k {
		return nil
	}
	pow := uint64(1)
	for i := 0; i < k; i++ {
		pow *= hashBase
	}
	out := make([]uint64, 0, len(kinds)-k+1)
	var h uint64
	for i, kd := range kinds {
		h = h*hashBase + mix(kd)
		if i >= k {
			h -= mix(kinds[i-k]) * pow
		}
		if i >= k-1 {
			out = append(out, h&windowHashMask)
		}
	}
	return out
}
