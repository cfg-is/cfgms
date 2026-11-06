// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"fmt"
	"strings"
)

const (
	preapprovalKey      = "cfgms-preapproved"
	preapprovalValue    = "automation"
	preapprovalKeyStart = "cfgms-"
)

// ParsePreapprovalRequest reports whether the leading header comment block of
// a script contains the declaration "cfgms-preapproved: automation".
//
// Only the leading header block counts: the scan stops at the first line that
// is neither blank nor a comment in the shell's syntax, so a declaration after
// code, inside a heredoc or inside a string is ignored. A declaration must be
// the whole comment line. Any other comment line that begins with "cfgms-" (a
// misspelled key or an unknown value) is an error, so a typo cannot silently
// mean "not requested". The declaration is a request only; it grants nothing.
func ParsePreapprovalRequest(content string, shell ShellType) (requested bool, err error) {
	scanner, err := newHeaderScanner(shell)
	if err != nil {
		return false, err
	}

	for _, raw := range strings.Split(normalizeScriptLines(content), "\n") {
		text, skip, end := scanner.commentText(strings.TrimSpace(raw))
		if end {
			return requested, nil
		}
		if skip {
			continue
		}
		found, perr := parsePreapprovalLine(text)
		if perr != nil {
			return false, perr
		}
		requested = requested || found
	}
	return requested, nil
}

// headerScanner tracks the comment syntax of one shell and whether the scan is
// inside a PowerShell <# ... #> block comment.
type headerScanner struct {
	lineMarkers   []string
	blockComments bool
	inBlock       bool
}

// newHeaderScanner returns a scanner configured with the comment syntax of
// shell, or ErrInvalidShellType for an unsupported shell.
func newHeaderScanner(shell ShellType) (*headerScanner, error) {
	switch shell {
	case ShellBash, ShellZsh, ShellSh, ShellPython, ShellPython3:
		return &headerScanner{lineMarkers: []string{"#"}}, nil
	case ShellPowerShell, ShellPwsh:
		return &headerScanner{lineMarkers: []string{"#"}, blockComments: true}, nil
	case ShellCmd:
		return &headerScanner{lineMarkers: []string{"::", "REM"}}, nil
	default:
		return nil, ErrInvalidShellType
	}
}

// normalizeScriptLines strips a leading BOM and converts CRLF and CR line
// endings to LF.
func normalizeScriptLines(content string) string {
	content = strings.TrimPrefix(content, "\ufeff")
	content = strings.ReplaceAll(content, "\r\n", "\n")
	return strings.ReplaceAll(content, "\r", "\n")
}

// commentText classifies one trimmed line of the header. It returns the
// comment's text, skip=true for a blank line, or end=true when the line ends
// the leading header block.
func (s *headerScanner) commentText(line string) (text string, skip, end bool) {
	switch {
	case s.inBlock:
		return s.blockContinuation(line), false, false
	case line == "":
		return "", true, false
	case s.blockComments && strings.HasPrefix(line, "<#"):
		return s.blockOpen(line)
	}
	marker, ok := matchLineMarker(line, s.lineMarkers)
	if !ok {
		return "", false, true // first non-comment line ends the header
	}
	return strings.TrimSpace(line[len(marker):]), false, false
}

// blockContinuation returns the text of a line inside a block comment and
// leaves the block when the line contains the closing "#>".
func (s *headerScanner) blockContinuation(line string) string {
	if i := strings.Index(line, "#>"); i >= 0 {
		s.inBlock = false
		return strings.TrimSpace(line[:i])
	}
	return line
}

// blockOpen handles a line that opens a block comment. A block closed on the
// same line and followed by code ends the header.
func (s *headerScanner) blockOpen(line string) (text string, skip, end bool) {
	text = strings.TrimSpace(strings.TrimPrefix(line, "<#"))
	i := strings.Index(text, "#>")
	if i < 0 {
		s.inBlock = true
		return text, false, false
	}
	if strings.TrimSpace(text[i+2:]) != "" {
		return "", false, true // code follows the block close
	}
	return strings.TrimSpace(text[:i]), false, false
}

// matchLineMarker returns the line-comment marker that prefixes line. Markers
// are matched case-insensitively and REM must be followed by whitespace or end
// of line so that identifiers such as "remove" are not treated as comments.
func matchLineMarker(line string, markers []string) (string, bool) {
	for _, m := range markers {
		if len(line) < len(m) || !strings.EqualFold(line[:len(m)], m) {
			continue
		}
		if m == "REM" && len(line) > len(m) && line[len(m)] != ' ' && line[len(m)] != '\t' {
			continue
		}
		return m, true
	}
	return "", false
}

// parsePreapprovalLine interprets one comment's text. It returns requested=true
// for the exact declaration, an error for any other cfgms- directive, and
// false otherwise.
func parsePreapprovalLine(text string) (bool, error) {
	if len(text) < len(preapprovalKeyStart) || !strings.EqualFold(text[:len(preapprovalKeyStart)], preapprovalKeyStart) {
		return false, nil
	}
	key, value, hasValue := strings.Cut(text, ":")
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key != preapprovalKey {
		return false, fmt.Errorf("unknown script header directive %q (expected %q)", truncateForError(key), preapprovalKey)
	}
	if !hasValue || value != preapprovalValue {
		return false, fmt.Errorf("invalid value for %s (expected %q)", preapprovalKey, preapprovalValue)
	}
	return true, nil
}

func truncateForError(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
