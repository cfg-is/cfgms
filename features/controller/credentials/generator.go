// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credentials

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PasswordLength is the length of every generated initial password.
const PasswordLength = 24

// Character classes. Each generated password holds at least one character from
// each. The symbol class avoids quote, backslash, backtick and space so a
// password survives being placed in a script argument or a config value.
const (
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	digitChars  = "0123456789"
	symbolChars = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
)

var passwordClasses = [...]string{upperChars, lowerChars, digitChars, symbolChars}

// GeneratePassword returns a PasswordLength-character password drawn from
// crypto/rand. It contains at least one upper-case letter, lower-case letter,
// digit and symbol; every character is chosen uniformly (rejection sampling, no
// modulo bias) from its class, and the positions are shuffled with an unbiased
// Fisher-Yates so the guaranteed characters are not at predictable offsets.
//
// This is the one generator for controller-issued initial passwords; the
// in-process account creation path (#5563) uses it too.
func GeneratePassword() (string, error) {
	all := upperChars + lowerChars + digitChars + symbolChars
	out := make([]byte, 0, PasswordLength)
	for _, class := range passwordClasses {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < PasswordLength {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := randIndex(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func pick(set string) (byte, error) {
	i, err := randIndex(len(set))
	if err != nil {
		return 0, err
	}
	return set[i], nil
}

// randIndex returns a uniform integer in [0, n). big.Int via rand.Int rejects
// out-of-range samples, so the result is unbiased.
func randIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("password generation failed: %w", err)
	}
	return int(v.Int64()), nil
}
