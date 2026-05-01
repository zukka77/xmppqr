// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import "strings"

type PassphraseStrength int

const (
	PassphraseInvalid    PassphraseStrength = iota
	PassphraseWeak
	PassphraseAcceptable
	PassphraseStrong
)

func (p PassphraseStrength) String() string {
	switch p {
	case PassphraseInvalid:
		return "invalid"
	case PassphraseWeak:
		return "weak"
	case PassphraseAcceptable:
		return "acceptable"
	case PassphraseStrong:
		return "strong"
	default:
		return "unknown"
	}
}

func EstimatePassphrase(passphrase []byte) PassphraseStrength {
	if len(passphrase) < 8 {
		return PassphraseInvalid
	}

	classes := charClasses(passphrase)

	if len(passphrase) < 12 || classes < 2 {
		return PassphraseWeak
	}

	if classes < 3 {
		return PassphraseWeak
	}

	// 12–19 bytes with ≥3 classes → Acceptable minimum.
	if len(passphrase) < 20 {
		return PassphraseAcceptable
	}

	// ≥20 bytes with ≥3 classes: check for obvious repetition / sequences.
	s := string(passphrase)
	if hasObviousPattern(s) {
		return PassphraseWeak
	}
	return PassphraseStrong
}

func charClasses(p []byte) int {
	var hasLower, hasUpper, hasDigit, hasSymbol, hasNonASCII bool
	for _, b := range p {
		switch {
		case b >= 'a' && b <= 'z':
			hasLower = true
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= '0' && b <= '9':
			hasDigit = true
		case b > 127:
			hasNonASCII = true
		default:
			hasSymbol = true
		}
	}
	n := 0
	for _, v := range []bool{hasLower, hasUpper, hasDigit, hasSymbol, hasNonASCII} {
		if v {
			n++
		}
	}
	return n
}

// hasObviousPattern detects three-char runs of repeated bytes or ascending/descending
// ASCII sequences, which are common in weak long passphrases.
func hasObviousPattern(s string) bool {
	sl := strings.ToLower(s)
	for i := 0; i+2 < len(sl); i++ {
		// aaa-style repeat
		if sl[i] == sl[i+1] && sl[i+1] == sl[i+2] {
			return true
		}
		// 123 / abc ascending
		if sl[i+1] == sl[i]+1 && sl[i+2] == sl[i]+2 {
			return true
		}
		// 321 / cba descending
		if sl[i+1] == sl[i]-1 && sl[i+2] == sl[i]-2 {
			return true
		}
	}
	return false
}
