// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"errors"
	"fmt"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrPairingCodeMalformed = errors.New("pairing: malformed code")
var ErrPairingCodeBadCheck = errors.New("pairing: check digit mismatch")

func GeneratePairingCode() (string, error) {
	buf := make([]byte, 9)
	if _, err := wolfcrypt.Read(buf); err != nil {
		return "", err
	}
	digits := make([]byte, 9)
	for i, b := range buf {
		digits[i] = '0' + b%10
	}
	check, err := LuhnCheck(string(digits))
	if err != nil {
		return "", err
	}
	return string(digits) + string(check), nil
}

func FormatPairingCode(code string) string {
	if len(code) != 10 {
		return code
	}
	return fmt.Sprintf("%s-%s-%s-%s", code[0:3], code[3:6], code[6:9], code[9:10])
}

func ParsePairingCode(input string) (string, error) {
	stripped := strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, input)
	if len(stripped) != 10 {
		return "", ErrPairingCodeMalformed
	}
	for _, c := range stripped {
		if c < '0' || c > '9' {
			return "", ErrPairingCodeMalformed
		}
	}
	expected, err := LuhnCheck(stripped[:9])
	if err != nil {
		return "", err
	}
	if stripped[9] != expected {
		return "", ErrPairingCodeBadCheck
	}
	return stripped, nil
}

func LuhnCheck(nineDigits string) (byte, error) {
	if len(nineDigits) != 9 {
		return 0, ErrPairingCodeMalformed
	}
	for _, c := range nineDigits {
		if c < '0' || c > '9' {
			return 0, ErrPairingCodeMalformed
		}
	}
	sum := 0
	for i, c := range nineDigits {
		d := int(c - '0')
		if i%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	check := (10 - sum%10) % 10
	return byte('0' + check), nil
}
