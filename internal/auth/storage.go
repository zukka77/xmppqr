package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	scryptN = 32768
	scryptR = 8
	scryptP = 1
	scryptKeyLen = 32
	scryptSaltLen = 16
)

func HashPasswordForStorage(password []byte) (string, error) {
	salt := make([]byte, scryptSaltLen)
	if _, err := wolfcrypt.Read(salt); err != nil {
		return "", err
	}
	hash, err := wolfcrypt.Scrypt(password, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$scrypt$N=%d,r=%d,p=%d$%s$%s", scryptN, scryptR, scryptP, saltB64, hashB64), nil
}

func VerifyStoredPassword(encoded string, password []byte) (bool, error) {
	n, r, p, salt, storedHash, err := parseEncoded(encoded)
	if err != nil {
		return false, err
	}
	hash, err := wolfcrypt.Scrypt(password, salt, n, r, p, len(storedHash))
	if err != nil {
		return false, err
	}
	return bytes.Equal(hash, storedHash), nil
}

func parseEncoded(encoded string) (n, r, p int, salt, hash []byte, err error) {
	// format: $scrypt$N=<n>,r=<r>,p=<p>$<base64-salt>$<base64-hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "scrypt" {
		return 0, 0, 0, nil, nil, errors.New("storage: invalid encoded format")
	}
	params := parseKV(parts[2])
	nv, ok1 := params["N"]
	rv, ok2 := params["r"]
	pv, ok3 := params["p"]
	if !ok1 || !ok2 || !ok3 {
		return 0, 0, 0, nil, nil, errors.New("storage: missing scrypt parameters")
	}
	n64, e1 := strconv.ParseInt(nv, 10, 64)
	r64, e2 := strconv.ParseInt(rv, 10, 64)
	p64, e3 := strconv.ParseInt(pv, 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, 0, 0, nil, nil, errors.New("storage: invalid scrypt parameter values")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("storage: invalid salt encoding: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("storage: invalid hash encoding: %w", err)
	}
	return int(n64), int(r64), int(p64), salt, hash, nil
}
