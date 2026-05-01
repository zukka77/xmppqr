// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

// Crypto note: scrypt KDF is via wolfCrypt (internal/wolfcrypt/scrypt.go),
// keeping all cryptographic primitives in wolfCrypt. This is the same approach
// used by internal/auth/storage.go for SCRAM password storage. Argon2id was
// considered but rejected because wolfCrypt does not ship it, and introducing
// golang.org/x/crypto/argon2 would be the sole non-wolfCrypt crypto dependency.
// RFC 7914 scrypt with N=131072, r=8, p=1 provides equivalent memory-hardness.

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const (
	aikRecoveryN      = 131072
	aikRecoveryR      = 8
	aikRecoveryP      = 1
	aikRecoverySaltLen  = 16
	aikRecoveryNonceLen = 12
	aikRecoveryKeyLen   = 32
	aikRecoveryVersion  = uint16(1)

	minN = 65536
	minR = 8
	minP = 1
)

var (
	ErrRecoveryBadPassphrase   = errors.New("recovery: passphrase did not unlock blob")
	ErrRecoveryMalformed       = errors.New("recovery: malformed sealed blob")
	ErrRecoveryParamsInsecure  = errors.New("recovery: scrypt params below minimum")
	ErrRecoveryWeakPassphrase  = errors.New("recovery: passphrase strength below acceptable")
)

var b32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func SealAIK(aik *AccountIdentityKey, passphrase []byte) (string, error) {
	if EstimatePassphrase(passphrase) < PassphraseAcceptable {
		return "", ErrRecoveryWeakPassphrase
	}
	return sealAIKRaw(aik, passphrase)
}

func SealAIKAllowWeak(aik *AccountIdentityKey, passphrase []byte) (string, error) {
	if EstimatePassphrase(passphrase) == PassphraseInvalid {
		return "", ErrRecoveryWeakPassphrase
	}
	return sealAIKRaw(aik, passphrase)
}

func sealAIKRaw(aik *AccountIdentityKey, passphrase []byte) (string, error) {
	salt := make([]byte, aikRecoverySaltLen)
	if _, err := wolfcrypt.Read(salt); err != nil {
		return "", err
	}
	nonce := make([]byte, aikRecoveryNonceLen)
	if _, err := wolfcrypt.Read(nonce); err != nil {
		return "", err
	}

	kek, err := wolfcrypt.Scrypt(passphrase, salt, aikRecoveryN, aikRecoveryR, aikRecoveryP, aikRecoveryKeyLen)
	if err != nil {
		return "", err
	}

	plain := serializeAIK(aik)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	header := fmt.Sprintf("x3dhpqv1$N=%d,r=%d,p=%d$%s$%s$", aikRecoveryN, aikRecoveryR, aikRecoveryP, saltB64, nonceB64)

	gcm, err := wolfcrypt.NewAESGCM(kek)
	if err != nil {
		return "", err
	}
	ct, err := gcm.Seal(nonce, plain, []byte(header))
	if err != nil {
		return "", err
	}

	return header + base64.RawStdEncoding.EncodeToString(ct), nil
}

func OpenAIK(blob string, passphrase []byte) (*AccountIdentityKey, error) {
	n, r, p, salt, nonce, header, ct, err := parseBlob(blob)
	if err != nil {
		return nil, err
	}
	if n < minN || r < minR || p < minP {
		return nil, ErrRecoveryParamsInsecure
	}

	kek, err := wolfcrypt.Scrypt(passphrase, salt, n, r, p, aikRecoveryKeyLen)
	if err != nil {
		return nil, err
	}

	gcm, err := wolfcrypt.NewAESGCM(kek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nonce, ct, []byte(header))
	if err != nil {
		return nil, ErrRecoveryBadPassphrase
	}

	return deserializeAIK(plain)
}

func PaperKey(sealed string) (string, error) {
	n, r, p, salt, nonce, _, ct, err := parseBlob(sealed)
	if err != nil {
		return "", err
	}

	paramsDisplay := fmt.Sprintf("N=%d r=%d p=%d", n, r, p)

	saltB32 := b32enc.EncodeToString(salt)
	nonceB32 := b32enc.EncodeToString(nonce)
	ctB32 := b32enc.EncodeToString(ct)

	var sb strings.Builder
	sb.WriteString("X3DHPQ-AIK-V1\n")
	sb.WriteString(paramsDisplay + "\n")
	sb.WriteString(saltB32 + "\n")
	sb.WriteString(nonceB32 + "\n")
	sb.WriteString(groupB32(ctB32) + "\n")
	return sb.String(), nil
}

func PaperKeyDecode(paper string) (string, error) {
	lines := splitPaperLines(paper)
	if len(lines) < 5 {
		return "", ErrRecoveryMalformed
	}
	if lines[0] != "X3DHPQ-AIK-V1" {
		return "", ErrRecoveryMalformed
	}

	paramsRaw := strings.ReplaceAll(lines[1], " ", ",")
	n, r, p, err := parseParams(paramsRaw)
	if err != nil {
		return "", ErrRecoveryMalformed
	}

	salt, err := b32enc.DecodeString(strings.ToUpper(lines[2]))
	if err != nil {
		return "", ErrRecoveryMalformed
	}
	nonce, err := b32enc.DecodeString(strings.ToUpper(lines[3]))
	if err != nil {
		return "", ErrRecoveryMalformed
	}

	ctRaw := strings.Join(lines[4:], "")
	ctRaw = strings.ReplaceAll(ctRaw, " ", "")
	ctRaw = strings.ToUpper(ctRaw)
	ct, err := b32enc.DecodeString(ctRaw)
	if err != nil {
		return "", ErrRecoveryMalformed
	}

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	ctB64 := base64.RawStdEncoding.EncodeToString(ct)
	return fmt.Sprintf("x3dhpqv1$N=%d,r=%d,p=%d$%s$%s$%s", n, r, p, saltB64, nonceB64, ctB64), nil
}

func serializeAIK(aik *AccountIdentityKey) []byte {
	privMLDSA := []byte{}
	pubMLDSA := aik.PubMLDSA

	size := 2 + // version
		2 + len(aik.PrivEd25519) +
		2 + len(aik.PubEd25519) +
		2 + len(privMLDSA) +
		2 + len(pubMLDSA)

	buf := make([]byte, size)
	off := 0

	binary.BigEndian.PutUint16(buf[off:], aikRecoveryVersion)
	off += 2

	binary.BigEndian.PutUint16(buf[off:], uint16(len(aik.PrivEd25519)))
	off += 2
	copy(buf[off:], aik.PrivEd25519)
	off += len(aik.PrivEd25519)

	binary.BigEndian.PutUint16(buf[off:], uint16(len(aik.PubEd25519)))
	off += 2
	copy(buf[off:], aik.PubEd25519)
	off += len(aik.PubEd25519)

	binary.BigEndian.PutUint16(buf[off:], uint16(len(privMLDSA)))
	off += 2
	off += len(privMLDSA)

	binary.BigEndian.PutUint16(buf[off:], uint16(len(pubMLDSA)))
	off += 2
	copy(buf[off:], pubMLDSA)

	return buf
}

func deserializeAIK(buf []byte) (*AccountIdentityKey, error) {
	if len(buf) < 2 {
		return nil, ErrRecoveryMalformed
	}
	off := 0
	ver := binary.BigEndian.Uint16(buf[off:])
	off += 2
	if ver != 1 {
		return nil, fmt.Errorf("recovery: unsupported AIK version %d", ver)
	}

	readField := func() ([]byte, error) {
		if off+2 > len(buf) {
			return nil, ErrRecoveryMalformed
		}
		l := int(binary.BigEndian.Uint16(buf[off:]))
		off += 2
		if off+l > len(buf) {
			return nil, ErrRecoveryMalformed
		}
		v := buf[off : off+l]
		off += l
		return v, nil
	}

	privEd, err := readField()
	if err != nil {
		return nil, err
	}
	pubEd, err := readField()
	if err != nil {
		return nil, err
	}
	_, err = readField() // privMLDSA reserved
	if err != nil {
		return nil, err
	}
	pubMLDSA, err := readField()
	if err != nil {
		return nil, err
	}

	aik := &AccountIdentityKey{
		PrivEd25519: privEd,
		PubEd25519:  pubEd,
	}
	if len(pubMLDSA) > 0 {
		aik.PubMLDSA = pubMLDSA
	}
	return aik, nil
}

// parseBlob parses "x3dhpqv1$<params>$<b64salt>$<b64nonce>$<b64ct>"
// returns n, r, p, salt, nonce, header (everything up to and including final $), ciphertext.
func parseBlob(blob string) (n, r, p int, salt, nonce []byte, header string, ct []byte, err error) {
	if !strings.HasPrefix(blob, "x3dhpqv1$") {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}
	// split into exactly 6 parts: ["x3dhpqv1", params, b64salt, b64nonce, "", b64ct]
	// but the format is "x3dhpqv1$params$salt$nonce$ct" — 5 $ separators → 5 fields after first
	// Actually format: "x3dhpqv1$N=...$<salt>$<nonce>$<ct>"
	// SplitN with 6 gives ["x3dhpqv1", "N=...", "<salt>", "<nonce>", "<ct>"] — 5 parts
	parts := strings.SplitN(blob, "$", 5)
	if len(parts) != 5 {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	n, r, p, err = parseParams(parts[1])
	if err != nil {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	nonce, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(nonce) == 0 {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	if parts[4] == "" {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	ct, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(ct) == 0 {
		return 0, 0, 0, nil, nil, "", nil, ErrRecoveryMalformed
	}

	// header is everything up to and including the trailing $ before the ciphertext
	// reconstruct as blob minus the last field
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	nonceB64 := base64.RawStdEncoding.EncodeToString(nonce)
	header = fmt.Sprintf("x3dhpqv1$N=%d,r=%d,p=%d$%s$%s$", n, r, p, saltB64, nonceB64)

	return n, r, p, salt, nonce, header, ct, nil
}

func parseParams(s string) (n, r, p int, err error) {
	// accepts "N=131072,r=8,p=1" or "N=131072 r=8 p=1"
	s = strings.ReplaceAll(s, " ", ",")
	kv := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		kv2 := strings.SplitN(part, "=", 2)
		if len(kv2) != 2 {
			return 0, 0, 0, ErrRecoveryMalformed
		}
		kv[kv2[0]] = kv2[1]
	}
	nv, ok1 := kv["N"]
	rv, ok2 := kv["r"]
	pv, ok3 := kv["p"]
	if !ok1 || !ok2 || !ok3 {
		return 0, 0, 0, ErrRecoveryMalformed
	}
	n64, e1 := strconv.ParseInt(nv, 10, 64)
	r64, e2 := strconv.ParseInt(rv, 10, 64)
	p64, e3 := strconv.ParseInt(pv, 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, 0, 0, ErrRecoveryMalformed
	}
	return int(n64), int(r64), int(p64), nil
}

// groupB32 formats a base32 string as groups of 4 chars, 8 groups per line.
func groupB32(s string) string {
	var sb strings.Builder
	groupSize := 4
	lineGroups := 8
	groupCount := 0
	for i := 0; i < len(s); i += groupSize {
		end := i + groupSize
		if end > len(s) {
			end = len(s)
		}
		if groupCount > 0 {
			if groupCount%lineGroups == 0 {
				sb.WriteByte('\n')
			} else {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(s[i:end])
		groupCount++
	}
	return sb.String()
}

// splitPaperLines splits a paper key into trimmed, non-empty lines, then
// joins lines 4+ back if they got split by groupB32's embedded newlines.
func splitPaperLines(paper string) []string {
	raw := strings.Split(strings.TrimSpace(paper), "\n")
	var lines []string
	for _, l := range raw {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

type RecoverOptions struct {
	PrevAuditEntry *AuditEntry
	DeviceCount    uint16
	Timestamp      int64
}

// OpenAIKAndRecord unseals the blob with the passphrase and emits the
// required RecoverFromBackup audit entry. Callers MUST publish the
// returned entry to the user's audit-chain PEP node before any further
// protocol traffic. The bare OpenAIK may be used for in-memory tests or
// sanity-checking a backup blob, but production recovery flows MUST go
// through OpenAIKAndRecord.
func OpenAIKAndRecord(blob string, passphrase []byte, opts RecoverOptions) (*AccountIdentityKey, *AuditEntry, error) {
	aik, err := OpenAIK(blob, passphrase)
	if err != nil {
		return nil, nil, err
	}
	payload := PayloadRecoverFromBackup(opts.Timestamp, opts.DeviceCount)
	entry, err := aik.AppendAudit(opts.PrevAuditEntry, AuditActionRecoverFromBackup, payload, opts.Timestamp)
	if err != nil {
		return nil, nil, err
	}
	return aik, entry, nil
}
