package c2s

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func goHMACSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func goSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// goSHA256PBKDF2 implements PBKDF2-HMAC-SHA256.
func goSHA256PBKDF2(password, salt []byte, iter, keyLen int) ([]byte, error) {
	prf := func(data []byte) []byte {
		return goHMACSHA256(password, data)
	}
	numBlocks := (keyLen + 31) / 32
	out := make([]byte, 0, numBlocks*32)
	for block := 1; block <= numBlocks; block++ {
		// U1 = PRF(password, salt || INT(block))
		buf := make([]byte, len(salt)+4)
		copy(buf, salt)
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(block))
		u := prf(buf)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen], nil
}
