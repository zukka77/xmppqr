package s2s

import (
	"encoding/hex"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

// DialbackKey computes the XEP-0220 §2.3 dialback key:
//
//	HEX(HMAC-SHA-256(SHA-256(secret), receiving || ' ' || originating || ' ' || streamID))
func DialbackKey(secret []byte, receiving, originating, streamID string) string {
	hashed := wolfcrypt.SHA256(secret)
	msg := []byte(receiving + " " + originating + " " + streamID)
	mac, err := wolfcrypt.HMACSHA256(hashed[:], msg)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(mac)
}
