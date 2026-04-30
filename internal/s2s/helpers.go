package s2s

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
)

func newStreamID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func extractTextBody(raw []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if cd, ok := tok.(xml.CharData); ok {
			s := string(bytes.TrimSpace(cd))
			if s != "" {
				return s
			}
		}
	}
}

func (p *Pool) handleDBVerify(streamID, from, to, key string) bool {
	expected := DialbackKey(p.secret, to, from, streamID)
	return expected == key
}
