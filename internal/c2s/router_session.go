package c2s

import (
	"bytes"

	"github.com/danielinux/xmppqr/internal/csi"
)

// stanzaInfo inspects raw stanza bytes to build a csi.StanzaInfo.
func stanzaInfo(raw []byte) csi.StanzaInfo {
	info := csi.StanzaInfo{}

	// Detect kind from opening tag
	if len(raw) < 2 {
		return info
	}
	if bytes.HasPrefix(raw, []byte("<message")) {
		info.Kind = csi.KindMessage
	} else if bytes.HasPrefix(raw, []byte("<presence")) {
		info.Kind = csi.KindPresence
	} else if bytes.HasPrefix(raw, []byte("<iq")) {
		info.Kind = csi.KindIQ
	}

	info.HasBody = bytes.Contains(raw, []byte("<body"))
	info.IsError = bytes.Contains(raw, []byte(`type="error"`)) || bytes.Contains(raw, []byte(`type='error'`))
	info.HasChatState = bytes.Contains(raw, []byte("http://jabber.org/protocol/chatstates"))
	info.IsMUCSubject = bytes.Contains(raw, []byte("<subject"))

	// Extract from attribute
	idx := bytes.Index(raw, []byte("from="))
	if idx >= 0 {
		rest := raw[idx+5:]
		if len(rest) > 0 {
			q := rest[0]
			end := bytes.IndexByte(rest[1:], q)
			if end >= 0 {
				info.FromJID = string(rest[1 : end+1])
			}
		}
	}

	return info
}
