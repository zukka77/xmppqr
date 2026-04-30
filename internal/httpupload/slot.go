package httpupload

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"context"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

const nsHTTPUpload = "urn:xmpp:http:upload:0"

type slotRequest struct {
	XMLName     xml.Name `xml:"request"`
	Filename    string   `xml:"filename,attr"`
	Size        int64    `xml:"size,attr"`
	ContentType string   `xml:"content-type,attr"`
}

func (s *Service) HandleIQ(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	if iq.Type != stanza.IQSet {
		return stanzaError(stanza.ErrorTypeCancel, stanza.ErrBadRequest, "")
	}

	var req slotRequest
	if err := xml.Unmarshal(iq.Payload, &req); err != nil {
		return stanzaError(stanza.ErrorTypeModify, stanza.ErrBadRequest, "malformed request")
	}
	if req.XMLName.Space != nsHTTPUpload {
		return stanzaError(stanza.ErrorTypeCancel, stanza.ErrBadRequest, "wrong namespace")
	}

	if req.Size > s.maxFileSize {
		return fileTooLarge(s.maxFileSize)
	}
	if req.Size <= 0 {
		return stanzaError(stanza.ErrorTypeModify, stanza.ErrBadRequest, "invalid size")
	}

	filename := sanitizeFilename(req.Filename)
	if filename == "" {
		return stanzaError(stanza.ErrorTypeModify, stanza.ErrBadRequest, "invalid filename")
	}

	slotID, token, expiry, err := s.newToken(filename, req.Size)
	if err != nil {
		return stanzaError(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
	}
	if db, ok := s.backend.(*DiskBackend); ok {
		if err := db.WriteSlotMeta(slotID, filename, req.Size, expiry); err != nil {
			return stanzaError(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
		}
	}

	putURL := fmt.Sprintf("%s/upload/%s?token=%s", s.baseURL, slotID, token)
	getURL := fmt.Sprintf("%s/download/%s/%s", s.baseURL, slotID, filename)

	var buf strings.Builder
	buf.WriteString(`<slot xmlns='urn:xmpp:http:upload:0'>`)
	buf.WriteString(`<put url='`)
	xml.EscapeText(&buf, []byte(putURL))
	buf.WriteString(`'/>`)
	buf.WriteString(`<get url='`)
	xml.EscapeText(&buf, []byte(getURL))
	buf.WriteString(`'/>`)
	buf.WriteString(`</slot>`)

	return []byte(buf.String()), nil
}

func (s *Service) newToken(filename string, size int64) (slotID, token, expiry string, err error) {
	raw := make([]byte, 16)
	if _, err = wolfcrypt.Read(raw); err != nil {
		return
	}
	slotID = base64.RawURLEncoding.EncodeToString(raw)
	expiry = strconv.FormatInt(time.Now().Add(s.tokenTTL).Unix(), 10)

	msg := []byte(slotID + "|" + expiry + "|" + filename + "|" + strconv.FormatInt(size, 10))
	mac, err := wolfcrypt.HMACSHA256(s.secret, msg)
	if err != nil {
		return
	}
	token = slotID + "." + expiry + "." + base64.RawURLEncoding.EncodeToString(mac)
	return
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	if name == "." || name == "/" {
		return ""
	}
	return name
}

func stanzaError(errType, condition, text string) ([]byte, error) {
	e := &stanza.StanzaError{Type: errType, Condition: condition, Text: text}
	return e.Marshal()
}

func fileTooLarge(max int64) ([]byte, error) {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf(
		`<error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>`+
			`<file-too-large xmlns='urn:xmpp:http:upload:0'><max-file-size>%d</max-file-size></file-too-large></error>`,
		max,
	))
	return []byte(buf.String()), nil
}
