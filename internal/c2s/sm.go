package c2s

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/danielinux/xmppqr/internal/sm"
)

func handleSMEnable(ctx context.Context, s *Session, start xml.StartElement) {
	if s.smQueue != nil {
		return // already enabled
	}
	resume := false
	for _, a := range start.Attr {
		if a.Name.Local == "resume" && a.Value == "true" {
			resume = true
		}
	}
	s.smQueue = sm.New(512)

	var tok string
	if resume && s.cfg.ResumeStore != nil {
		t, err := s.cfg.ResumeStore.Issue(ctx, s.jid)
		if err == nil {
			tok = string(t)
		}
	}

	var resp string
	if tok != "" {
		resp = fmt.Sprintf(`<enabled xmlns='%s' resume='true' id='%s'/>`, nsSM, tok)
	} else {
		resp = fmt.Sprintf(`<enabled xmlns='%s'/>`, nsSM)
	}
	_, _ = s.enc.WriteRaw([]byte(resp))
}

func handleSMResume(ctx context.Context, s *Session, start xml.StartElement) bool {
	if s.cfg.ResumeStore == nil {
		_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<failed xmlns='%s'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>`, nsSM)))
		return false
	}

	prevID := ""
	var hVal uint32
	for _, a := range start.Attr {
		switch a.Name.Local {
		case "previd":
			prevID = a.Value
		case "h":
			v, _ := strconv.ParseUint(a.Value, 10, 32)
			hVal = uint32(v)
		}
	}

	jid, ok := s.cfg.ResumeStore.Lookup(sm.ResumeToken(prevID))
	if !ok {
		_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<failed xmlns='%s'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>`, nsSM)))
		return false
	}

	s.jid = jid
	if s.smQueue != nil {
		s.smQueue.Ack(hVal)
		for _, raw := range s.smQueue.Unacked() {
			s.outbound <- raw
		}
	}

	_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<resumed xmlns='%s' previd='%s' h='%d'/>`, nsSM, prevID, atomic.LoadUint32(&s.smInH))))
	return true
}

func handleSMAck(s *Session, start xml.StartElement) {
	if s.smQueue == nil {
		return
	}
	for _, a := range start.Attr {
		if a.Name.Local == "h" {
			v, err := strconv.ParseUint(a.Value, 10, 32)
			if err == nil {
				s.smQueue.Ack(uint32(v))
			}
			break
		}
	}
}

func handleSMRequest(s *Session) {
	h := atomic.LoadUint32(&s.smInH)
	_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<a xmlns='%s' h='%d'/>`, nsSM, h)))
}
