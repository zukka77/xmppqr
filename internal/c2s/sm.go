package c2s

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

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
		ttl := s.cfg.ResumeTimeout
		if ttl <= 0 {
			ttl = 300 * time.Second
		}
		t, err := s.cfg.ResumeStore.Issue(ctx, s.jid, ttl)
		if err == nil {
			tok = string(t)
			s.smResumeToken = tok
			s.cfg.ResumeStore.SetParkCallback(t, func() {
				s.parkIfResumable()
				if s.cfg.Router != nil {
					s.cfg.Router.Unregister(s)
				}
			})
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

	state, ok := s.cfg.ResumeStore.Take(sm.ResumeToken(prevID))
	if !ok {
		_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<failed xmlns='%s'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>`, nsSM)))
		return false
	}

	s.jid = state.JID
	atomic.StoreUint32(&s.smInH, state.LastInH)
	s.smResumeToken = prevID

	if s.smQueue == nil {
		s.smQueue = sm.New(512)
	}
	s.smQueue.Ack(hVal)

	_, _ = s.enc.WriteRaw([]byte(fmt.Sprintf(`<resumed xmlns='%s' previd='%s' h='%d'/>`, nsSM, prevID, atomic.LoadUint32(&s.smInH))))

	replay := append(state.OutQueueTail, state.Pending...)
	for _, raw := range replay {
		s.outbound <- raw
	}

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
