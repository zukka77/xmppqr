package c2s

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/danielinux/xmppqr/internal/disco"
	"github.com/danielinux/xmppqr/internal/x3dhpq"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/version"
	xmlpkg "github.com/danielinux/xmppqr/internal/xml"
)

var serverStartTime = time.Now()

func runStream(ctx context.Context, s *Session) error {
	hdr, err := s.dec.OpenStream(ctx)
	if err != nil {
		return err
	}

	if hdr.To != "" && hdr.To != s.cfg.Domain {
		_ = sendStreamHeader(s, "")
		_, _ = s.enc.WriteRaw(streamError("host-unknown"))
		return fmt.Errorf("host-unknown: client requested %q", hdr.To)
	}

	streamID := newStreamID()
	if err := sendStreamHeader(s, streamID); err != nil {
		return err
	}

	if _, err := s.enc.WriteRaw(buildFeatures(s, true, false)); err != nil {
		return err
	}

	authRes, err := authLoop(ctx, s)
	if err != nil {
		return err
	}
	s.jid = stanza.JID{Local: authRes.Username, Domain: s.cfg.Domain}

	switch authRes.Style {
	case authStyleLegacy:
		if err := sendLegacySASLSuccess(s, authRes.ServerFinal); err != nil {
			return err
		}
		if err := restartPostAuthStream(ctx, s); err != nil {
			return err
		}
	default:
		bindExtras, err := bindLoop(ctx, s)
		if err != nil {
			return err
		}
		fullJID := s.jid.String()
		if err := sendSASL2Success(s, fullJID, bindExtras, authRes.ServerFinal); err != nil {
			return err
		}
	}

	if s.cfg.Router != nil {
		s.cfg.Router.Register(s)
		defer func() {
			parked := s.parkIfResumable()
			s.cfg.Router.Unregister(s)
			// Only evict MUC occupants when the session is permanently
			// gone. A parked SM session may resume with the same FullJID,
			// in which case the user is still "in the room" from the
			// MUC's perspective.
			if !parked && s.cfg.Modules != nil && s.cfg.Modules.MUC != nil && s.jid.Resource != "" {
				s.cfg.Modules.MUC.OnSessionEnd(context.Background(), s.jid)
			}
		}()
	}

	writerCtx, cancelWriter := context.WithCancel(ctx)
	defer cancelWriter()
	go runWriter(writerCtx, s, cancelWriter)

	return readerLoop(ctx, s)
}

func sendStreamHeader(s *Session, id string) error {
	h := xmlpkg.StreamHeader{
		From:    s.cfg.Domain,
		ID:      id,
		Version: "1.0",
	}
	return s.enc.OpenStream(h)
}

func newStreamID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

const nsIQRegister = "jabber:iq:register"

func authLoop(ctx context.Context, s *Session) (*authResult, error) {
	for {
		start, raw, err := s.dec.NextElement()
		if err != nil {
			return nil, err
		}
		switch start.Name.Local {
		case "authenticate":
			s.log.Info("pre-auth mechanism", "element", "authenticate", "ns", start.Name.Space, "mechanism", authMechanism(start))
			return handleAuthenticate(ctx, s, start, raw)
		case "auth":
			if start.Name.Space != nsSASL {
				s.log.Warn("pre-auth: unexpected auth namespace", "ns", start.Name.Space)
				continue
			}
			s.log.Info("pre-auth mechanism", "element", "auth", "ns", start.Name.Space, "mechanism", authMechanism(start))
			return handleLegacyAuth(ctx, s, start, raw)
		case "iq":
			mods := s.cfg.Modules
			if mods == nil || mods.IBR == nil || !mods.IBR.Allowed() {
				s.log.Warn("pre-auth: IQ without IBR enabled")
				continue
			}
			iq, iqErr := stanza.ParseIQ(start, raw)
			if iqErr == nil && firstChildNS(iq.Payload) == nsIQRegister {
				resp, herr := mods.IBR.HandleIQ(ctx, iq)
				writeIQResponse(s, iq, resp, herr)
				continue
			}
		default:
			s.log.Warn("pre-auth: unexpected element", "local", start.Name.Local, "ns", start.Name.Space)
		}
	}
}

func authMechanism(start xml.StartElement) string {
	for _, a := range start.Attr {
		if a.Name.Local == "mechanism" {
			return a.Value
		}
	}
	return ""
}

func sendSASL2Success(s *Session, fullJID string, bindExtras string, serverFinal []byte) error {
	var extraData string
	if len(serverFinal) > 0 {
		extraData = fmt.Sprintf(`<additional-data>%s</additional-data>`, base64.StdEncoding.EncodeToString(serverFinal))
	}
	_, err := s.enc.WriteRaw([]byte(fmt.Sprintf(
		`<success xmlns='%s'>%s<authorization-identifier>%s</authorization-identifier>%s</success>`,
		nsSASL2, extraData, fullJID, bindExtras,
	)))
	return err
}

func sendLegacySASLSuccess(s *Session, serverFinal []byte) error {
	payload := ""
	if len(serverFinal) > 0 {
		payload = base64.StdEncoding.EncodeToString(serverFinal)
	}
	_, err := s.enc.WriteRaw([]byte(fmt.Sprintf(`<success xmlns='%s'>%s</success>`, nsSASL, payload)))
	return err
}

func restartPostAuthStream(ctx context.Context, s *Session) error {
	hdr, err := s.dec.OpenStream(ctx)
	if err != nil {
		return err
	}
	if hdr.To != "" && hdr.To != s.cfg.Domain {
		_ = sendStreamHeader(s, "")
		_, _ = s.enc.WriteRaw(streamError("host-unknown"))
		return fmt.Errorf("host-unknown: client requested %q", hdr.To)
	}
	if err := sendStreamHeader(s, newStreamID()); err != nil {
		return err
	}
	_, err = s.enc.WriteRaw(buildLegacyPostAuthFeatures())
	return err
}

func bindLoop(ctx context.Context, s *Session) (string, error) {
	resource := randomResource()
	s.jid = stanza.JID{Local: s.jid.Local, Domain: s.cfg.Domain, Resource: resource}
	return "", nil
}

func readerLoop(ctx context.Context, s *Session) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		start, raw, err := s.dec.NextElement()
		if err != nil {
			return err
		}

		if err := dispatchElement(ctx, s, start, raw); err != nil {
			return err
		}
	}
}

func dispatchElement(ctx context.Context, s *Session, start xml.StartElement, raw []byte) error {
	local := start.Name.Local
	space := start.Name.Space

	if local == "message" || local == "presence" || local == "iq" {
		return handleStanza(ctx, s, start, raw)
	}

	if space == nsSM {
		switch local {
		case "enable":
			handleSMEnable(ctx, s, start)
			return nil
		case "resume":
			handleSMResume(ctx, s, start)
			return nil
		case "a":
			handleSMAck(s, start)
			return nil
		case "r":
			handleSMRequest(s)
			return nil
		}
	}

	if space == nsCSI {
		switch local {
		case "active":
			s.csiF.SetActive(true)
			for _, held := range s.csiF.FlushHeld() {
				select {
				case s.outbound <- held:
				default:
				}
			}
			return nil
		case "inactive":
			s.csiF.SetActive(false)
			return nil
		}
	}

	if local == "error" && space == nsStreamErr {
		return fmt.Errorf("stream error received from client")
	}

	id := ""
	for _, a := range start.Attr {
		if a.Name.Local == "id" {
			id = a.Value
			break
		}
	}
	resp := []byte(fmt.Sprintf(
		`<iq type='error' id='%s'><error type='cancel'><feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>`,
		id,
	))
	_, _ = s.enc.WriteRaw(resp)
	return nil
}

func handleStanza(ctx context.Context, s *Session, start xml.StartElement, raw []byte) error {
	if start.Name.Local == "iq" {
		return handleIQ(ctx, s, start, raw)
	}

	toJID := ""
	for _, a := range start.Attr {
		if a.Name.Local == "to" {
			toJID = a.Value
			break
		}
	}

	if start.Name.Local == "presence" && toJID == "" {
		return handleBarePresence(ctx, s, start, raw)
	}

	if toJID == "" {
		return nil
	}

	j, err := stanza.Parse(toJID)
	if err != nil {
		return nil
	}

	if start.Name.Local == "message" {
		return handleOutboundMessage(ctx, s, start, raw, j)
	}

	if start.Name.Local == "presence" {
		return handlePresence(ctx, s, start, raw, j)
	}

	if s.cfg.Router != nil {
		if j.Resource != "" {
			_ = s.cfg.Router.RouteToFull(ctx, j, raw)
		} else {
			_, _ = s.cfg.Router.RouteToBare(ctx, j, raw)
		}
	}

	atomic.AddUint32(&s.smInH, 1)
	return nil
}

func handleOutboundMessage(ctx context.Context, s *Session, start xml.StartElement, raw []byte, j stanza.JID) error {
	mods := s.cfg.Modules

	if mods != nil && mods.MUC != nil && mods.MUC.IsOurDomain(j) {
		msgType := ""
		for _, a := range start.Attr {
			if a.Name.Local == "type" {
				msgType = a.Value
				break
			}
		}
		if msgType == stanza.MessageGroupchat || msgType == "" || j.Domain == mods.MUC.Domain() {
			from := s.jid
			if err := mods.MUC.HandleStanza(ctx, raw, "message", from, j); err != nil {
				s.log.Warn("muc message failed", "from", from.String(), "to", j.String(), "err", err)
				writeStanzaErrorResponse(s, start.Name.Local, raw, s.jid.String(), j.String(), err)
			}
			atomic.AddUint32(&s.smInH, 1)
			return nil
		}
	}

	if mods != nil && mods.X3DHPQPolicy.X3DHPQOnlyMode {
		if err := x3dhpq.EnforceMessagePolicy(raw, mods.X3DHPQPolicy); err != nil {
			errMsg := fmt.Sprintf(
				`<message to='%s'><error type='cancel'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>`,
				xmlEscape(s.jid.String()),
			)
			_, _ = s.enc.WriteRaw([]byte(errMsg))
			atomic.AddUint32(&s.smInH, 1)
			return nil
		}
	}

	routedRaw := rewriteStanzaFrom(raw, s.jid.String())

	if mods != nil {
		senderBare := s.jid.Bare().String()
		msg, parseErr := stanza.ParseMessage(start, routedRaw)

		if parseErr == nil && mods.MAM != nil {
			_ = mods.MAM.Archive(ctx, senderBare, msg, 1, routedRaw)
		}

		if mods.Carbons != nil && s.cfg.Router != nil {
			allRes := s.cfg.Router.SessionsFor(senderBare)
			jids := make([]stanza.JID, 0, len(allRes))
			for _, sess := range allRes {
				// XEP-0280 §6: do NOT carbon back to the very session that
				// sent the stanza — otherwise sent-carbons loop to the
				// sender itself (the wrapped <message xmlns='jabber:client'>
				// inside <forwarded> looked malformed to xmpp-vala and
				// emitted "no message subnode in jabber:client namespace"
				// + xmpp_jid_construct null-jid criticals on dino, while
				// the actual recipient may have raced or been masked).
				if sess.JID().Equal(s.jid) {
					continue
				}
				jids = append(jids, sess.JID())
			}
			if len(jids) > 0 {
				_ = mods.Carbons.DeliverCarbons(ctx, s.jid.Bare(), j, routedRaw, 1, jids)
			}
		}
	}

	if s.cfg.Router != nil {
		if j.Resource != "" {
			_ = s.cfg.Router.RouteToFull(ctx, j, routedRaw)
		} else {
			_, _ = s.cfg.Router.RouteToBare(ctx, j, routedRaw)
		}
	}

	atomic.AddUint32(&s.smInH, 1)
	return nil
}

func handlePresence(ctx context.Context, s *Session, start xml.StartElement, raw []byte, j stanza.JID) error {
	presType := ""
	for _, a := range start.Attr {
		if a.Name.Local == "type" {
			presType = a.Value
			break
		}
	}

	mods := s.cfg.Modules

	if mods != nil && mods.MUC != nil && mods.MUC.IsOurDomain(j) {
		from := s.jid
		if err := mods.MUC.HandleStanza(ctx, raw, "presence", from, j); err != nil {
			s.log.Warn("muc presence failed", "from", from.String(), "to", j.String(), "err", err)
			writeStanzaErrorResponse(s, start.Name.Local, raw, s.jid.String(), j.String(), err)
		}
		atomic.AddUint32(&s.smInH, 1)
		return nil
	}

	avail := presType == "" || presType == "available"
	if avail {
		atomic.StoreInt32(&s.avail, 1)
	} else if presType == "unavailable" || presType == "error" {
		atomic.StoreInt32(&s.avail, 0)
	}
	atomic.StoreInt32(&s.priority, 0)

	switch presType {
	case stanza.PresenceSubscribe:
		if mods != nil && mods.Roster != nil {
			item, _ := mods.Roster.Subscribe(ctx, s.jid.Bare().String(), j.Bare())
			s.sendRosterPush(ctx, item)
		}
		if s.cfg.Router != nil {
			_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), raw)
		}
	case stanza.PresenceSubscribed:
		if mods != nil && mods.Roster != nil {
			item, _ := mods.Roster.Subscribed(ctx, s.jid.Bare().String(), j.Bare())
			s.sendRosterPush(ctx, item)
			if curPres := s.currentAvailablePresence(); curPres != nil && s.cfg.Router != nil {
				_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), curPres)
			}
		}
		if s.cfg.Router != nil {
			_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), raw)
		}
	case stanza.PresenceUnsubscribe:
		if mods != nil && mods.Roster != nil {
			item, _ := mods.Roster.Unsubscribe(ctx, s.jid.Bare().String(), j.Bare())
			s.sendRosterPush(ctx, item)
		}
		if s.cfg.Router != nil {
			_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), raw)
		}
	case stanza.PresenceUnsubscribed:
		if mods != nil && mods.Roster != nil {
			item, _ := mods.Roster.Unsubscribed(ctx, s.jid.Bare().String(), j.Bare())
			s.sendRosterPush(ctx, item)
			if s.cfg.Router != nil {
				for _, unavail := range s.unavailablePresenceStanzas() {
					_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), unavail)
				}
			}
		}
		if s.cfg.Router != nil {
			_, _ = s.cfg.Router.RouteToBare(ctx, j.Bare(), raw)
		}
	case stanza.PresenceUnavailable:
		atomic.StoreInt32(&s.avail, 0)
		if mods != nil && mods.Presence != nil {
			_ = mods.Presence.OnUnavailablePresence(ctx, s, raw)
		} else if s.cfg.Router != nil {
			if j.Resource != "" {
				_ = s.cfg.Router.RouteToFull(ctx, j, raw)
			} else {
				_, _ = s.cfg.Router.RouteToBare(ctx, j, raw)
			}
		}
	default:
		// available presence (no type or type='available')
		if mods != nil && mods.Presence != nil {
			// use wasAvail to distinguish initial vs update
			wasAvail := atomic.LoadInt32(&s.avail) == 1
			atomic.StoreInt32(&s.avail, 1)
			if !wasAvail {
				_ = mods.Presence.OnInitialPresence(ctx, s, raw)
			} else {
				_ = mods.Presence.OnPresenceUpdate(ctx, s, raw)
			}
		} else if s.cfg.Router != nil {
			if j.Resource != "" {
				_ = s.cfg.Router.RouteToFull(ctx, j, raw)
			} else {
				_, _ = s.cfg.Router.RouteToBare(ctx, j, raw)
			}
		}
	}

	atomic.AddUint32(&s.smInH, 1)
	return nil
}

func handleBarePresence(ctx context.Context, s *Session, start xml.StartElement, raw []byte) error {
	presType := ""
	for _, a := range start.Attr {
		if a.Name.Local == "type" {
			presType = a.Value
			break
		}
	}

	mods := s.cfg.Modules

	switch presType {
	case "", "available":
		atomic.StoreInt32(&s.avail, 1)
		if mods != nil && mods.Caps != nil {
			_ = mods.Caps.RecordPresence(s.jid, raw)
		}
		if mods != nil && mods.Presence != nil {
			if !s.initialPresenceSent {
				s.initialPresenceSent = true
				_ = mods.Presence.OnInitialPresence(ctx, s, raw)
			} else {
				_ = mods.Presence.OnPresenceUpdate(ctx, s, raw)
			}
		}
	case stanza.PresenceUnavailable:
		atomic.StoreInt32(&s.avail, 0)
		if mods != nil && mods.Caps != nil {
			mods.Caps.Forget(s.jid)
		}
		if mods != nil && mods.Presence != nil {
			_ = mods.Presence.OnUnavailablePresence(ctx, s, raw)
		}
	}

	atomic.AddUint32(&s.smInH, 1)
	return nil
}

func handleIQ(ctx context.Context, s *Session, start xml.StartElement, raw []byte) error {
	iq, err := stanza.ParseIQ(start, raw)
	if err != nil {
		return nil
	}

	ns := firstChildNS(iq.Payload)
	if ns == nsBind2 || ns == "urn:ietf:params:xml:ns:xmpp-bind" {
		resource := randomResource()
		s.jid = stanza.JID{Local: s.jid.Local, Domain: s.cfg.Domain, Resource: resource}
		resp := fmt.Sprintf(`<iq id='%s' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>%s</jid></bind></iq>`,
			iq.ID, s.jid.String())
		_, _ = s.enc.WriteRaw([]byte(resp))
		atomic.AddUint32(&s.smInH, 1)
		return nil
	}

	if iq.To != "" {
		j, parseErr := stanza.Parse(iq.To)
		if parseErr == nil {
			isLocal := j.Domain == s.cfg.Domain || j.Domain == ""
			isMUCDomain := s.cfg.Modules != nil && s.cfg.Modules.MUC != nil && s.cfg.Modules.MUC.IsOurDomain(j)
			if isMUCDomain {
				if iq.From == "" {
					iq.From = s.jid.String()
				}
				respBytes, herr := s.cfg.Modules.MUC.HandleIQ(ctx, iq)
				writeIQResponse(s, iq, respBytes, herr)
				atomic.AddUint32(&s.smInH, 1)
				return nil
			}
			if !isLocal || j.Resource != "" {
				if s.cfg.Router != nil {
					if j.Resource != "" {
						_ = s.cfg.Router.RouteToFull(ctx, j, raw)
					} else {
						_, _ = s.cfg.Router.RouteToBare(ctx, j, raw)
					}
				}
				atomic.AddUint32(&s.smInH, 1)
				return nil
			}
		}
	}

	respBytes, herr := dispatchLocalIQ(ctx, s, iq)
	writeIQResponse(s, iq, respBytes, herr)
	atomic.AddUint32(&s.smInH, 1)
	return nil
}

func writeIQResponse(s *Session, iq *stanza.IQ, respBytes []byte, err error) {
	if err != nil {
		se, ok := err.(*stanza.StanzaError)
		if !ok {
			se = &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
		}
		errBytes, _ := se.Marshal()
		errIQ := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQError, Payload: errBytes}
		raw, _ := errIQ.Marshal()
		_, _ = s.enc.WriteRaw(raw)
		return
	}
	if respBytes != nil {
		_, _ = s.enc.WriteRaw(respBytes)
	}
}

func writeStanzaErrorResponse(s *Session, stanzaLocal string, original []byte, from, to string, err error) {
	se, ok := err.(*stanza.StanzaError)
	if !ok {
		se = &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrInternalServerError}
	}
	errBytes, merr := se.Marshal()
	if merr != nil {
		s.log.Warn("marshal stanza error failed", "stanza", stanzaLocal, "err", merr)
		return
	}
	var idAttr string
	if id := extractAttr(original, "id"); id != "" {
		idAttr = fmt.Sprintf(` id='%s'`, xmlEscape(id))
	}
	resp := fmt.Sprintf(
		`<%s from='%s' to='%s'%s type='error'>%s</%s>`,
		stanzaLocal,
		xmlEscape(from),
		xmlEscape(to),
		idAttr,
		errBytes,
		stanzaLocal,
	)
	_, _ = s.enc.WriteRaw([]byte(resp))
}

func dispatchLocalIQ(ctx context.Context, s *Session, iq *stanza.IQ) ([]byte, error) {
	ns := firstChildNS(iq.Payload)
	mods := s.cfg.Modules

	switch ns {
	case "http://jabber.org/protocol/disco#info":
		if mods != nil && mods.Disco != nil {
			return disco.HandleDiscoInfo(iq, mods.Disco)
		}
	case "http://jabber.org/protocol/disco#items":
		var discoItems []string
		if mods != nil && mods.MUC != nil {
			discoItems = append(discoItems, mods.MUC.Domain())
		}
		return disco.HandleDiscoItems(iq, discoItems...)
	case "vcard-temp":
		if mods != nil && mods.VCard != nil {
			raw, err := mods.VCard.HandleIQ(ctx, iq)
			if err != nil {
				return nil, err
			}
			result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: raw}
			return result.Marshal()
		}
	case "urn:xmpp:blocking":
		if mods != nil && mods.Block != nil {
			raw, err := mods.Block.HandleIQ(ctx, iq)
			if err != nil {
				return nil, err
			}
			result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: raw}
			return result.Marshal()
		}
	case "urn:xmpp:mam:2":
		if mods != nil && mods.MAM != nil {
			ownerBare := s.jid.Bare().String()
			deliver := func(msg []byte) error {
				_, werr := s.enc.WriteRaw(msg)
				return werr
			}
			return mods.MAM.HandleIQ(ctx, iq, ownerBare, deliver)
		}
	case "http://jabber.org/protocol/pubsub", "http://jabber.org/protocol/pubsub#owner":
		if mods != nil && mods.PEP != nil {
			if iq.From == "" {
				iq.From = s.jid.String()
			}
			return mods.PEP.HandleIQ(ctx, s.jid, iq)
		}
		if mods != nil && mods.PubSub != nil {
			if iq.From == "" {
				iq.From = s.jid.String()
			}
			return mods.PubSub.HandleIQ(ctx, s.jid.Bare(), iq)
		}
	case "urn:xmpp:push:0":
		if mods != nil && mods.Push != nil {
			if iq.Type == stanza.IQSet {
				local := firstChildLocal(iq.Payload)
				if local == "enable" {
					svcJIDStr, node, formXML := parsePushEnable(iq.Payload)
					svcJID, jerr := stanza.Parse(svcJIDStr)
					if jerr == nil {
						_ = mods.Push.Enable(ctx, s.jid, svcJID, node, formXML)
					}
				} else if local == "disable" {
					svcJIDStr, node, _ := parsePushEnable(iq.Payload)
					svcJID, jerr := stanza.Parse(svcJIDStr)
					if jerr == nil {
						_ = mods.Push.Disable(ctx, s.jid, svcJID, node)
					}
				}
			}
			result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
			return result.Marshal()
		}
	case "urn:xmpp:http:upload:0":
		if mods != nil && mods.HTTPUpload != nil {
			raw, err := mods.HTTPUpload.HandleIQ(ctx, iq)
			if err != nil {
				return nil, err
			}
			result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: raw}
			return result.Marshal()
		}
	case "urn:ietf:params:xml:ns:xmpp-session":
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
		return result.Marshal()
	case "jabber:iq:version":
		payload := fmt.Sprintf(
			`<query xmlns='jabber:iq:version'><name>%s</name><version>%s</version><os>%s</os></query>`,
			version.Name(), version.Version(), version.OS(),
		)
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: []byte(payload)}
		return result.Marshal()
	case "urn:xmpp:time":
		now := time.Now().UTC()
		payload := fmt.Sprintf(
			`<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>%s</utc></time>`,
			now.Format("2006-01-02T15:04:05Z"),
		)
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: []byte(payload)}
		return result.Marshal()
	case "jabber:iq:last":
		secs := int64(time.Since(serverStartTime).Seconds())
		payload := fmt.Sprintf(`<query xmlns='jabber:iq:last' seconds='%d'/>`, secs)
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: []byte(payload)}
		return result.Marshal()
	case "urn:xmpp:ping":
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
		return result.Marshal()
	case "jabber:iq:roster":
		if mods != nil && mods.Roster != nil {
			return handleRosterIQ(ctx, s, iq, mods)
		}
	case "urn:xmpp:carbons:2":
		if mods != nil && mods.Carbons != nil {
			return handleCarbonsIQ(s, iq)
		}
	}

	se := &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrFeatureNotImplemented}
	errBytes, _ := se.Marshal()
	errIQ := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQError, Payload: errBytes}
	return errIQ.Marshal()
}

func handleRosterIQ(ctx context.Context, s *Session, iq *stanza.IQ, mods *Modules) ([]byte, error) {
	ownerBare := s.jid.Bare().String()

	switch iq.Type {
	case stanza.IQGet:
		items, ver, err := mods.Roster.Get(ctx, ownerBare)
		if err != nil {
			return nil, err
		}
		var qbuf bytes.Buffer
		fmt.Fprintf(&qbuf, `<query xmlns='jabber:iq:roster' ver='%d'>`, ver)
		for _, item := range items {
			sub := subscriptionName(item.Subscription)
			askAttr := ""
			if item.Ask == 1 {
				askAttr = ` ask='subscribe'`
			}
			if len(item.Groups) == 0 {
				fmt.Fprintf(&qbuf, `<item jid='%s' name='%s' subscription='%s'%s/>`,
					xmlEscape(item.Contact), xmlEscape(item.Name), sub, askAttr)
			} else {
				fmt.Fprintf(&qbuf, `<item jid='%s' name='%s' subscription='%s'%s>`,
					xmlEscape(item.Contact), xmlEscape(item.Name), sub, askAttr)
				for _, g := range item.Groups {
					fmt.Fprintf(&qbuf, `<group>%s</group>`, xmlEscape(g))
				}
				qbuf.WriteString(`</item>`)
			}
		}
		qbuf.WriteString(`</query>`)
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult, Payload: qbuf.Bytes()}
		return result.Marshal()

	case stanza.IQSet:
		dec := xml.NewDecoder(bytes.NewReader(iq.Payload))
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			se, ok := tok.(xml.StartElement)
			if !ok || se.Name.Local != "item" {
				continue
			}
			itemJIDStr := ""
			itemName := ""
			itemSub := ""
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "jid":
					itemJIDStr = a.Value
				case "name":
					itemName = a.Value
				case "subscription":
					itemSub = a.Value
				}
			}
			if itemJIDStr == "" {
				continue
			}
			contactJID, jerr := stanza.Parse(itemJIDStr)
			if jerr != nil {
				continue
			}
			if itemSub == "remove" {
				_, _ = mods.Roster.Remove(ctx, ownerBare, contactJID.Bare())
			} else {
				_, _ = mods.Roster.Set(ctx, ownerBare, contactJID.Bare(), itemName, nil)
			}
		}
		if s.cfg.Router != nil {
			pushSessions := s.cfg.Router.SessionsFor(ownerBare)
			for _, sess := range pushSessions {
				pushIQ := &stanza.IQ{
					ID:      iq.ID,
					To:      sess.JID().String(),
					Type:    stanza.IQSet,
					Payload: iq.Payload,
				}
				pushRaw, merr := pushIQ.Marshal()
				if merr == nil {
					_ = sess.Deliver(ctx, pushRaw)
				}
			}
		}
		result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
		return result.Marshal()
	}

	se := &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrFeatureNotImplemented}
	errBytes, _ := se.Marshal()
	errIQ := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQError, Payload: errBytes}
	return errIQ.Marshal()
}

func handleCarbonsIQ(s *Session, iq *stanza.IQ) ([]byte, error) {
	if iq.Type != stanza.IQSet {
		se := &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrFeatureNotImplemented}
		errBytes, _ := se.Marshal()
		errIQ := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQError, Payload: errBytes}
		return errIQ.Marshal()
	}
	local := firstChildLocal(iq.Payload)
	switch local {
	case "enable":
		s.cfg.Modules.Carbons.EnableForSession(s.jid)
	case "disable":
		s.cfg.Modules.Carbons.DisableForSession(s.jid)
	}
	result := &stanza.IQ{ID: iq.ID, From: iq.To, To: iq.From, Type: stanza.IQResult}
	return result.Marshal()
}

func parsePushEnable(payload []byte) (svcJID, node string, formXML []byte) {
	dec := xml.NewDecoder(bytes.NewReader(payload))
	depth := 0
	var formBuf bytes.Buffer
	formEnc := xml.NewEncoder(&formBuf)
	inForm := false
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "jid":
						svcJID = a.Value
					case "node":
						node = a.Value
					}
				}
			}
			if t.Name.Space == "jabber:x:data" || (t.Name.Local == "x" && depth == 2) {
				inForm = true
			}
			if inForm {
				formEnc.EncodeToken(t)
			}
		case xml.EndElement:
			if inForm {
				formEnc.EncodeToken(t)
			}
			depth--
			if depth == 1 {
				inForm = false
			}
		case xml.CharData:
			if inForm {
				formEnc.EncodeToken(t)
			}
		}
	}
	formEnc.Flush()
	if formBuf.Len() > 0 {
		formXML = formBuf.Bytes()
	}
	return
}

func firstChildNS(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Space
		}
	}
}

func firstChildLocal(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	dec := xml.NewDecoder(bytes.NewReader(payload))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local
		}
	}
}

func subscriptionName(sub int) string {
	switch sub {
	case 1:
		return "from"
	case 2:
		return "to"
	case 3:
		return "both"
	default:
		return "none"
	}
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func rewriteStanzaFrom(raw []byte, from string) []byte {
	end := bytes.IndexByte(raw, '>')
	if end <= 0 {
		return raw
	}

	head := raw[:end]
	tail := raw[end:]
	needle := []byte("from=")
	idx := bytes.Index(head, needle)
	if idx >= 0 {
		value := head[idx+len(needle):]
		if len(value) > 1 {
			q := value[0]
			closeIdx := bytes.IndexByte(value[1:], q)
			if closeIdx >= 0 {
				out := make([]byte, 0, len(raw)+len(from))
				out = append(out, head[:idx]...)
				out = append(out, []byte("from='"+xmlEscape(from)+"'")...)
				out = append(out, value[closeIdx+2:]...)
				out = append(out, tail...)
				return out
			}
		}
		return raw
	}

	out := make([]byte, 0, len(raw)+len(from)+8)
	out = append(out, head...)
	out = append(out, []byte(" from='"+xmlEscape(from)+"'")...)
	out = append(out, tail...)
	return out
}
