package muc

import (
	"bytes"
	"context"
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func (s *Service) HandleStanza(ctx context.Context, raw []byte, kind string, from stanza.JID, to stanza.JID) error {
	switch kind {
	case "presence":
		return s.handlePresence(ctx, raw, from, to)
	case "message":
		return s.handleMessage(ctx, raw, from, to)
	case "iq":
		dec := xml.NewDecoder(bytes.NewReader(raw))
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			return nil
		}
		iq, err := stanza.ParseIQ(se, raw)
		if err != nil {
			return err
		}
		resp, err := s.HandleIQ(ctx, iq)
		if err != nil {
			return err
		}
		if resp != nil {
			_ = s.router.RouteToFull(ctx, from, resp)
		}
		return nil
	}
	return nil
}

func (s *Service) handlePresence(ctx context.Context, raw []byte, from stanza.JID, to stanza.JID) error {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	se, ok := tok.(xml.StartElement)
	if !ok {
		return nil
	}
	p, err := stanza.ParsePresence(se, raw)
	if err != nil {
		return err
	}

	if p.Type == stanza.PresenceUnavailable {
		room := s.getRoom(to)
		if room == nil {
			return nil
		}
		return room.Leave(ctx, from, s.router)
	}

	if p.Type != "" {
		return nil
	}

	nick := to.Resource
	if nick == "" {
		return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}

	var password string
	if len(p.Children) > 0 {
		if je, found := parseJoinElement(p.Children); found {
			password = je.Password
		}
	}

	room, created := s.getOrCreateRoom(ctx, to, from)

	occ := &Occupant{
		Nick:           nick,
		FullJID:        from,
		AIKFingerprint: parseAIKExtension(raw),
	}
	return room.Join(ctx, occ, password, s.router, s.store, created)
}

func (s *Service) handleMessage(ctx context.Context, raw []byte, from stanza.JID, to stanza.JID) error {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	se, ok := tok.(xml.StartElement)
	if !ok {
		return nil
	}
	m, err := stanza.ParseMessage(se, raw)
	if err != nil {
		return err
	}

	if m.Type != stanza.MessageGroupchat {
		return nil
	}

	room := s.getRoom(to)
	if room == nil {
		return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrItemNotFound}
	}

	if m.Subject != "" {
		nick := ""
		room.mu.RLock()
		for _, occ := range room.occupants {
			if occ.FullJID.Equal(from) {
				nick = occ.Nick
				break
			}
		}
		room.mu.RUnlock()
		if nick == "" {
			return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrForbidden}
		}
		return room.ChangeSubject(ctx, nick, m.Subject, s.router)
	}

	return room.BroadcastMessage(ctx, from, raw, s.router)
}

func (s *Service) HandleIQ(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	to, err := stanza.Parse(iq.To)
	if err != nil {
		return marshalErrorIQ(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest), nil
	}

	if iq.Type == stanza.IQGet && to.Resource == "" && to.Local == "" && isDiscoInfoIQ(iq.Payload) {
		payload := []byte(`<query xmlns='http://jabber.org/protocol/disco#info'>` +
			`<identity category='conference' type='text' name='MUC'/>` +
			`<feature var='http://jabber.org/protocol/muc'/>` +
			`<feature var='http://jabber.org/protocol/disco#info'/>` +
			`<feature var='http://jabber.org/protocol/disco#items'/>` +
			`</query>`)
		return marshalResultIQ(iq, payload), nil
	}

	if iq.Type == stanza.IQGet && to.Local != "" && to.Resource == "" && isDiscoInfoIQ(iq.Payload) {
		room := s.getRoom(to)
		if room == nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrItemNotFound), nil
		}
		return marshalResultIQ(iq, buildRoomDiscoInfo(room)), nil
	}

	if iq.Type == stanza.IQGet && to.Local == "" && to.Resource == "" && isDiscoItemsIQ(iq.Payload) {
		return marshalResultIQ(iq, buildConferenceDiscoItems(s.listPublicRooms())), nil
	}

	if iq.Type == stanza.IQGet && to.Local != "" && to.Resource == "" && isDiscoItemsIQ(iq.Payload) {
		room := s.getRoom(to)
		if room == nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrItemNotFound), nil
		}
		return marshalResultIQ(iq, buildRoomDiscoItems(room)), nil
	}

	if to.Local != "" && to.Resource == "" && isMUCOwnerIQ(iq.Payload) {
		from, ferr := stanza.Parse(iq.From)
		if ferr != nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest), nil
		}
		room := s.getRoom(to)
		if room == nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrItemNotFound), nil
		}
		if !room.IsOwner(from) {
			return marshalErrorIQ(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden), nil
		}

		switch iq.Type {
		case stanza.IQGet:
			return marshalResultIQ(iq, buildOwnerConfigForm(room)), nil
		case stanza.IQSet:
			form, ok := parseMUCOwnerSubmit(iq.Payload)
			if !ok || form == nil {
				return marshalErrorIQ(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest), nil
			}
			if form.Type == "cancel" {
				return marshalResultIQ(iq, nil), nil
			}
			room.ApplyOwnerForm(form.Fields)
			if err := s.persistRoom(ctx, room); err != nil {
				s.logger.Warn("muc: persist room failed", "jid", room.JID().String(), "err", err)
			}
			return marshalResultIQ(iq, nil), nil
		default:
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrFeatureNotImplemented), nil
		}
	}

	if iq.Type == stanza.IQGet && to.Resource != "" && isSelfPingIQ(iq.Payload) {
		room := s.getRoom(to)
		from, ferr := stanza.Parse(iq.From)
		if ferr != nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest), nil
		}
		if room == nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrItemNotFound), nil
		}
		if perr := room.SelfPing(ctx, from, s.router); perr != nil {
			return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrNotAcceptable), nil
		}
		return marshalResultIQ(iq, nil), nil
	}

	return marshalErrorIQ(iq, stanza.ErrorTypeCancel, stanza.ErrFeatureNotImplemented), nil
}
