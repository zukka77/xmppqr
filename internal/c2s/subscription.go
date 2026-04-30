package c2s

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"

	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/stanza"
)

func (s *Session) sendRosterPush(ctx context.Context, item *storage.RosterItem) {
	if s.cfg.Router == nil || item == nil {
		return
	}
	sub := subscriptionName(item.Subscription)
	askAttr := ""
	if item.Ask == 1 {
		askAttr = ` ask='subscribe'`
	}
	itemXML := fmt.Sprintf(`<item jid='%s' subscription='%s'%s/>`,
		xmlEscape(item.Contact), sub, askAttr)
	pushID := fmt.Sprintf("push-%s", xmlEscape(item.Contact))
	pushXML := fmt.Sprintf(
		`<iq type='set' id='%s'><query xmlns='jabber:iq:roster' ver='%d'>%s</query></iq>`,
		pushID, item.Ver, itemXML,
	)
	ownerBare := s.jid.Bare().String()
	for _, sess := range s.cfg.Router.SessionsFor(ownerBare) {
		_ = sess.Deliver(ctx, []byte(pushXML))
	}
}

func (s *Session) currentAvailablePresence() []byte {
	if s.cfg.Router == nil {
		return nil
	}
	ownerBare := s.jid.Bare().String()
	for _, sess := range s.cfg.Router.SessionsFor(ownerBare) {
		if sess.IsAvailable() {
			p := &stanza.Presence{From: sess.JID().String()}
			raw, err := p.Marshal()
			if err == nil {
				return raw
			}
		}
	}
	return nil
}

func (s *Session) unavailablePresenceStanzas() [][]byte {
	if s.cfg.Router == nil {
		return nil
	}
	ownerBare := s.jid.Bare().String()
	var out [][]byte
	for _, sess := range s.cfg.Router.SessionsFor(ownerBare) {
		p := &stanza.Presence{From: sess.JID().String(), Type: stanza.PresenceUnavailable}
		raw, err := p.Marshal()
		if err == nil {
			out = append(out, raw)
		}
	}
	return out
}

// handleInboundSubscription processes an inbound subscription-type presence stanza
// delivered to this session (Goal 2). Returns true if the stanza was fully handled
// server-side and should NOT be forwarded to the client.
func (s *Session) handleInboundSubscription(ctx context.Context, raw []byte, mods *Modules) bool {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	se, ok := tok.(xml.StartElement)
	if !ok || se.Name.Local != "presence" {
		return false
	}
	presType := ""
	fromStr := ""
	for _, a := range se.Attr {
		switch a.Name.Local {
		case "type":
			presType = a.Value
		case "from":
			fromStr = a.Value
		}
	}
	if fromStr == "" {
		return false
	}
	fromJID, err := stanza.Parse(fromStr)
	if err != nil {
		return false
	}
	ownerBare := s.jid.Bare().String()

	switch presType {
	case stanza.PresenceSubscribe:
		existing, _ := mods.Roster.GetItem(ctx, ownerBare, fromJID.Bare())
		if existing != nil && (existing.Subscription == 1 || existing.Subscription == 3) {
			// auto-approve: contact is already subscribed from/both
			reply := &stanza.Presence{
				From: ownerBare,
				To:   fromJID.Bare().String(),
				Type: stanza.PresenceSubscribed,
			}
			replyRaw, rerr := reply.Marshal()
			if rerr == nil && s.cfg.Router != nil {
				_, _ = s.cfg.Router.RouteToBare(ctx, fromJID.Bare(), replyRaw)
			}
			return true
		}
		return false

	case stanza.PresenceSubscribed:
		item, _ := mods.Roster.InboundSubscribed(ctx, ownerBare, fromJID.Bare())
		s.sendRosterPush(ctx, item)
		return true

	case stanza.PresenceUnsubscribed:
		item, _ := mods.Roster.InboundUnsubscribed(ctx, ownerBare, fromJID.Bare())
		s.sendRosterPush(ctx, item)
		return true
	}
	return false
}
