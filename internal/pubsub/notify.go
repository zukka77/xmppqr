package pubsub

import (
	"bytes"
	"context"
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
)

const nsPubSubEvent = "http://jabber.org/protocol/pubsub#event"

func (svc *Service) notify(ctx context.Context, owner stanza.JID, node, itemID string, payload []byte) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	eventEl := xml.StartElement{Name: xml.Name{Space: nsPubSubEvent, Local: "event"}}
	itemsEl := xml.StartElement{
		Name: xml.Name{Local: "items"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	itemEl := xml.StartElement{
		Name: xml.Name{Local: "item"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: itemID}},
	}

	enc.EncodeToken(eventEl)
	enc.EncodeToken(itemsEl)
	enc.EncodeToken(itemEl)
	enc.Flush()
	if len(payload) > 0 {
		buf.Write(payload)
	}
	enc.EncodeToken(itemEl.End())
	enc.EncodeToken(itemsEl.End())
	enc.EncodeToken(eventEl.End())
	enc.Flush()

	msg := &stanza.Message{
		From:     owner.String(),
		To:       owner.Bare().String(),
		Type:     stanza.MessageHeadline,
		Children: buf.Bytes(),
	}
	raw, err := msg.Marshal()
	if err != nil {
		svc.logger.Error("pubsub notify marshal", "err", err)
		return
	}

	if _, err := svc.router.RouteToBare(ctx, owner.Bare(), raw); err != nil {
		svc.logger.Debug("pubsub notify route", "owner", owner, "err", err)
	}

	if !svc.contactNotifyEnabled() {
		return
	}

	roster, _, err := svc.roster.Get(ctx, owner.Bare().String())
	if err != nil {
		svc.logger.Debug("pubsub notify roster get", "owner", owner, "err", err)
		return
	}

	notifyFeature := node + "+notify"
	for _, item := range roster {
		if item.Subscription != 1 && item.Subscription != 3 {
			continue
		}
		contactBare, err := stanza.Parse(item.Contact)
		if err != nil {
			continue
		}
		for _, fullJID := range svc.caps.BareJIDsWithFeatureMatching(contactBare, notifyFeature) {
			contactMsg := &stanza.Message{
				From:     owner.String(),
				To:       fullJID.String(),
				Type:     stanza.MessageHeadline,
				Children: buf.Bytes(),
			}
			contactRaw, merr := contactMsg.Marshal()
			if merr != nil {
				continue
			}
			if rerr := svc.router.RouteToFull(ctx, fullJID, contactRaw); rerr != nil {
				svc.logger.Debug("pubsub notify contact route", "contact", fullJID, "err", rerr)
			}
		}
	}
}
