package push

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

const pushNS = "urn:xmpp:push:0"

type Payload struct {
	MessageCount int
	LastFromJID  string
	LastBody     string
}

type Dispatcher struct {
	store       storage.PushStore
	router      *router.Router
	providers   map[string]Provider
	logger      *slog.Logger
	rateLimiter *rateLimiter
	localDomain string
}

func New(store storage.PushStore, r *router.Router, localDomain string, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		store:        store,
		router:       r,
		providers:    make(map[string]Provider),
		logger:       logger,
		rateLimiter:  newRateLimiter(60, defaultBurst),
		localDomain:  localDomain,
	}
}

func (d *Dispatcher) RegisterProvider(name string, p Provider) {
	d.providers[name] = p
}

func (d *Dispatcher) Enable(ctx context.Context, owner stanza.JID, serviceJID stanza.JID, node string, form []byte) error {
	reg := &storage.PushRegistration{
		Owner:      owner.Bare().String(),
		ServiceJID: serviceJID.String(),
		Node:       node,
		FormXML:    form,
		EnabledAt:  time.Now(),
	}
	return d.store.Put(ctx, reg)
}

func (d *Dispatcher) Disable(ctx context.Context, owner stanza.JID, serviceJID stanza.JID, node string) error {
	return d.store.Delete(ctx, owner.Bare().String(), serviceJID.String(), node)
}

func (d *Dispatcher) Notify(ctx context.Context, owner stanza.JID, hint Payload) {
	regs, err := d.store.List(ctx, owner.Bare().String())
	if err != nil {
		d.logger.Error("push: list registrations", "err", err)
		return
	}

	for _, reg := range regs {
		p := hint
		if suppressBody(reg.FormXML) {
			p.LastBody = ""
		}

		deviceKey := reg.ServiceJID + "\x00" + reg.Node
		if !d.rateLimiter.Allow(deviceKey) {
			d.logger.Debug("push: rate limited", "owner", owner.String(), "service", reg.ServiceJID)
			continue
		}

		svcJID, err := stanza.Parse(reg.ServiceJID)
		if err != nil {
			d.logger.Error("push: bad serviceJID", "jid", reg.ServiceJID, "err", err)
			continue
		}

		if svcJID.Domain == d.localDomain {
			provider, ok := d.providers[svcJID.Domain]
			if !ok {
				provider, ok = d.providers[svcJID.Local]
			}
			if ok {
				if _, err := provider.Send(ctx, reg, p); err != nil {
					d.logger.Error("push: provider send", "provider", provider.Name(), "err", err)
				}
				continue
			}
		}

		raw, err := buildNotificationStanza(reg, p, owner)
		if err != nil {
			d.logger.Error("push: build stanza", "err", err)
			continue
		}

		if _, err := d.router.RouteToBare(ctx, svcJID, raw); err != nil {
			d.logger.Debug("push: route notification", "service", reg.ServiceJID, "err", err)
		}
	}
}

func suppressBody(formXML []byte) bool {
	if len(formXML) == 0 {
		return false
	}
	dec := xml.NewDecoder(bytes.NewReader(formXML))
	var inIncludeBody bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "field" {
				for _, a := range t.Attr {
					if a.Name.Local == "var" && a.Value == "include-body" {
						inIncludeBody = true
					}
				}
			}
			if t.Name.Local == "value" && inIncludeBody {
				var v string
				if err := dec.DecodeElement(&v, &t); err == nil {
					return v == "false" || v == "0"
				}
			}
		case xml.EndElement:
			if t.Name.Local == "field" {
				inIncludeBody = false
			}
		}
	}
	return false
}

func buildNotificationStanza(reg *storage.PushRegistration, p Payload, owner stanza.JID) ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	msgStart := xml.StartElement{
		Name: xml.Name{Local: "message"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "to"}, Value: reg.ServiceJID},
		},
	}
	enc.EncodeToken(msgStart)

	notifStart := xml.StartElement{
		Name: xml.Name{Local: "notification", Space: pushNS},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: pushNS},
			{Name: xml.Name{Local: "id"}, Value: reg.Node},
		},
	}
	enc.EncodeToken(notifStart)

	if p.MessageCount > 0 || p.LastFromJID != "" {
		xStart := xml.StartElement{Name: xml.Name{Local: "x"}}
		enc.EncodeToken(xStart)

		if p.MessageCount > 0 {
			enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "count"}})
			enc.EncodeToken(xml.CharData(fmt.Sprintf("%d", p.MessageCount)))
			enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "count"}})
		}
		if p.LastFromJID != "" {
			enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "last-from"}})
			enc.EncodeToken(xml.CharData(p.LastFromJID))
			enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "last-from"}})
		}
		if p.LastBody != "" {
			enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: "body"}})
			enc.EncodeToken(xml.CharData(p.LastBody))
			enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: "body"}})
		}

		enc.EncodeToken(xStart.End())
	}

	enc.EncodeToken(notifStart.End())
	enc.EncodeToken(msgStart.End())

	if err := enc.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

