// Package block implements XEP-0191 blocking command.
package block

import (
	"bytes"
	"context"
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

type Manager struct {
	store storage.BlockStore
}

func New(store storage.BlockStore) *Manager {
	return &Manager{store: store}
}

func (m *Manager) IsBlocked(ctx context.Context, owner string, peer stanza.JID) (bool, error) {
	bare := peer.Bare().String()
	list, err := m.store.List(ctx, owner)
	if err != nil {
		return false, err
	}
	for _, jid := range list {
		if jid == bare {
			return true, nil
		}
	}
	return false, nil
}

func (m *Manager) List(ctx context.Context, owner string) ([]string, error) {
	return m.store.List(ctx, owner)
}

func (m *Manager) HandleIQ(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	switch iq.Type {
	case stanza.IQGet:
		return m.handleGet(ctx, iq)
	case stanza.IQSet:
		return m.handleSet(ctx, iq)
	default:
		return errXML(stanza.ErrorTypeCancel, stanza.ErrBadRequest, "")
	}
}

func (m *Manager) BroadcastUpdate(_ context.Context, _ string, _ []byte) {}

func (m *Manager) handleGet(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	list, err := m.store.List(ctx, iq.From)
	if err != nil {
		return errXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
	}

	type item struct {
		JID string `xml:"jid,attr"`
	}
	type blocklist struct {
		XMLName xml.Name `xml:"blocklist"`
		NS      string   `xml:"xmlns,attr"`
		Items   []item   `xml:"item"`
	}
	bl := blocklist{NS: "urn:xmpp:blocking"}
	for _, j := range list {
		bl.Items = append(bl.Items, item{JID: j})
	}
	b, err := xml.Marshal(bl)
	if err != nil {
		return errXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
	}
	return b, nil
}

type blockItem struct {
	JID string `xml:"jid,attr"`
}

type blockCmd struct {
	XMLName xml.Name    `xml:"block"`
	Items   []blockItem `xml:"item"`
}

type unblockCmd struct {
	XMLName xml.Name    `xml:"unblock"`
	Items   []blockItem `xml:"item"`
}

func (m *Manager) handleSet(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	if len(iq.Payload) == 0 {
		return errXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "")
	}

	// Determine whether it's block or unblock by peeking at the root element name.
	var root xml.Name
	dec := xml.NewDecoder(bytes.NewReader(iq.Payload))
	tok, err := dec.Token()
	if err != nil {
		return errXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "")
	}
	if se, ok := tok.(xml.StartElement); ok {
		root = se.Name
	}

	switch root.Local {
	case "block":
		var cmd blockCmd
		if err := xml.Unmarshal(iq.Payload, &cmd); err != nil {
			return errXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "")
		}
		for _, it := range cmd.Items {
			if err := m.store.Add(ctx, iq.From, it.JID); err != nil {
				return errXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
			}
		}
	case "unblock":
		var cmd unblockCmd
		if err := xml.Unmarshal(iq.Payload, &cmd); err != nil {
			return errXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "")
		}
		if len(cmd.Items) == 0 {
			if err := m.store.Clear(ctx, iq.From); err != nil {
				return errXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
			}
		} else {
			for _, it := range cmd.Items {
				if err := m.store.Remove(ctx, iq.From, it.JID); err != nil {
					return errXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
				}
			}
		}
	default:
		return errXML(stanza.ErrorTypeCancel, stanza.ErrBadRequest, "unknown command")
	}
	return nil, nil
}

func errXML(errType, condition, text string) ([]byte, error) {
	e := &stanza.StanzaError{Type: errType, Condition: condition, Text: text}
	return e.Marshal()
}
