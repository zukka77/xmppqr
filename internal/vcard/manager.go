// Package vcard implements XEP-0054 vCard-temp storage and IQ dispatch.
package vcard

import (
	"context"
	"encoding/xml"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

const (
	nsVCard  = "vcard-temp"
	pepNode  = "vcard-temp"
	itemID   = "current"
)

type Manager struct {
	pep storage.PEPStore
}

func New(pep storage.PEPStore) *Manager {
	return &Manager{pep: pep}
}

func (m *Manager) Get(ctx context.Context, owner string) ([]byte, error) {
	item, err := m.pep.GetItem(ctx, owner, pepNode, itemID)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return item.Payload, nil
}

func (m *Manager) Set(ctx context.Context, owner string, vcardXML []byte) error {
	return m.pep.PutItem(ctx, &storage.PEPItem{
		Owner:   owner,
		Node:    pepNode,
		ItemID:  itemID,
		Payload: vcardXML,
	})
}

func (m *Manager) HandleIQ(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	switch iq.Type {
	case stanza.IQGet:
		return m.handleGet(ctx, iq)
	case stanza.IQSet:
		return m.handleSet(ctx, iq)
	default:
		return errorXML(stanza.ErrorTypeCancel, stanza.ErrBadRequest, "")
	}
}

func (m *Manager) handleGet(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	owner := iq.From
	data, err := m.Get(ctx, owner)
	if err != nil {
		return errorXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
	}
	if data == nil {
		return []byte(`<vCard xmlns='vcard-temp'/>`), nil
	}
	return data, nil
}

func (m *Manager) handleSet(ctx context.Context, iq *stanza.IQ) ([]byte, error) {
	if len(iq.Payload) == 0 {
		return errorXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "empty payload")
	}

	var check struct {
		XMLName xml.Name `xml:"vCard"`
	}
	if err := xml.Unmarshal(iq.Payload, &check); err != nil {
		return errorXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "malformed vCard")
	}
	if check.XMLName.Space != nsVCard {
		return errorXML(stanza.ErrorTypeModify, stanza.ErrBadRequest, "wrong namespace")
	}

	if err := m.Set(ctx, iq.From, iq.Payload); err != nil {
		return errorXML(stanza.ErrorTypeWait, stanza.ErrInternalServerError, "")
	}
	return nil, nil
}

func errorXML(errType, condition, text string) ([]byte, error) {
	e := &stanza.StanzaError{Type: errType, Condition: condition, Text: text}
	return e.Marshal()
}
