package pubsub

import (
	"bytes"
	"context"
	"encoding/xml"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

func iqError(iq *stanza.IQ, errType, condition string) ([]byte, error) {
	se := &stanza.StanzaError{Type: errType, Condition: condition}
	errBytes, err := se.Marshal()
	if err != nil {
		return nil, err
	}
	resp := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQError,
		Payload: errBytes,
	}
	return resp.Marshal()
}

func iqResult(iq *stanza.IQ, payload []byte) ([]byte, error) {
	resp := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQResult,
		Payload: payload,
	}
	return resp.Marshal()
}

func (svc *Service) HandleIQ(ctx context.Context, owner stanza.JID, iq *stanza.IQ) ([]byte, error) {
	if len(iq.Payload) == 0 {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	req, err := parseRequest(iq.Payload)
	if err != nil || req.op == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	switch req.op {
	case "publish":
		return svc.handlePublish(ctx, owner, iq, req.node, req.items)
	case "retract":
		return svc.handleRetract(ctx, owner, iq, req.node, req.itemID)
	case "items":
		return svc.handleItems(ctx, owner, iq, req.node, req.itemID, req.max)
	case "subscribe":
		return iqResult(iq, nil)
	case "unsubscribe":
		return iqResult(iq, nil)
	case "create":
		return svc.handleCreate(ctx, owner, iq, req.node)
	case "delete":
		return svc.handleDelete(ctx, owner, iq, req.node)
	default:
		return iqError(iq, stanza.ErrorTypeCancel, stanza.ErrFeatureNotImplemented)
	}
}

func (svc *Service) handlePublish(ctx context.Context, owner stanza.JID, iq *stanza.IQ, node string, items []rawItem) ([]byte, error) {
	if node == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	publisher := iq.From
	if publisher == "" {
		publisher = owner.String()
	}

	for _, it := range items {
		if svc.itemMaxBytes > 0 && int64(len(it.Payload)) > svc.itemMaxBytes {
			return iqError(iq, stanza.ErrorTypeModify, stanza.ErrPolicyViolation)
		}
		if svc.publishLimiter != nil && !svc.publishLimiter.AllowPublish(node, it.ID) {
			return iqError(iq, stanza.ErrorTypeWait, stanza.ErrPolicyViolation)
		}
		pepItem := &storage.PEPItem{
			Owner:       owner.Bare().String(),
			Node:        node,
			ItemID:      it.ID,
			Publisher:   publisher,
			PublishedAt: time.Now().UTC(),
			Payload:     it.Payload,
		}
		if err := svc.store.PutItem(ctx, pepItem); err != nil {
			return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
		}
		go svc.notify(ctx, owner, node, it.ID, it.Payload)
	}
	return iqResult(iq, nil)
}

func (svc *Service) handleRetract(ctx context.Context, owner stanza.JID, iq *stanza.IQ, node, itemID string) ([]byte, error) {
	if node == "" || itemID == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}
	if err := svc.store.DeleteItem(ctx, owner.Bare().String(), node, itemID); err != nil {
		return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
	}
	return iqResult(iq, nil)
}

func (svc *Service) handleItems(ctx context.Context, owner stanza.JID, iq *stanza.IQ, node, itemID string, max int) ([]byte, error) {
	if node == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	var (
		items []*storage.PEPItem
		err   error
	)
	if itemID != "" {
		var it *storage.PEPItem
		it, err = svc.store.GetItem(ctx, owner.Bare().String(), node, itemID)
		if err == nil {
			items = []*storage.PEPItem{it}
		}
	} else {
		items, err = svc.store.ListItems(ctx, owner.Bare().String(), node, max)
	}
	if err != nil {
		return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
	}

	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	psEl := xml.StartElement{
		Name: xml.Name{Space: nsPubSub, Local: "pubsub"},
	}
	itemsEl := xml.StartElement{
		Name: xml.Name{Space: nsPubSub, Local: "items"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "node"}, Value: node}},
	}
	enc.EncodeToken(psEl)
	enc.EncodeToken(itemsEl)

	for _, it := range items {
		itemEl := xml.StartElement{
			Name: xml.Name{Space: nsPubSub, Local: "item"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "id"}, Value: it.ItemID}},
		}
		enc.EncodeToken(itemEl)
		enc.Flush()
		if len(it.Payload) > 0 {
			buf.Write(it.Payload)
		}
		enc.EncodeToken(itemEl.End())
	}
	enc.EncodeToken(itemsEl.End())
	enc.EncodeToken(psEl.End())
	enc.Flush()

	return iqResult(iq, buf.Bytes())
}

func (svc *Service) handleCreate(ctx context.Context, owner stanza.JID, iq *stanza.IQ, node string) ([]byte, error) {
	if node == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}
	pepNode := &storage.PEPNode{
		Owner:       owner.Bare().String(),
		Node:        node,
		AccessModel: 0,
	}
	if err := svc.store.PutNode(ctx, pepNode); err != nil {
		return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
	}
	return iqResult(iq, nil)
}

func (svc *Service) handleDelete(ctx context.Context, owner stanza.JID, iq *stanza.IQ, node string) ([]byte, error) {
	if node == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}
	if err := svc.store.DeleteNode(ctx, owner.Bare().String(), node); err != nil {
		return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
	}
	return iqResult(iq, nil)
}

// EnsureNode creates the node if it doesn't exist yet.
func (svc *Service) EnsureNode(ctx context.Context, owner stanza.JID, node string) error {
	_, err := svc.store.GetNode(ctx, owner.Bare().String(), node)
	if err == nil {
		return nil
	}
	return svc.store.PutNode(ctx, &storage.PEPNode{
		Owner:       owner.Bare().String(),
		Node:        node,
		AccessModel: 0,
	})
}
