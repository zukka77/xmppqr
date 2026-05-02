package pubsub

import (
	"context"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

// HostAuth is a pluggable authorisation hook for a per-JID pubsub host.
// Callers (e.g. the MUC service) supply their own implementation.
type HostAuth interface {
	// CanPublish returns true when requester is allowed to publish to (host, node).
	CanPublish(host stanza.JID, node string, requester stanza.JID) bool
	// CanSubscribe returns true when requester is allowed to subscribe to (host, node).
	CanSubscribe(host stanza.JID, node string, requester stanza.JID) bool
}

// HostService wraps the core pubsub Service so it can serve pubsub IQs
// on behalf of any bare JID, not just user accounts.  Authorisation is
// delegated to the supplied HostAuth hook.
type HostService struct {
	inner *Service
	auth  HostAuth
}

// NewHostService constructs a HostService backed by inner and authorised by auth.
func NewHostService(inner *Service, auth HostAuth) *HostService {
	return &HostService{inner: inner, auth: auth}
}

// HandleIQ dispatches a pubsub or pubsub#owner IQ that targets host on behalf
// of requester.  It enforces HostAuth before delegating to inner.
func (h *HostService) HandleIQ(ctx context.Context, host stanza.JID, requester stanza.JID, iq *stanza.IQ) ([]byte, error) {
	if len(iq.Payload) == 0 {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	req, err := parseRequest(iq.Payload)
	if err != nil || req.op == "" {
		return iqError(iq, stanza.ErrorTypeModify, stanza.ErrBadRequest)
	}

	switch req.op {
	case "publish":
		if !h.auth.CanPublish(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		// Ensure the node exists before publishing (mirrors PEP auto-create).
		if err := h.inner.EnsureNode(ctx, host, req.node); err != nil {
			return iqError(iq, stanza.ErrorTypeWait, stanza.ErrInternalServerError)
		}
		return h.inner.handlePublish(ctx, host, iq, req.node, req.items)

	case "subscribe":
		if !h.auth.CanSubscribe(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		// Record the subscription so last-item replay and drop-on-evict work.
		subscriberBare := requester.Bare().String()
		_ = h.inner.store.PutSubscription(ctx, &storage.PEPSubscription{
			Owner:      host.Bare().String(),
			Node:       req.node,
			Subscriber: subscriberBare,
		})
		// Replay the most-recent item to the new subscriber.
		h.inner.replayLastItem(ctx, host, req.node, requester)
		return iqResult(iq, nil)

	case "unsubscribe":
		subscriberBare := requester.Bare().String()
		_ = h.inner.store.DeleteSubscription(ctx, host.Bare().String(), req.node, subscriberBare)
		return iqResult(iq, nil)

	case "retract":
		if !h.auth.CanPublish(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		return h.inner.handleRetract(ctx, host, iq, req.node, req.itemID)

	case "items":
		// Subscribed members or anyone (open room) may fetch items; CanSubscribe
		// doubles as the read-access check.
		if !h.auth.CanSubscribe(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		return h.inner.handleItems(ctx, host, iq, req.node, req.itemID, req.max)

	case "create":
		if !h.auth.CanPublish(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		return h.inner.handleCreate(ctx, host, iq, req.node)

	case "delete":
		if !h.auth.CanPublish(host, req.node, requester) {
			return iqError(iq, stanza.ErrorTypeAuth, stanza.ErrForbidden)
		}
		return h.inner.handleDelete(ctx, host, iq, req.node)

	default:
		return iqError(iq, stanza.ErrorTypeCancel, stanza.ErrFeatureNotImplemented)
	}
}

// DropSubscriptionsForUser removes all subscriptions that subscriber holds
// under owner.  Called when a room evicts a member so they stop receiving
// pubsub notifications from that room's nodes.
func (h *HostService) DropSubscriptionsForUser(ctx context.Context, owner stanza.JID, subscriberBare string) error {
	return h.inner.store.DeleteSubscriptionsForSubscriber(ctx, owner.Bare().String(), subscriberBare)
}

// Store returns the underlying PEPStore so callers (e.g. the MUC pubsub auth)
// can perform item-cap enforcement without reaching through private fields.
func (h *HostService) Store() storage.PEPStore {
	return h.inner.store
}

// DeleteAllNodesForOwner deletes every PEP node (and its items) owned by
// owner.  Called when a MUC room is destroyed so its pubsub nodes do not
// linger in storage.
func (h *HostService) DeleteAllNodesForOwner(ctx context.Context, owner stanza.JID) error {
	return h.inner.store.DeleteNodesForOwner(ctx, owner.Bare().String())
}
