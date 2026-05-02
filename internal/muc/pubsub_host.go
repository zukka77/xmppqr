// Package muc — per-room pubsub host (Wave 5b).
//
// This file implements the MUC-specific authorisation hook and item-policy
// enforcement for the per-room pubsub host introduced in Wave 5a.
//
// Wire format for the X3DHPQ group membership journal node:
//
// Subscribe (room member):
//
//	<iq type='set' to='room@conference.example.org'>
//	  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
//	    <subscribe node='urn:xmppqr:x3dhpq:group:0'
//	               jid='alice@example.org/phone'/>
//	  </pubsub>
//	</iq>
//
// Publish (room owner only — the AIK signing the journal must be the owner):
//
//	<iq type='set' to='room@conference.example.org'>
//	  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
//	    <publish node='urn:xmppqr:x3dhpq:group:0'>
//	      <item id='entry-N'>
//	        <membership-entry xmlns='urn:xmppqr:x3dhpq:group:0'>
//	          BASE64-ENCODED-SIGNED-PAYLOAD
//	        </membership-entry>
//	      </item>
//	    </publish>
//	  </pubsub>
//	</iq>
//
// The server stores payloads opaquely; it never validates signatures.
// Items are capped at groupNodeItemMaxBytes (16 KiB) and at most
// groupNodeItemCap (200) items are retained — oldest are pruned on publish.
//
// Delivery via +notify (XEP-0163):
//
//	<message from='room@conference.example.org'
//	         to='alice@example.org/phone'>
//	  <event xmlns='http://jabber.org/protocol/pubsub#event'>
//	    <items node='urn:xmppqr:x3dhpq:group:0'>
//	      <item id='entry-N'>...</item>
//	    </items>
//	  </event>
//	</message>

package muc

import (
	"context"
	"fmt"

	"github.com/danielinux/xmppqr/internal/pubsub"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

const (
	// xepGroupNode is the PEP node that carries the X3DHPQ AIK membership
	// journal on a room JID per X3DHPQ XEP §13.8.
	xepGroupNode = "urn:xmppqr:x3dhpq:group:0"

	// groupNodeItemMaxBytes is the per-item byte cap for the group membership
	// journal node.  Matches DefaultAuditChainPolicy.ItemMaxBytes = 16 KiB.
	groupNodeItemMaxBytes = 16 * 1024

	// groupNodeItemCap is the maximum number of items retained on the group
	// membership journal node.  Older items are pruned on publish.
	// Matches DefaultAuditChainPolicy item count = 200.
	groupNodeItemCap = 200
)

// pubsubAuth implements pubsub.HostAuth for MUC rooms.
//
// Default policy:
//   - Publish: requester must hold affiliation >= AffAdmin.
//   - Subscribe: requester must hold affiliation >= AffMember, or the room is
//     open (not members-only) and public.
//
// For xepGroupNode the publish policy is tightened to AffOwner: the AIK
// signing the membership journal must hold room ownership.
type pubsubAuth struct {
	svc *Service
}

// AffiliationOf returns the affiliation level for userBare in this room.
// Returns AffNone if the room is nil or the user has no entry.
func (r *Room) AffiliationOf(userBare string) int {
	r.mu.RLock()
	aff := r.affiliations[userBare]
	r.mu.RUnlock()
	return aff
}

func (a *pubsubAuth) CanPublish(host stanza.JID, node string, requester stanza.JID) bool {
	room := a.svc.getRoom(host)
	if room == nil {
		return false
	}
	aff := room.AffiliationOf(requester.Bare().String())
	// The group membership journal must be published by the room owner only.
	// All other nodes allow admin-level publish.
	switch node {
	case xepGroupNode:
		return aff >= AffOwner
	default:
		return aff >= AffAdmin
	}
}

func (a *pubsubAuth) CanSubscribe(host stanza.JID, _ string, requester stanza.JID) bool {
	room := a.svc.getRoom(host)
	if room == nil {
		return false
	}
	room.mu.RLock()
	aff := room.affiliations[requester.Bare().String()]
	membersOnly := room.config.MembersOnly
	public := room.config.Public
	room.mu.RUnlock()

	if aff >= AffMember {
		return true
	}
	// Open (not members-only) and public room: anyone may subscribe.
	return !membersOnly && public
}

// enforceGroupNodePublish enforces the X3DHPQ group membership journal policy
// for a publish IQ targeting xepGroupNode.  It must be called before delegating
// to pubsubHost.HandleIQ.
//
// Policy:
//   - Reject items larger than groupNodeItemMaxBytes with <not-acceptable/>.
//   - Prune oldest items so at most groupNodeItemCap-1 remain before the new
//     item lands, keeping the total at or below groupNodeItemCap.
//
// Returns a non-nil error string if the publish should be rejected.  On prune
// errors the publish is still allowed through (best-effort cap).
func enforceGroupNodePublish(ctx context.Context, host stanza.JID, rawPayload []byte, store interface {
	ListItems(ctx context.Context, owner, node string, limit int) ([]*storage.PEPItem, error)
	DeleteItem(ctx context.Context, owner, node, itemID string) error
}) error {
	// Conservatively treat the whole IQ payload as the upper-bound item size
	// for the purpose of the byte cap check.  The per-item payload is always
	// smaller, so this is safe — it only rejects obviously too-large publishes.
	if len(rawPayload) > groupNodeItemMaxBytes {
		return fmt.Errorf("not-acceptable")
	}

	// Prune: list all existing items (oldest-first) and delete the excess so
	// there is room for the incoming item within the cap.
	items, err := store.ListItems(ctx, host.Bare().String(), xepGroupNode, 0)
	if err != nil {
		// Non-fatal: allow the publish through; storage will grow past the cap
		// but the next publish will clean it up.
		return nil
	}
	if len(items) >= groupNodeItemCap {
		excess := len(items) - groupNodeItemCap + 1
		for i := 0; i < excess; i++ {
			_ = store.DeleteItem(ctx, host.Bare().String(), xepGroupNode, items[i].ItemID)
		}
	}
	return nil
}

// newPubsubHostService wraps a pubsub.Service with MUC-specific auth for this
// Service.
func newPubsubHostService(ps *pubsub.Service, svc *Service) *pubsub.HostService {
	return pubsub.NewHostService(ps, &pubsubAuth{svc: svc})
}
