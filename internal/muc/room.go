package muc

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/mam"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

const (
	AffNone    = 0
	AffOutcast = 1
	AffMember  = 2
	AffAdmin   = 3
	AffOwner   = 4

	RoleNone      = 0
	RoleVisitor   = 1
	RoleParticipant = 2
	RoleModerator = 3

	AnonymityOpen    = 0
	AnonymitySemi    = 1
	AnonymityNonAnon = 2
)

var ErrNotAcceptable = errors.New("not-acceptable")

type RoomConfig struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	PasswordProtected bool     `json:"password_protected"`
	Password          string   `json:"password"`
	MembersOnly       bool     `json:"members_only"`
	Moderated         bool     `json:"moderated"`
	PersistRoom       bool     `json:"persist_room"`
	Public            bool     `json:"public"`
	AnonymityMode     int      `json:"anonymity_mode"`
	HistoryMax        int      `json:"history_max"`
	AIKMembers        []string `json:"aik_members,omitempty"`
}

type Occupant struct {
	Nick           string
	FullJID        stanza.JID
	Role           int
	Affiliation    int
	AIKFingerprint string
}

type ArchivedMessage struct {
	TS       time.Time
	FromNick string
	XML      []byte
}

type Room struct {
	jid              stanza.JID
	config           RoomConfig
	mu               sync.RWMutex
	occupants        map[string]*Occupant
	affiliations     map[string]int
	subject          string
	subjectChangedBy string
	subjectTS        time.Time
	history          []*ArchivedMessage
	persistent       bool
	store            storage.MUCStore
	// mam is optional; when set, BroadcastMessage archives into MAM.
	mam              *mam.Service
}

func newRoom(j stanza.JID, cfg RoomConfig, persistent bool, store storage.MUCStore, mamSvc *mam.Service) *Room {
	return &Room{
		jid:          j,
		config:       cfg,
		occupants:    make(map[string]*Occupant),
		affiliations: make(map[string]int),
		persistent:   persistent,
		store:        store,
		mam:          mamSvc,
	}
}

func roomFromStorage(r *storage.MUCRoom, store storage.MUCStore, mamSvc *mam.Service) (*Room, error) {
	j, err := stanza.Parse(r.JID)
	if err != nil {
		return nil, err
	}
	var cfg RoomConfig
	if len(r.Config) > 0 {
		if err2 := json.Unmarshal(r.Config, &cfg); err2 != nil {
			return nil, err2
		}
	}
	room := newRoom(j, cfg, r.Persistent, store, mamSvc)
	return room, nil
}

func (r *Room) JID() stanza.JID { return r.jid }

func (r *Room) Join(ctx context.Context, occ *Occupant, password string, rtr *router.Router, store storage.MUCStore, roomCreated bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.config.PasswordProtected && r.config.Password != password {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrNotAuthorized}
	}

	bareJID := occ.FullJID.Bare().String()
	aff, ok := r.affiliations[bareJID]
	if !ok {
		aff = AffNone
	}
	occ.Affiliation = aff

	// Outcasts are banned regardless of members-only setting (XEP-0045 §10.2).
	if aff == AffOutcast {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	if r.config.MembersOnly && aff < AffMember {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	// Preload stored history when the room has no in-memory history yet.
	r.preloadFromStoreIfEmpty(ctx)

	if existing, clash := r.occupants[occ.Nick]; clash {
		switch {
		case existing.FullJID.Equal(occ.FullJID):
			// Same session re-sending presence; idempotent.
		case existing.FullJID.Bare().Equal(occ.FullJID.Bare()):
			// Same user, different resource. The old session is presumed
			// gone (an ungraceful disconnect leaves the occupant entry
			// stranded because no <presence type='unavailable'/> ever
			// arrived). Take over the entry rather than returning
			// <conflict/>, which would lock the user out of the room
			// for the lifetime of the stale entry.
			delete(r.occupants, occ.Nick)
		default:
			return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrConflict}
		}
	}

	if r.config.Moderated {
		if aff >= AffAdmin {
			occ.Role = RoleModerator
		} else if aff >= AffMember {
			occ.Role = RoleParticipant
		} else {
			occ.Role = RoleVisitor
		}
	} else {
		if aff >= AffAdmin {
			occ.Role = RoleModerator
		} else {
			occ.Role = RoleParticipant
		}
	}

	nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: occ.Nick}

	for _, existing := range r.occupants {
		presXML := buildOccupantPresence(nickJID.String(), existing.FullJID.String(), occ.Role, occ.Affiliation, false, occ.AIKFingerprint)
		_ = rtr.RouteToFull(ctx, existing.FullJID, presXML)
	}

	for _, existing := range r.occupants {
		existNickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: existing.Nick}
		presXML := buildOccupantPresence(existNickJID.String(), occ.FullJID.String(), existing.Role, existing.Affiliation, false, existing.AIKFingerprint)
		_ = rtr.RouteToFull(ctx, occ.FullJID, presXML)
	}

	selfPresXML := buildSelfPresence(nickJID.String(), occ.FullJID.String(), occ.Role, occ.Affiliation, roomCreated)
	if err := rtr.RouteToFull(ctx, occ.FullJID, selfPresXML); err != nil {
		return err
	}

	r.occupants[occ.Nick] = occ
	r.recomputeAIKMembers()

	histMax := r.config.HistoryMax
	if histMax == 0 {
		histMax = 20
	}
	start := 0
	if len(r.history) > histMax {
		start = len(r.history) - histMax
	}
	for _, msg := range r.history[start:] {
		_ = rtr.RouteToFull(ctx, occ.FullJID, msg.XML)
	}

	subjFrom := r.jid
	if r.subjectChangedBy != "" {
		subjFrom = stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: r.subjectChangedBy}
	}
	subjMsg := buildSubjectMessage(subjFrom.String(), occ.FullJID.String(), r.subject)
	_ = rtr.RouteToFull(ctx, occ.FullJID, subjMsg)

	if r.persistent && store != nil {
		_ = store.PutAffiliation(ctx, &storage.MUCAffiliation{
			RoomJID:     r.jid.String(),
			UserJID:     bareJID,
			Affiliation: aff,
		})
	}

	return nil
}

func (r *Room) Leave(ctx context.Context, fullJID stanza.JID, rtr *router.Router) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var leaver *Occupant
	for _, occ := range r.occupants {
		if occ.FullJID.Equal(fullJID) {
			leaver = occ
			break
		}
	}
	if leaver == nil {
		return nil
	}

	delete(r.occupants, leaver.Nick)
	r.recomputeAIKMembers()

	nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: leaver.Nick}
	for _, occ := range r.occupants {
		presXML := buildOccupantPresence(nickJID.String(), occ.FullJID.String(), leaver.Role, leaver.Affiliation, true, "")
		_ = rtr.RouteToFull(ctx, occ.FullJID, presXML)
	}
	presXML := buildOccupantPresence(nickJID.String(), fullJID.String(), leaver.Role, leaver.Affiliation, true, "")
	_ = rtr.RouteToFull(ctx, fullJID, presXML)

	return nil
}

func (r *Room) BroadcastMessage(ctx context.Context, fromFullJID stanza.JID, raw []byte, rtr *router.Router) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var sender *Occupant
	for _, occ := range r.occupants {
		if occ.FullJID.Equal(fromFullJID) {
			sender = occ
			break
		}
	}
	if sender == nil {
		return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrForbidden}
	}

	fromNickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: sender.Nick}

	rewritten, err := rewriteMessageFrom(raw, fromNickJID.String())
	if err != nil {
		return err
	}

	msgTS := time.Now()
	r.history = append(r.history, &ArchivedMessage{
		TS:       msgTS,
		FromNick: sender.Nick,
		XML:      rewritten,
	})
	max := r.config.HistoryMax
	if max == 0 {
		max = 100
	}
	var oldestKeptTS time.Time
	if len(r.history) > max*2 {
		r.history = r.history[len(r.history)-max:]
		oldestKeptTS = r.history[0].TS
	}

	if r.persistent && r.store != nil {
		if _, err := r.store.AppendHistory(ctx, &storage.MUCHistory{
			RoomJID:   r.jid.String(),
			SenderJID: fromFullJID.String(),
			TS:        msgTS,
			StanzaXML: rewritten,
		}); err != nil {
			// Best-effort: warn but never block delivery.
			_ = err
		}
		// Trim stored history to match the in-memory cap.
		if !oldestKeptTS.IsZero() {
			if _, err := r.store.DeleteHistoryBefore(ctx, r.jid.String(), oldestKeptTS); err != nil {
				_ = err
			}
		}
	}

	// Archive into MAM for XEP-0313 query support.  Best-effort: never
	// block or fail the broadcast on archival errors.
	if r.mam != nil {
		if _, err := r.mam.ArchiveMUC(ctx, r.jid, fromFullJID, rewritten); err != nil {
			_ = err
		}
	}

	for _, occ := range r.occupants {
		msg := rewritten
		if r.config.AnonymityMode == AnonymityNonAnon ||
			(r.config.AnonymityMode == AnonymitySemi && occ.Role >= RoleModerator) {
			msg = injectRealJID(rewritten, fromFullJID.String())
		}
		toMsg := rewriteMessageTo(msg, occ.FullJID.String())
		_ = rtr.RouteToFull(ctx, occ.FullJID, toMsg)
	}
	return nil
}

func (r *Room) ChangeSubject(ctx context.Context, fromNick string, newSubject string, rtr *router.Router) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	occ, ok := r.occupants[fromNick]
	if !ok {
		return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrForbidden}
	}
	if r.config.Moderated && occ.Role < RoleModerator {
		return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrForbidden}
	}

	now := time.Now()
	r.subject = newSubject
	r.subjectChangedBy = fromNick
	r.subjectTS = now

	if r.persistent && r.store != nil {
		if err := r.store.PutRoomSubject(ctx, r.jid.String(), newSubject, fromNick, now); err != nil {
			// Best-effort: warn but do not fail the broadcast.
			_ = err
		}
	}

	fromNickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: fromNick}
	for _, o := range r.occupants {
		subjMsg := buildSubjectMessage(fromNickJID.String(), o.FullJID.String(), newSubject)
		_ = rtr.RouteToFull(ctx, o.FullJID, subjMsg)
	}
	return nil
}

func (r *Room) SetAffiliation(ctx context.Context, byJID stanza.JID, targetJID stanza.JID, newAff int, store storage.MUCStore) error {
	return r.setAffiliationFull(ctx, byJID, targetJID, newAff, "", store, nil)
}

// setAffiliationFull is the internal implementation that supports reason, actor,
// and presence broadcasts. Caller must NOT hold r.mu.
func (r *Room) setAffiliationFull(ctx context.Context, byJID stanza.JID, targetJID stanza.JID, newAff int, reason string, store storage.MUCStore, rtr *router.Router) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	byBare := byJID.Bare().String()
	byAff, ok := r.affiliations[byBare]
	if !ok {
		byAff = AffNone
	}

	if byAff < AffAdmin {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}
	if byAff == AffAdmin && newAff >= AffAdmin {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	targetBare := targetJID.Bare().String()

	// Admins cannot modify other admins or owners.
	if byAff == AffAdmin {
		existing := r.affiliations[targetBare]
		if existing >= AffAdmin {
			return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
		}
	}

	oldAff := r.affiliations[targetBare]
	r.affiliations[targetBare] = newAff

	if store != nil {
		if err := store.PutAffiliation(ctx, &storage.MUCAffiliation{
			RoomJID:     r.jid.String(),
			UserJID:     targetBare,
			Affiliation: newAff,
		}); err != nil {
			return err
		}
	}

	if rtr == nil {
		// Legacy path: just update in-memory occupant affiliation, no broadcasts.
		for nick, occ := range r.occupants {
			if occ.FullJID.Bare().String() == targetBare {
				r.occupants[nick].Affiliation = newAff
			}
		}
		return nil
	}

	// Determine status code and whether to evict.
	var statusCode string
	evict := false
	if newAff == AffOutcast {
		statusCode = "301"
		evict = true
	} else if newAff < AffMember && oldAff >= AffMember {
		statusCode = "321"
		evict = true
	}

	actorJIDStr := byJID.Bare().String()

	// Collect affected occupants before mutating the map.
	type affected struct {
		nick string
		occ  *Occupant
	}
	var targets []affected
	for nick, occ := range r.occupants {
		if occ.FullJID.Bare().String() == targetBare {
			targets = append(targets, affected{nick, occ})
		}
	}

	for _, t := range targets {
		occ := t.occ
		if evict {
			delete(r.occupants, t.nick)
		} else {
			r.occupants[t.nick].Affiliation = newAff
		}

		presType := "available"
		if evict {
			presType = "unavailable"
		}
		xPayload := buildMUCUserXWithStatus(occ.Role, newAff, t.nick, reason, actorJIDStr, statusCode)
		nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: t.nick}

		// Broadcast to all remaining occupants.
		for _, other := range r.occupants {
			pres := buildRawPresence(nickJID.String(), other.FullJID.String(), presType, xPayload)
			_ = rtr.RouteToFull(ctx, other.FullJID, pres)
		}
		// Also send to the target occupant itself.
		pres := buildRawPresence(nickJID.String(), occ.FullJID.String(), presType, xPayload)
		_ = rtr.RouteToFull(ctx, occ.FullJID, pres)
	}

	if evict {
		r.recomputeAIKMembers()
		// Drop any pubsub subscriptions the evicted user held on this room's nodes.
		if dropPubsubSubscriptions != nil {
			go dropPubsubSubscriptions(ctx, r.jid, targetBare)
		}
	}

	return nil
}

// SetRole updates an occupant's role for the current session (kick = RoleNone).
// Broadcasts presence with status code 307 (kicked). Caller must be moderator.
func (r *Room) SetRole(ctx context.Context, byJID stanza.JID, targetNick string, newRole int, reason string, rtr *router.Router) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Verify requester is a moderator.
	byBare := byJID.Bare().String()
	var byRole int
	for _, occ := range r.occupants {
		if occ.FullJID.Bare().String() == byBare {
			byRole = occ.Role
			break
		}
	}
	if byRole < RoleModerator {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	target, ok := r.occupants[targetNick]
	if !ok {
		return &stanza.StanzaError{Type: stanza.ErrorTypeCancel, Condition: stanza.ErrItemNotFound}
	}

	// Moderators cannot kick other moderators.
	if target.Role >= RoleModerator {
		aff := r.affiliations[byBare]
		if aff < AffAdmin {
			return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
		}
	}

	oldRole := target.Role
	_ = oldRole

	var statusCode string
	evict := false
	if newRole == RoleNone {
		statusCode = "307"
		evict = true
		delete(r.occupants, targetNick)
	} else {
		r.occupants[targetNick].Role = newRole
	}

	actorJIDStr := byJID.Bare().String()
	xPayload := buildMUCUserXWithStatus(newRole, target.Affiliation, targetNick, reason, actorJIDStr, statusCode)
	nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: targetNick}

	presType := "available"
	if evict {
		presType = "unavailable"
	}

	for _, other := range r.occupants {
		pres := buildRawPresence(nickJID.String(), other.FullJID.String(), presType, xPayload)
		_ = rtr.RouteToFull(ctx, other.FullJID, pres)
	}
	// Send to target as well.
	pres := buildRawPresence(nickJID.String(), target.FullJID.String(), presType, xPayload)
	_ = rtr.RouteToFull(ctx, target.FullJID, pres)

	if evict {
		r.recomputeAIKMembers()
	}

	return nil
}

// AdminItems returns affiliation entries at or above the requested level.
// Used to answer get-banlist / get-memberlist / get-adminlist / get-ownerlist.
func (r *Room) AdminItems(level int) []AdminItem {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []AdminItem
	for jidStr, aff := range r.affiliations {
		if aff == level {
			out = append(out, AdminItem{
				Affiliation: affiliationName(aff),
				JID:         jidStr,
			})
		}
	}
	return out
}

// ApplyAdminItems applies a slice of muc#admin item directives atomically.
// Items containing both Affiliation and Role MUST NOT be mixed in one IQ
// (XEP-0045 §9.5); this is enforced before any mutation.
func (r *Room) ApplyAdminItems(ctx context.Context, byJID stanza.JID, items []AdminItem, rtr *router.Router) error {
	if len(items) == 0 {
		return nil
	}

	// Detect affiliation+role mixing before any mutation.
	hasAff := false
	hasRole := false
	for _, it := range items {
		if it.Affiliation != "" {
			hasAff = true
		}
		if it.Role != "" {
			hasRole = true
		}
	}
	if hasAff && hasRole {
		return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}

	if hasRole {
		// Role-only items: apply via SetRole (each acquires the lock separately,
		// but that's acceptable since role ops are per-session not stored state).
		for _, it := range items {
			if it.Nick == "" {
				return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
			}
			newRole := parseRoleName(it.Role)
			if err := r.SetRole(ctx, byJID, it.Nick, newRole, it.Reason, rtr); err != nil {
				return err
			}
		}
		return nil
	}

	// Affiliation items: validate all, then apply atomically under one lock.
	type work struct {
		targetJID stanza.JID
		newAff    int
		reason    string
	}
	ops := make([]work, 0, len(items))

	r.mu.Lock()
	defer r.mu.Unlock()

	byBare := byJID.Bare().String()
	byAff := r.affiliations[byBare]

	for _, it := range items {
		if it.Affiliation == "" {
			return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
		}
		newAff := parseAffiliationName(it.Affiliation)

		// Real-JID required for outcast and all affiliation changes.
		if it.JID == "" {
			if newAff == AffOutcast {
				// Nick-only ban rejected per locked design decision.
				return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrNotAcceptable}
			}
			// Other affiliation changes also require real JID.
			return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
		}

		tj, err := stanza.Parse(it.JID)
		if err != nil {
			return &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
		}
		targetBare := tj.Bare().String()

		// Auth checks.
		if byAff < AffAdmin {
			return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
		}
		if byAff == AffAdmin {
			if newAff >= AffAdmin {
				return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
			}
			existing := r.affiliations[targetBare]
			if existing >= AffAdmin {
				return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
			}
		}

		ops = append(ops, work{tj, newAff, it.Reason})
	}

	// All validations passed — apply mutations.
	actorJIDStr := byJID.Bare().String()

	// Apply outcasts first so evictions happen before promotions.
	for _, op := range ops {
		if op.newAff == AffOutcast {
			r.applyAffiliationLocked(ctx, op.targetJID, op.newAff, op.reason, actorJIDStr, rtr)
		}
	}
	for _, op := range ops {
		if op.newAff != AffOutcast {
			r.applyAffiliationLocked(ctx, op.targetJID, op.newAff, op.reason, actorJIDStr, rtr)
		}
	}

	// Persist all changes.
	if r.store != nil {
		for _, op := range ops {
			targetBare := op.targetJID.Bare().String()
			_ = r.store.PutAffiliation(ctx, &storage.MUCAffiliation{
				RoomJID:     r.jid.String(),
				UserJID:     targetBare,
				Affiliation: op.newAff,
			})
		}
	}

	return nil
}

// dropPubsubSubscriptions is set by the MUC Service when a pubsub host is
// wired in.  It is called after affiliation-based eviction to remove the
// evicted user's pubsub subscriptions on this room's nodes.
var dropPubsubSubscriptions func(ctx context.Context, roomJID stanza.JID, subscriberBare string)

// applyAffiliationLocked applies one affiliation change and broadcasts presence.
// Caller must hold r.mu.Lock(). Does NOT persist — caller persists after all ops.
func (r *Room) applyAffiliationLocked(ctx context.Context, targetJID stanza.JID, newAff int, reason, actorJIDStr string, rtr *router.Router) {
	targetBare := targetJID.Bare().String()
	oldAff := r.affiliations[targetBare]
	r.affiliations[targetBare] = newAff

	var statusCode string
	evict := false
	if newAff == AffOutcast {
		statusCode = "301"
		evict = true
	} else if newAff < AffMember && oldAff >= AffMember {
		statusCode = "321"
		evict = true
	}

	if rtr == nil {
		if !evict {
			for nick, occ := range r.occupants {
				if occ.FullJID.Bare().String() == targetBare {
					r.occupants[nick].Affiliation = newAff
				}
			}
		}
		return
	}

	type affected struct {
		nick string
		occ  *Occupant
	}
	var targets []affected
	for nick, occ := range r.occupants {
		if occ.FullJID.Bare().String() == targetBare {
			targets = append(targets, affected{nick, occ})
		}
	}

	for _, t := range targets {
		occ := t.occ
		if evict {
			delete(r.occupants, t.nick)
		} else {
			r.occupants[t.nick].Affiliation = newAff
		}

		presType := "available"
		if evict {
			presType = "unavailable"
		}
		xPayload := buildMUCUserXWithStatus(occ.Role, newAff, t.nick, reason, actorJIDStr, statusCode)
		nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: t.nick}

		for _, other := range r.occupants {
			pres := buildRawPresence(nickJID.String(), other.FullJID.String(), presType, xPayload)
			_ = rtr.RouteToFull(ctx, other.FullJID, pres)
		}
		pres := buildRawPresence(nickJID.String(), occ.FullJID.String(), presType, xPayload)
		_ = rtr.RouteToFull(ctx, occ.FullJID, pres)
	}

	if evict {
		r.recomputeAIKMembers()
		// Drop any pubsub subscriptions the evicted user held on this room's nodes.
		if dropPubsubSubscriptions != nil {
			targetBare := targetJID.Bare().String()
			go dropPubsubSubscriptions(ctx, r.jid, targetBare)
		}
	}
}

// Destroy evicts every occupant with a tombstone presence and clears
// affiliations. The caller is responsible for removing the room from
// the Service map and deleting the row from MUCStore.
//
// Tombstone presence per XEP-0045 §10.9:
//
//	<presence from='room@conference/nick' to='occupant' type='unavailable'>
//	  <x xmlns='http://jabber.org/protocol/muc#user'>
//	    <item affiliation='none' role='none'/>
//	    <destroy jid='alt-jid'><reason>...</reason></destroy>
//	  </x>
//	</presence>
func (r *Room) Destroy(ctx context.Context, altJID, reason string, rtr *router.Router) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build the <x> payload once; it is identical for every recipient.
	xPayload := buildDestroyX(altJID, reason)

	// Emit tombstone to every occupant BEFORE clearing the map so they all
	// receive their notification.
	for nick, occ := range r.occupants {
		nickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: nick}
		pres := buildRawPresence(nickJID.String(), occ.FullJID.String(), stanza.PresenceUnavailable, xPayload)
		_ = rtr.RouteToFull(ctx, occ.FullJID, pres)
	}

	// Clear in-memory state.
	r.occupants = make(map[string]*Occupant)
	r.affiliations = make(map[string]int)

	// Best-effort: remove history rows so storage stays tidy.
	if r.persistent && r.store != nil {
		_, _ = r.store.DeleteHistoryBefore(ctx, r.jid.String(), time.Now())
	}
}

// buildDestroyX builds the <x xmlns='muc#user'> payload for a destroy tombstone.
func buildDestroyX(altJID, reason string) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	x := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "x"}}
	enc.EncodeToken(x)

	item := xml.StartElement{
		Name: xml.Name{Space: nsMUCUser, Local: "item"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "affiliation"}, Value: "none"},
			{Name: xml.Name{Local: "role"}, Value: "none"},
		},
	}
	enc.EncodeToken(item)
	enc.EncodeToken(item.End())

	destroyAttrs := []xml.Attr{}
	if altJID != "" {
		destroyAttrs = append(destroyAttrs, xml.Attr{Name: xml.Name{Local: "jid"}, Value: altJID})
	}
	destroy := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "destroy"}, Attr: destroyAttrs}
	enc.EncodeToken(destroy)
	if reason != "" {
		reasonEl := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "reason"}}
		enc.EncodeToken(reasonEl)
		enc.EncodeToken(xml.CharData(reason))
		enc.EncodeToken(reasonEl.End())
	}
	enc.EncodeToken(destroy.End())

	enc.EncodeToken(x.End())
	enc.Flush()
	return buf.Bytes()
}

func (r *Room) SelfPing(ctx context.Context, fromFullJID stanza.JID, rtr *router.Router) error {
	// Fast path: exact match under the read lock.
	r.mu.RLock()
	for _, occ := range r.occupants {
		if occ.FullJID.Equal(fromFullJID) {
			r.mu.RUnlock()
			return nil
		}
	}
	r.mu.RUnlock()

	// Slow path: SM-resume can land the user on a new resource without a
	// fresh presence to <room/nick>. If the bare JID still matches the
	// occupant, refresh the FullJID rather than failing — failing here
	// triggers an unnecessary rejoin cycle on the client and risks the
	// stale-occupant lockout discussed in Room.Join.
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, occ := range r.occupants {
		if occ.FullJID.Bare().Equal(fromFullJID.Bare()) {
			occ.FullJID = fromFullJID
			return nil
		}
	}
	return ErrNotAcceptable
}

func (r *Room) OccupantCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.occupants)
}

func (r *Room) OccupantNicks() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nicks := make([]string, 0, len(r.occupants))
	for nick := range r.occupants {
		nicks = append(nicks, nick)
	}
	sort.Strings(nicks)
	return nicks
}

func (r *Room) IsOwner(j stanza.JID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	aff, ok := r.affiliations[j.Bare().String()]
	return ok && aff >= AffOwner
}

func (r *Room) ApplyOwnerForm(fields map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.persistent = true

	get := func(key string) (string, bool) {
		v, ok := fields[key]
		return v, ok
	}
	getBool := func(key string) (bool, bool) {
		if v, ok := get(key); ok {
			switch v {
			case "1", "true":
				return true, true
			case "0", "false":
				return false, true
			}
		}
		return false, false
	}

	if v, ok := get("muc#roomconfig_roomname"); ok {
		r.config.Name = v
	}
	if v, ok := get("muc#roomconfig_roomdesc"); ok {
		r.config.Description = v
	}
	if v, ok := getBool("muc#roomconfig_persistentroom"); ok {
		r.persistent = v
	}
	if v, ok := getBool("muc#roomconfig_publicroom"); ok {
		r.config.Public = v
	}
	if v, ok := getBool("muc#roomconfig_membersonly"); ok {
		r.config.MembersOnly = v
	}
	if v, ok := getBool("muc#roomconfig_moderatedroom"); ok {
		r.config.Moderated = v
	}
	if v, ok := getBool("muc#roomconfig_passwordprotectedroom"); ok {
		r.config.PasswordProtected = v
	}
	if v, ok := get("muc#roomconfig_roomsecret"); ok {
		r.config.Password = v
	}
	if v, ok := get("muc#roomconfig_whois"); ok {
		switch v {
		case "anyone":
			r.config.AnonymityMode = AnonymityNonAnon
		case "moderators":
			r.config.AnonymityMode = AnonymitySemi
		}
	}
	r.config.PersistRoom = r.persistent
}

func (r *Room) DisplayName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.config.Name != "" {
		return r.config.Name
	}
	return r.jid.Local
}

func (r *Room) recomputeAIKMembers() {
	seen := make(map[string]struct{})
	for _, occ := range r.occupants {
		if occ.AIKFingerprint != "" {
			seen[occ.AIKFingerprint] = struct{}{}
		}
	}
	members := make([]string, 0, len(seen))
	for fp := range seen {
		members = append(members, fp)
	}
	sort.Strings(members)
	r.config.AIKMembers = members
}

func (r *Room) AIKMembers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.config.AIKMembers))
	copy(out, r.config.AIKMembers)
	return out
}

// preloadFromStoreIfEmpty loads history from storage when the room has no
// in-memory history yet (e.g. after a service restart). Caller must hold r.mu.
func (r *Room) preloadFromStoreIfEmpty(ctx context.Context) {
	if len(r.history) > 0 || !r.persistent || r.store == nil {
		return
	}
	limit := r.config.HistoryMax
	if limit == 0 {
		limit = 20
	}
	rows, err := r.store.QueryHistory(ctx, r.jid.String(), nil, nil, limit)
	if err != nil {
		return
	}
	for _, h := range rows {
		// Derive FromNick from SenderJID resource (stored as room@conf/nick).
		nick := ""
		if sj, perr := stanza.Parse(h.SenderJID); perr == nil {
			nick = sj.Resource
		}
		r.history = append(r.history, &ArchivedMessage{
			TS:       h.TS,
			FromNick: nick,
			XML:      h.StanzaXML,
		})
	}
}

func buildOccupantPresence(from, to string, role, affiliation int, unavailable bool, aikFP string) []byte {
	p := &stanza.Presence{
		From: from,
		To:   to,
	}
	if unavailable {
		p.Type = stanza.PresenceUnavailable
	}
	xElem := buildMUCUserX(role, affiliation, "")
	if aikFP != "" {
		xElem = append(xElem, buildAIKElement(aikFP)...)
	}
	p.Children = xElem
	raw, _ := p.Marshal()
	return raw
}

func buildSelfPresence(from, to string, role, affiliation int, created bool) []byte {
	p := &stanza.Presence{
		From: from,
		To:   to,
	}
	xElem := buildMUCUserXSelf(role, affiliation, created)
	p.Children = xElem
	raw, _ := p.Marshal()
	return raw
}

func buildAIKElement(fp string) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	aik := xml.StartElement{
		Name: xml.Name{Space: nsGroup, Local: "aik"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "fp"}, Value: fp}},
	}
	enc.EncodeToken(aik)
	enc.EncodeToken(aik.End())
	enc.Flush()
	return buf.Bytes()
}

func buildMUCUserX(role, affiliation int, realJID string) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	x := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "x"}}
	enc.EncodeToken(x)
	item := xml.StartElement{
		Name: xml.Name{Space: nsMUCUser, Local: "item"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "affiliation"}, Value: affiliationName(affiliation)},
			{Name: xml.Name{Local: "role"}, Value: roleName(role)},
		},
	}
	if realJID != "" {
		item.Attr = append(item.Attr, xml.Attr{Name: xml.Name{Local: "jid"}, Value: realJID})
	}
	enc.EncodeToken(item)
	enc.EncodeToken(item.End())
	enc.EncodeToken(x.End())
	enc.Flush()
	return buf.Bytes()
}

func buildMUCUserXSelf(role, affiliation int, created bool) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	x := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "x"}}
	enc.EncodeToken(x)
	item := xml.StartElement{
		Name: xml.Name{Space: nsMUCUser, Local: "item"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "affiliation"}, Value: affiliationName(affiliation)},
			{Name: xml.Name{Local: "role"}, Value: roleName(role)},
		},
	}
	enc.EncodeToken(item)
	enc.EncodeToken(item.End())
	codes := []string{"110"}
	if created {
		codes = append(codes, "201")
	}
	for _, code := range codes {
		status := xml.StartElement{
			Name: xml.Name{Space: nsMUCUser, Local: "status"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "code"}, Value: code}},
		}
		enc.EncodeToken(status)
		enc.EncodeToken(status.End())
	}
	enc.EncodeToken(x.End())
	enc.Flush()
	return buf.Bytes()
}

func buildRoomDiscoInfo(room *Room) []byte {
	room.mu.RLock()
	cfg := room.config
	persistent := room.persistent
	name := cfg.Name
	if name == "" {
		name = room.jid.Local
	}
	room.mu.RUnlock()

	feat := func(v string) string {
		return `<feature var='` + xmlAttrEscape(v) + `'/>`
	}

	var b bytes.Buffer
	b.WriteString(`<query xmlns='http://jabber.org/protocol/disco#info'>`)
	b.WriteString(`<identity category='conference' type='text' name='` + xmlAttrEscape(name) + `'/>`)
	b.WriteString(feat("http://jabber.org/protocol/muc"))
	b.WriteString(feat("http://jabber.org/protocol/disco#info"))
	b.WriteString(feat("http://jabber.org/protocol/disco#items"))
	b.WriteString(feat("urn:xmpp:ping"))

	if persistent {
		b.WriteString(feat("muc_persistent"))
	} else {
		b.WriteString(feat("muc_temporary"))
	}
	if cfg.MembersOnly {
		b.WriteString(feat("muc_membersonly"))
	} else {
		b.WriteString(feat("muc_open"))
	}
	if cfg.Public {
		b.WriteString(feat("muc_public"))
	} else {
		b.WriteString(feat("muc_hidden"))
	}
	if cfg.PasswordProtected {
		b.WriteString(feat("muc_passwordprotected"))
	} else {
		b.WriteString(feat("muc_unsecured"))
	}
	if cfg.Moderated {
		b.WriteString(feat("muc_moderated"))
	} else {
		b.WriteString(feat("muc_unmoderated"))
	}
	switch cfg.AnonymityMode {
	case AnonymityNonAnon:
		b.WriteString(feat("muc_nonanonymous"))
	default:
		b.WriteString(feat("muc_semianonymous"))
	}
	b.WriteString(`</query>`)
	return b.Bytes()
}

func buildOwnerConfigForm(room *Room) []byte {
	room.mu.RLock()
	cfg := room.config
	persistent := room.persistent
	room.mu.RUnlock()

	bool01 := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	whois := "moderators"
	if cfg.AnonymityMode == AnonymityNonAnon {
		whois = "anyone"
	}

	var b bytes.Buffer
	b.WriteString(`<query xmlns='http://jabber.org/protocol/muc#owner'>`)
	b.WriteString(`<x xmlns='jabber:x:data' type='form'>`)
	b.WriteString(`<title>Room configuration</title>`)
	b.WriteString(`<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#roomconfig</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_roomname' type='text-single' label='Room name'><value>` + xmlAttrEscape(cfg.Name) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_roomdesc' type='text-single' label='Description'><value>` + xmlAttrEscape(cfg.Description) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_persistentroom' type='boolean' label='Persistent'><value>` + bool01(persistent) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_publicroom' type='boolean' label='Publicly listed'><value>` + bool01(cfg.Public) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_membersonly' type='boolean' label='Members only'><value>` + bool01(cfg.MembersOnly) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_moderatedroom' type='boolean' label='Moderated'><value>` + bool01(cfg.Moderated) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_passwordprotectedroom' type='boolean' label='Password protected'><value>` + bool01(cfg.PasswordProtected) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_roomsecret' type='text-private' label='Password'><value>` + xmlAttrEscape(cfg.Password) + `</value></field>`)
	b.WriteString(`<field var='muc#roomconfig_whois' type='list-single' label='Real-JID visible to'>`)
	b.WriteString(`<value>` + whois + `</value>`)
	b.WriteString(`<option label='Moderators only'><value>moderators</value></option>`)
	b.WriteString(`<option label='Anyone'><value>anyone</value></option>`)
	b.WriteString(`</field>`)
	b.WriteString(`</x>`)
	b.WriteString(`</query>`)
	return b.Bytes()
}

func buildConferenceDiscoItems(rooms []*Room) []byte {
	var b bytes.Buffer
	b.WriteString(`<query xmlns='http://jabber.org/protocol/disco#items'>`)
	for _, room := range rooms {
		b.WriteString(`<item jid='` + xmlAttrEscape(room.JID().String()) + `' name='` + xmlAttrEscape(room.DisplayName()) + `'/>`)
	}
	b.WriteString(`</query>`)
	return b.Bytes()
}

func buildRoomDiscoItems(room *Room) []byte {
	roomJID := room.JID()
	nicks := room.OccupantNicks()
	var b bytes.Buffer
	b.WriteString(`<query xmlns='http://jabber.org/protocol/disco#items'>`)
	for _, nick := range nicks {
		nj := stanza.JID{Local: roomJID.Local, Domain: roomJID.Domain, Resource: nick}
		b.WriteString(`<item jid='` + xmlAttrEscape(nj.String()) + `'/>`)
	}
	b.WriteString(`</query>`)
	return b.Bytes()
}

func xmlAttrEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func buildSubjectMessage(from, to, subject string) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	start := xml.StartElement{
		Name: xml.Name{Local: "message"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "from"}, Value: from},
			{Name: xml.Name{Local: "to"}, Value: to},
			{Name: xml.Name{Local: "type"}, Value: stanza.MessageGroupchat},
		},
	}
	enc.EncodeToken(start)
	subjStart := xml.StartElement{Name: xml.Name{Local: "subject"}}
	enc.EncodeToken(subjStart)
	if subject != "" {
		enc.EncodeToken(xml.CharData(subject))
	}
	enc.EncodeToken(subjStart.End())
	enc.EncodeToken(start.End())
	enc.Flush()
	return buf.Bytes()
}

func rewriteMessageFrom(raw []byte, newFrom string) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	first := true
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		if first {
			if se, ok := tok.(xml.StartElement); ok {
				newAttrs := make([]xml.Attr, 0, len(se.Attr))
				for _, a := range se.Attr {
					if a.Name.Local == "from" {
						continue
					}
					if a.Name.Local == "to" {
						continue
					}
					newAttrs = append(newAttrs, a)
				}
				newAttrs = append(newAttrs, xml.Attr{Name: xml.Name{Local: "from"}, Value: newFrom})
				se.Attr = newAttrs
				enc.EncodeToken(se)
				first = false
				continue
			}
		}
		enc.EncodeToken(tok)
	}
	enc.Flush()
	return buf.Bytes(), nil
}

func rewriteMessageTo(raw []byte, newTo string) []byte {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	first := true
	for {
		tok, err := dec.RawToken()
		if err != nil {
			break
		}
		if first {
			if se, ok := tok.(xml.StartElement); ok {
				newAttrs := make([]xml.Attr, 0, len(se.Attr))
				for _, a := range se.Attr {
					if a.Name.Local == "to" {
						continue
					}
					newAttrs = append(newAttrs, a)
				}
				newAttrs = append(newAttrs, xml.Attr{Name: xml.Name{Local: "to"}, Value: newTo})
				se.Attr = newAttrs
				enc.EncodeToken(se)
				first = false
				continue
			}
		}
		enc.EncodeToken(tok)
	}
	enc.Flush()
	return buf.Bytes()
}

func injectRealJID(raw []byte, realJID string) []byte {
	return raw
}

func affiliationName(a int) string {
	switch a {
	case AffOwner:
		return "owner"
	case AffAdmin:
		return "admin"
	case AffMember:
		return "member"
	case AffOutcast:
		return "outcast"
	default:
		return "none"
	}
}

func roleName(r int) string {
	switch r {
	case RoleModerator:
		return "moderator"
	case RoleParticipant:
		return "participant"
	case RoleVisitor:
		return "visitor"
	default:
		return "none"
	}
}

// buildMUCUserXWithStatus builds the <x xmlns='muc#user'> payload for kick/ban/role-change
// presence stanzas, including optional reason, actor, and status code.
func buildMUCUserXWithStatus(role, affiliation int, nick, reason, actorJID, statusCode string) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	x := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "x"}}
	enc.EncodeToken(x)

	item := xml.StartElement{
		Name: xml.Name{Space: nsMUCUser, Local: "item"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "affiliation"}, Value: affiliationName(affiliation)},
			{Name: xml.Name{Local: "role"}, Value: roleName(role)},
		},
	}
	if nick != "" {
		item.Attr = append(item.Attr, xml.Attr{Name: xml.Name{Local: "nick"}, Value: nick})
	}
	enc.EncodeToken(item)

	if reason != "" {
		reasonEl := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "reason"}}
		enc.EncodeToken(reasonEl)
		enc.EncodeToken(xml.CharData(reason))
		enc.EncodeToken(reasonEl.End())
	}
	if actorJID != "" {
		actorEl := xml.StartElement{
			Name: xml.Name{Space: nsMUCUser, Local: "actor"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "jid"}, Value: actorJID}},
		}
		enc.EncodeToken(actorEl)
		enc.EncodeToken(actorEl.End())
	}

	enc.EncodeToken(item.End())

	if statusCode != "" {
		status := xml.StartElement{
			Name: xml.Name{Space: nsMUCUser, Local: "status"},
			Attr: []xml.Attr{{Name: xml.Name{Local: "code"}, Value: statusCode}},
		}
		enc.EncodeToken(status)
		enc.EncodeToken(status.End())
	}

	enc.EncodeToken(x.End())
	enc.Flush()
	return buf.Bytes()
}

// buildRawPresence builds a <presence> stanza with the given from/to/type and XML payload.
func buildRawPresence(from, to, presType string, payload []byte) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	start := xml.StartElement{
		Name: xml.Name{Local: "presence"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "from"}, Value: from},
			{Name: xml.Name{Local: "to"}, Value: to},
		},
	}
	if presType != "" && presType != "available" {
		start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Local: "type"}, Value: presType})
	}
	enc.EncodeToken(start)
	enc.Flush()

	buf.Write(payload)

	enc2 := xml.NewEncoder(&buf)
	enc2.EncodeToken(start.End())
	enc2.Flush()
	return buf.Bytes()
}

func parseAffiliationName(s string) int {
	switch s {
	case "owner":
		return AffOwner
	case "admin":
		return AffAdmin
	case "member":
		return AffMember
	case "outcast":
		return AffOutcast
	default:
		return AffNone
	}
}

func parseRoleName(s string) int {
	switch s {
	case "moderator":
		return RoleModerator
	case "participant":
		return RoleParticipant
	case "visitor":
		return RoleVisitor
	default:
		return RoleNone
	}
}

func marshalErrorIQ(iq *stanza.IQ, errType, condition string) []byte {
	se := &stanza.StanzaError{Type: errType, Condition: condition}
	errBytes, _ := se.Marshal()
	resp := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQError,
		Payload: errBytes,
	}
	raw, _ := resp.Marshal()
	return raw
}

func marshalResultIQ(iq *stanza.IQ, payload []byte) []byte {
	resp := &stanza.IQ{
		ID:      iq.ID,
		From:    iq.To,
		To:      iq.From,
		Type:    stanza.IQResult,
		Payload: payload,
	}
	raw, _ := resp.Marshal()
	return raw
}
