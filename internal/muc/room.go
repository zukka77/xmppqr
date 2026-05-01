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
	history          []*ArchivedMessage
	persistent       bool
}

func newRoom(j stanza.JID, cfg RoomConfig, persistent bool) *Room {
	return &Room{
		jid:          j,
		config:       cfg,
		occupants:    make(map[string]*Occupant),
		affiliations: make(map[string]int),
		persistent:   persistent,
	}
}

func roomFromStorage(r *storage.MUCRoom) (*Room, error) {
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
	room := newRoom(j, cfg, r.Persistent)
	return room, nil
}

func (r *Room) JID() stanza.JID { return r.jid }

func (r *Room) Join(ctx context.Context, occ *Occupant, password string, rtr *router.Router, store storage.MUCStore) error {
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

	if r.config.MembersOnly && aff < AffMember {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	if existing, clash := r.occupants[occ.Nick]; clash {
		if !existing.FullJID.Equal(occ.FullJID) {
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

	selfPresXML := buildSelfPresence(nickJID.String(), occ.FullJID.String(), occ.Role, occ.Affiliation)
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

	if r.subject != "" {
		subjFrom := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: r.subjectChangedBy}
		subjMsg := buildSubjectMessage(subjFrom.String(), occ.FullJID.String(), r.subject)
		_ = rtr.RouteToFull(ctx, occ.FullJID, subjMsg)
	}

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

	if r.config.HistoryMax != 0 || true {
		r.history = append(r.history, &ArchivedMessage{
			TS:       time.Now(),
			FromNick: sender.Nick,
			XML:      rewritten,
		})
		max := r.config.HistoryMax
		if max == 0 {
			max = 100
		}
		if len(r.history) > max*2 {
			r.history = r.history[len(r.history)-max:]
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

	r.subject = newSubject
	r.subjectChangedBy = fromNick

	fromNickJID := stanza.JID{Local: r.jid.Local, Domain: r.jid.Domain, Resource: fromNick}
	for _, o := range r.occupants {
		subjMsg := buildSubjectMessage(fromNickJID.String(), o.FullJID.String(), newSubject)
		_ = rtr.RouteToFull(ctx, o.FullJID, subjMsg)
	}
	return nil
}

func (r *Room) SetAffiliation(ctx context.Context, byJID stanza.JID, targetJID stanza.JID, newAff int, store storage.MUCStore) error {
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
	if byAff == AffAdmin && newAff > AffAdmin {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}
	if byAff == AffAdmin && newAff == AffOwner {
		return &stanza.StanzaError{Type: stanza.ErrorTypeAuth, Condition: stanza.ErrForbidden}
	}

	targetBare := targetJID.Bare().String()
	r.affiliations[targetBare] = newAff

	for nick, occ := range r.occupants {
		if occ.FullJID.Bare().String() == targetBare {
			r.occupants[nick].Affiliation = newAff
		}
	}

	if store != nil {
		if err := store.PutAffiliation(ctx, &storage.MUCAffiliation{
			RoomJID:     r.jid.String(),
			UserJID:     targetBare,
			Affiliation: newAff,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Room) SelfPing(ctx context.Context, fromFullJID stanza.JID, rtr *router.Router) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, occ := range r.occupants {
		if occ.FullJID.Equal(fromFullJID) {
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

func buildSelfPresence(from, to string, role, affiliation int) []byte {
	p := &stanza.Presence{
		From: from,
		To:   to,
	}
	xElem := buildMUCUserXSelf(role, affiliation)
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
		Name: xml.Name{Local: "item"},
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

func buildMUCUserXSelf(role, affiliation int) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	x := xml.StartElement{Name: xml.Name{Space: nsMUCUser, Local: "x"}}
	enc.EncodeToken(x)
	item := xml.StartElement{
		Name: xml.Name{Local: "item"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "affiliation"}, Value: affiliationName(affiliation)},
			{Name: xml.Name{Local: "role"}, Value: roleName(role)},
		},
	}
	enc.EncodeToken(item)
	enc.EncodeToken(item.End())
	status := xml.StartElement{
		Name: xml.Name{Local: "status"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "code"}, Value: "110"}},
	}
	enc.EncodeToken(status)
	enc.EncodeToken(status.End())
	enc.EncodeToken(x.End())
	enc.Flush()
	return buf.Bytes()
}

func buildSubjectMessage(from, to, subject string) []byte {
	m := &stanza.Message{
		From:    from,
		To:      to,
		Type:    stanza.MessageGroupchat,
		Subject: subject,
	}
	raw, _ := m.Marshal()
	return raw
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

