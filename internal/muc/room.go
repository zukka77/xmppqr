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
