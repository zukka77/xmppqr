package storage

import (
	"context"
	"time"
)

type JID = string

type User struct {
	Username     string
	ScramSalt    []byte
	ScramIter    int
	Argon2Params string
	StoredKey256 []byte
	ServerKey256 []byte
	StoredKey512 []byte
	ServerKey512 []byte
	CreatedAt    time.Time
	Disabled     bool
}

type RosterItem struct {
	Owner        string
	Contact      JID
	Name         string
	Subscription int
	Ask          int
	Groups       []string
	Ver          int64
}

type ArchivedStanza struct {
	ID        int64
	Owner     string
	With      JID
	TS        time.Time
	StanzaID  string
	OriginID  string
	Direction int
	StanzaXML []byte
}

type PEPNode struct {
	Owner       string
	Node        string
	Config      []byte
	AccessModel int
}

type PEPItem struct {
	Owner       string
	Node        string
	ItemID      string
	Publisher   JID
	PublishedAt time.Time
	Payload     []byte
}

type MUCRoom struct {
	JID        JID
	Config     []byte
	CreatedAt  time.Time
	Persistent bool
}

type MUCAffiliation struct {
	RoomJID     JID
	UserJID     JID
	Affiliation int
}

type PushRegistration struct {
	Owner      string
	ServiceJID JID
	Node       string
	FormXML    []byte
	EnabledAt  time.Time
}

type OfflineMessage struct {
	ID      int64
	Owner   string
	TS      time.Time
	Stanza  []byte
	Expires *time.Time
}

type UserStore interface {
	Get(ctx context.Context, username string) (*User, error)
	Put(ctx context.Context, u *User) error
	Delete(ctx context.Context, username string) error
	List(ctx context.Context, limit, offset int) ([]*User, error)
}

type RosterStore interface {
	Get(ctx context.Context, owner string) ([]*RosterItem, int64, error)
	Put(ctx context.Context, item *RosterItem) (int64, error)
	Delete(ctx context.Context, owner string, contact JID) (int64, error)
}

type MAMStore interface {
	Append(ctx context.Context, msg *ArchivedStanza) (int64, error)
	Query(ctx context.Context, owner string, with *JID, before, after *time.Time, limit int) ([]*ArchivedStanza, error)
	Prune(ctx context.Context, owner string, olderThan time.Time) (int, error)
}

type PEPStore interface {
	PutNode(ctx context.Context, node *PEPNode) error
	GetNode(ctx context.Context, owner, node string) (*PEPNode, error)
	DeleteNode(ctx context.Context, owner, node string) error
	PutItem(ctx context.Context, item *PEPItem) error
	GetItem(ctx context.Context, owner, node, itemID string) (*PEPItem, error)
	ListItems(ctx context.Context, owner, node string, limit int) ([]*PEPItem, error)
	DeleteItem(ctx context.Context, owner, node, itemID string) error
}

type MUCStore interface {
	PutRoom(ctx context.Context, room *MUCRoom) error
	GetRoom(ctx context.Context, jid JID) (*MUCRoom, error)
	DeleteRoom(ctx context.Context, jid JID) error
	PutAffiliation(ctx context.Context, a *MUCAffiliation) error
	ListAffiliations(ctx context.Context, roomJID JID) ([]*MUCAffiliation, error)
	ListRooms(ctx context.Context) ([]*MUCRoom, error)
}

type PushStore interface {
	Put(ctx context.Context, reg *PushRegistration) error
	List(ctx context.Context, owner string) ([]*PushRegistration, error)
	Delete(ctx context.Context, owner string, serviceJID JID, node string) error
}

type BlockStore interface {
	List(ctx context.Context, owner string) ([]JID, error)
	Add(ctx context.Context, owner string, blocked JID) error
	Remove(ctx context.Context, owner string, blocked JID) error
	Clear(ctx context.Context, owner string) error
}

type OfflineStore interface {
	Push(ctx context.Context, msg *OfflineMessage) (int64, error)
	Pop(ctx context.Context, owner string, limit int) ([]*OfflineMessage, error)
	Count(ctx context.Context, owner string) (int, error)
}

type Stores struct {
	Users   UserStore
	Roster  RosterStore
	MAM     MAMStore
	PEP     PEPStore
	MUC     MUCStore
	Push    PushStore
	Block   BlockStore
	Offline OfflineStore
}
