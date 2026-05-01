// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

var ErrUnknownSender                 = errors.New("group: no receiver chain for sender")
var ErrEpochMismatch                 = errors.New("group: header epoch outside accepted range")
var ErrAnnouncementWrongRoom         = errors.New("group: announcement room mismatch")
var ErrAnnouncementUnknownSender     = errors.New("group: announcement sender not a current member")
var ErrGroupAEADFailure              = errors.New("group: AEAD authentication failed")
var ErrAnnouncementFromRemovedMember = errors.New("group: announcement from removed member")
var ErrMessageFromRemovedMember      = errors.New("group: message from removed member")

type SecurityEventKind uint8

const (
	SecurityEventNone                    SecurityEventKind = iota
	SecurityEventMessageFromRemoved
	SecurityEventAnnouncementFromRemoved
	SecurityEventStaleEpoch
)

func (k SecurityEventKind) String() string {
	switch k {
	case SecurityEventMessageFromRemoved:
		return "MessageFromRemoved"
	case SecurityEventAnnouncementFromRemoved:
		return "AnnouncementFromRemoved"
	case SecurityEventStaleEpoch:
		return "StaleEpoch"
	default:
		return fmt.Sprintf("SecurityEventKind(%d)", uint8(k))
	}
}

type SecurityEvent struct {
	Kind           SecurityEventKind
	AIKFingerprint string
	DeviceID       uint32
	Epoch          uint32
	Detail         string
}

type GroupMember struct {
	AIKPub    *AccountIdentityPub
	DeviceIDs []uint32
}

type recvKey struct {
	aikFP    string
	deviceID uint32
	epoch    uint32
}

type GroupSession struct {
	RoomJID    string
	MyAIKPub   *AccountIdentityPub
	MyDeviceID uint32
	Epoch      uint32

	Members     []*GroupMember
	MySend      *SenderChain
	RecvChains  map[recvKey]*SenderChain
	RemovedAIKs map[string]uint32

	pendingSecurityEvents []SecurityEvent
}

func NewGroupSession(roomJID string, myAIKPub *AccountIdentityPub, myDeviceID uint32, members []*GroupMember) (*GroupSession, error) {
	sc, err := NewSenderChain(0)
	if err != nil {
		return nil, err
	}
	return &GroupSession{
		RoomJID:     roomJID,
		MyAIKPub:    myAIKPub,
		MyDeviceID:  myDeviceID,
		Epoch:       0,
		Members:     members,
		MySend:      sc,
		RecvChains:  make(map[recvKey]*SenderChain),
		RemovedAIKs: make(map[string]uint32),
	}, nil
}

func (g *GroupSession) AnnounceSenderChain() *SenderChainAnnouncement {
	ck := make([]byte, 32)
	copy(ck, g.MySend.ChainKey)
	return &SenderChainAnnouncement{
		SenderAIKPub:   g.MyAIKPub,
		SenderDeviceID: g.MyDeviceID,
		RoomJID:        g.RoomJID,
		Epoch:          g.Epoch,
		ChainKey:       ck,
		NextIndex:      g.MySend.NextIndex,
	}
}

func (g *GroupSession) AcceptSenderChain(ann *SenderChainAnnouncement) error {
	if ann.RoomJID != g.RoomJID {
		return ErrAnnouncementWrongRoom
	}
	fp := ann.SenderAIKPub.Fingerprint()
	if _, removed := g.RemovedAIKs[fp]; removed {
		g.pendingSecurityEvents = append(g.pendingSecurityEvents, SecurityEvent{
			Kind:           SecurityEventAnnouncementFromRemoved,
			AIKFingerprint: fp,
			DeviceID:       ann.SenderDeviceID,
			Epoch:          ann.Epoch,
			Detail:         "announcement received after AIK removal",
		})
		return ErrAnnouncementFromRemovedMember
	}
	found := false
	for _, m := range g.Members {
		if m.AIKPub.Equal(ann.SenderAIKPub) {
			found = true
			break
		}
	}
	if !found {
		return ErrAnnouncementUnknownSender
	}
	sc, err := RestoreSenderChain(ann.Epoch, ann.ChainKey, ann.NextIndex)
	if err != nil {
		return err
	}
	k := recvKey{
		aikFP:    fp,
		deviceID: ann.SenderDeviceID,
		epoch:    ann.Epoch,
	}
	g.RecvChains[k] = sc
	return nil
}

func buildNonce(epoch, chainIndex uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce[0:4], []byte("GMSG"))
	binary.BigEndian.PutUint32(nonce[4:8], epoch)
	binary.BigEndian.PutUint32(nonce[8:12], chainIndex)
	return nonce
}

func (g *GroupSession) Encrypt(plaintext []byte) (header *GroupMessageHeader, ciphertext []byte, err error) {
	idx, mk, err := g.MySend.Step()
	if err != nil {
		return nil, nil, err
	}
	h := &GroupMessageHeader{
		Version:        1,
		Epoch:          g.Epoch,
		SenderDeviceID: g.MyDeviceID,
		ChainIndex:     idx,
	}
	aad := append(h.Marshal(), []byte(g.RoomJID)...)
	nonce := buildNonce(g.Epoch, idx)
	aesGCM, err := wolfcrypt.NewAESGCM(mk)
	if err != nil {
		return nil, nil, err
	}
	ct, err := aesGCM.Seal(nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return h, ct, nil
}

func (g *GroupSession) Decrypt(senderAIK *AccountIdentityPub, header *GroupMessageHeader, ciphertext []byte) ([]byte, error) {
	fp := senderAIK.Fingerprint()
	if _, removed := g.RemovedAIKs[fp]; removed {
		g.pendingSecurityEvents = append(g.pendingSecurityEvents, SecurityEvent{
			Kind:           SecurityEventMessageFromRemoved,
			AIKFingerprint: fp,
			DeviceID:       header.SenderDeviceID,
			Epoch:          header.Epoch,
			Detail:         "message received after AIK removal",
		})
		return nil, ErrMessageFromRemovedMember
	}
	if header.Epoch < g.Epoch {
		return nil, ErrEpochMismatch
	}
	k := recvKey{
		aikFP:    fp,
		deviceID: header.SenderDeviceID,
		epoch:    header.Epoch,
	}
	sc, ok := g.RecvChains[k]
	if !ok {
		return nil, ErrUnknownSender
	}
	mk, err := sc.MessageKeyAt(header.ChainIndex)
	if err != nil {
		return nil, err
	}
	aad := append(header.Marshal(), []byte(g.RoomJID)...)
	nonce := buildNonce(header.Epoch, header.ChainIndex)
	aesGCM, err := wolfcrypt.NewAESGCM(mk)
	if err != nil {
		return nil, err
	}
	pt, err := aesGCM.Open(nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrGroupAEADFailure
	}
	return pt, nil
}

func (g *GroupSession) rotateEpoch() error {
	sc, err := NewSenderChain(g.Epoch + 1)
	if err != nil {
		return err
	}
	g.Epoch++
	g.MySend = sc
	return nil
}

func (g *GroupSession) AddMember(m *GroupMember) {
	fp := m.AIKPub.Fingerprint()
	delete(g.RemovedAIKs, fp)
	g.Members = append(g.Members, m)
	_ = g.rotateEpoch()
}

func (g *GroupSession) RemoveMember(aikPub *AccountIdentityPub) {
	fp := aikPub.Fingerprint()
	filtered := g.Members[:0]
	for _, m := range g.Members {
		if !m.AIKPub.Equal(aikPub) {
			filtered = append(filtered, m)
		}
	}
	g.Members = filtered

	for k := range g.RecvChains {
		if k.aikFP == fp {
			delete(g.RecvChains, k)
		}
	}
	_ = g.rotateEpoch()
	g.RemovedAIKs[fp] = g.Epoch
}

func (g *GroupSession) Events() []SecurityEvent {
	out := g.pendingSecurityEvents
	g.pendingSecurityEvents = nil
	return out
}

func (g *GroupSession) IsRemoved(aikPub *AccountIdentityPub) bool {
	_, ok := g.RemovedAIKs[aikPub.Fingerprint()]
	return ok
}

func (g *GroupSession) CurrentMembers() []*GroupMember {
	out := make([]*GroupMember, len(g.Members))
	copy(out, g.Members)
	return out
}
