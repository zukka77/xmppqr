// SPDX-License-Identifier: AGPL-3.0-or-later
// Test vectors for XEP-XQR Appendix A.
// All inputs are fixed/deterministic; outputs are locked in here so an
// external implementer can verify against this reference.
package x3dhpqcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

// fixedEd25519Pub is a hardcoded 32-byte Ed25519 public key used as a test fixture.
// It is NOT a valid key pair — it is used only for deterministic encoding tests.
var fixedEd25519Pub = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// A.1 — AIK fingerprint computation (hybrid, Wave 20).
// Input: PubEd25519 = 0x0102…0x20 (32 bytes),
//        PubMLDSA   = 0xA5 x 1952 bytes (fixed test pattern, NOT a real ML-DSA-65 key).
// Fingerprint = hex(BLAKE2b-160(Marshal())[:15]) in 6 groups of 5.
// Marshal() encoding: uint16(1) | uint8(1) | 32-byte Ed25519 pub | 1952-byte ML-DSA-65 pub
//   total 1987 bytes.
const wantAIKFingerprint = "7AD37 1A1A3 67A62 B6533 1BC5A 2204C"

func TestVectorA1_AIKFingerprint(t *testing.T) {
	fixedMLDSAPub := bytes.Repeat([]byte{0xA5}, wolfcrypt.MLDSA65PubSize)
	pub := &AccountIdentityPub{
		PubEd25519: fixedEd25519Pub,
		PubMLDSA:   fixedMLDSAPub,
	}
	got := pub.Fingerprint()
	if got != wantAIKFingerprint {
		t.Errorf("A.1 AIK fingerprint\n got  %q\n want %q", got, wantAIKFingerprint)
	}
}

// A.2 — DeviceCertificate SignedPart with fixed inputs.
// Inputs:
//
//	Version=1, DeviceID=0xDEADBEEF,
//	DIKPubEd25519 = fixedEd25519Pub (32 bytes),
//	DIKPubX25519  = 0x21..0x40 (32 bytes),
//	DIKPubMLDSA   = nil (len=0),
//	CreatedAt     = 1714483200 (0x000000006630f000 big-endian),
//	Flags         = 0x01
//
// Wire layout: uint16(ver) uint32(id) uint16(ed_len) <ed> uint16(x25519_len) <x25519>
//
//	uint16(mldsa_len=0) int64(created_at) uint8(flags)
const wantDCSignedPartHex = "" +
	"0001" + "deadbeef" +
	"0020" + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"0020" + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
	"0000" +
	"000000006630f000" +
	"01"

func TestVectorA2_DCSignedPart(t *testing.T) {
	dikX25519 := make([]byte, 32)
	for i := range dikX25519 {
		dikX25519[i] = byte(0x21 + i)
	}
	dc := &DeviceCertificate{
		Version:       1,
		DeviceID:      0xDEADBEEF,
		DIKPubEd25519: fixedEd25519Pub,
		DIKPubX25519:  dikX25519,
		DIKPubMLDSA:   nil,
		CreatedAt:     1714483200,
		Flags:         0x01,
	}
	got := hex.EncodeToString(dc.SignedPart())
	if got != wantDCSignedPartHex {
		t.Errorf("A.2 DC SignedPart\n got  %s\n want %s", got, wantDCSignedPartHex)
	}
}

// A.3 — Sender chain step (chainStep).
// Input CK: 0xAA x32.
// MK     = HMAC-SHA-256(CK, 0x01)
// nextCK = HMAC-SHA-256(CK, 0x02)
const (
	wantMKHex     = "790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e"
	wantNextCKHex = "e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e"
)

func TestVectorA3_SenderChainStep(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = 0xAA
	}
	mk, nextCK, err := chainStep(ck)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(mk) != wantMKHex {
		t.Errorf("A.3 MK\n got  %s\n want %s", hex.EncodeToString(mk), wantMKHex)
	}
	if hex.EncodeToString(nextCK) != wantNextCKHex {
		t.Errorf("A.3 nextCK\n got  %s\n want %s", hex.EncodeToString(nextCK), wantNextCKHex)
	}
}

// A.4 — AuditEntry SignedPart with fixed inputs.
// Seq=7, PrevHash=0x55 x32, Action=AuditActionAddDevice(1),
// Payload=0x0000012300000006DEADBEEF0001 (14 bytes),
// Timestamp=1714483200
//
// Wire layout: prefix(16) seq(8) prevHash(32) action(1) payloadLen(4) payload(14) ts(8)
const wantAuditSignedPartHex = "" +
	"5833444850512d41756469742d763100" + // "X3DHPQ-Audit-v1\x00"
	"0000000000000007" + // seq = 7
	"5555555555555555555555555555555555555555555555555555555555555555" + // prevHash
	"01" + // action = AuditActionAddDevice
	"0000000e" + // payload length = 14
	"0000012300000006deadbeef0001" + // payload
	"000000006630f000" // timestamp

func TestVectorA4_AuditSignedPart(t *testing.T) {
	var prevHash [32]byte
	for i := range prevHash {
		prevHash[i] = 0x55
	}
	payload := []byte{
		0x00, 0x00, 0x01, 0x23, // device_id = 0x00000123
		0x00, 0x00, 0x00, 0x06, // cert_len = 6
		0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, // fake cert bytes
	}
	entry := &AuditEntry{
		Seq:       7,
		PrevHash:  prevHash,
		Action:    AuditActionAddDevice,
		Payload:   payload,
		Timestamp: 1714483200,
	}
	got := hex.EncodeToString(entry.SignedPart())
	if got != wantAuditSignedPartHex {
		t.Errorf("A.4 Audit SignedPart\n got  %s\n want %s", got, wantAuditSignedPartHex)
	}
}

// A.5 — KEM checkpoint mix (kemCheckpointMix) with fixed inputs.
// senderCK    = 0xBB x32
// kemSS       = 0xCC x32
// senderDH    = fixedEd25519Pub (0x01..0x20)
// kemCT       = 0xDD x16
// epoch       = 42
// prevHistory = 0x00 x32
const (
	wantKEMNewCKs     = "a69de60e57332f72590af362634ee57f3002644a7d4a6fd86b2146dcaf3d24a7"
	wantKEMNewCKr     = "fdb1f3d1eb083c9049170245004401f1649eae82d7d14620bdd64d717c39dce2"
	wantKEMNewHistory = "3cd70ff3b328c19fb5cb767d31e3e11e8c01e2860393fadd5bb7d3e689c1e10e"
)

func TestVectorA5_KEMCheckpointMix(t *testing.T) {
	senderCK := make([]byte, 32)
	for i := range senderCK {
		senderCK[i] = 0xBB
	}
	kemSS := make([]byte, 32)
	for i := range kemSS {
		kemSS[i] = 0xCC
	}
	senderDH := fixedEd25519Pub
	kemCT := make([]byte, 16)
	for i := range kemCT {
		kemCT[i] = 0xDD
	}
	prevHistory := make([]byte, 32) // all zeros

	newCKs, newCKr, newHistory, err := kemCheckpointMix(senderCK, kemSS, senderDH, kemCT, 42, prevHistory)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(newCKs) != wantKEMNewCKs {
		t.Errorf("A.5 newCKs\n got  %s\n want %s", hex.EncodeToString(newCKs), wantKEMNewCKs)
	}
	if hex.EncodeToString(newCKr) != wantKEMNewCKr {
		t.Errorf("A.5 newCKr\n got  %s\n want %s", hex.EncodeToString(newCKr), wantKEMNewCKr)
	}
	if hex.EncodeToString(newHistory) != wantKEMNewHistory {
		t.Errorf("A.5 newHistory\n got  %s\n want %s", hex.EncodeToString(newHistory), wantKEMNewHistory)
	}
}
