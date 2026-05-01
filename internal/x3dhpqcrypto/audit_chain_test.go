// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"testing"
)

func makeAuditChain(t *testing.T, aik *AccountIdentityKey, n int) []*AuditEntry {
	t.Helper()
	entries := make([]*AuditEntry, n)
	var prev *AuditEntry
	ts := int64(1000000)
	for i := 0; i < n; i++ {
		action := AuditAction(uint8(i%4) + 1)
		e, err := aik.AppendAudit(prev, action, []byte("payload"), ts)
		if err != nil {
			t.Fatalf("AppendAudit[%d]: %v", i, err)
		}
		entries[i] = e
		prev = e
		ts++
	}
	return entries
}

func TestAppendGenesis(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e, err := aik.AppendAudit(nil, AuditActionAddDevice, []byte("genesis"), 1000)
	if err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	var zeroHash [32]byte
	if e.PrevHash != zeroHash {
		t.Error("genesis PrevHash must be all-zero")
	}
	if e.Seq != 0 {
		t.Errorf("genesis Seq must be 0, got %d", e.Seq)
	}
	if err := e.Verify(aik.Public()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	h := e.Hash()
	var zeroH [32]byte
	if h == zeroH {
		t.Error("Hash() must not be all-zero")
	}
}

func TestAppendChain(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 5)
	if err := VerifyChain(entries, aik.Public()); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestAuditVerifyWrongAIKFails(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 3)
	if err := VerifyChain(entries, other.Public()); err == nil {
		t.Fatal("expected error against wrong AIK")
	}
}

func TestVerifyChainCatchesBrokenLink(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 5)
	var zeroHash [32]byte
	entries[2].PrevHash = zeroHash

	err = VerifyChain(entries, aik.Public())
	if err == nil {
		t.Fatal("expected chain error")
	}
	if err != ErrAuditBadSig && err != ErrAuditBadChain {
		t.Fatalf("expected ErrAuditBadChain (or bad sig due to tamper), got: %v", err)
	}
}

func TestVerifyChainCatchesSeqGap(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 5)
	entries[3].Seq = 5

	err = VerifyChain(entries, aik.Public())
	if err != ErrAuditBadSeq && err != ErrAuditBadSig {
		t.Fatalf("expected ErrAuditBadSeq, got: %v", err)
	}
}

func TestVerifyChainCatchesGenesis(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 3)
	entries[0].PrevHash = [32]byte{0xFF}

	err = VerifyChain(entries, aik.Public())
	if err == nil {
		t.Fatal("expected error on bad genesis")
	}
	if err != ErrAuditBadGenesis && err != ErrAuditBadSig {
		t.Fatalf("expected ErrAuditBadGenesis (or bad sig), got: %v", err)
	}
}

func TestVerifyChainCatchesTimestampRegress(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries := makeAuditChain(t, aik, 5)
	entries[3].Timestamp = entries[2].Timestamp - 1

	err = VerifyChain(entries, aik.Public())
	if err != ErrAuditTimestampRegress && err != ErrAuditBadSig {
		t.Fatalf("expected ErrAuditTimestampRegress, got: %v", err)
	}
}

func TestPayloadAddDeviceRoundTrip(t *testing.T) {
	aik, _ := GenerateAccountIdentity()
	dik, _ := GenerateDeviceIdentity()
	dc, err := aik.IssueDeviceCert(dik, 42, DeviceFlagPrimary)
	if err != nil {
		t.Fatal(err)
	}
	payload := PayloadAddDevice(42, dc)
	if len(payload) < 8 {
		t.Fatal("payload too short")
	}

	deviceID := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if deviceID != 42 {
		t.Errorf("device_id mismatch: got %d", deviceID)
	}
	certLen := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if int(certLen) != len(dc.Marshal()) {
		t.Errorf("cert_len mismatch: got %d want %d", certLen, len(dc.Marshal()))
	}
	dc2, err := UnmarshalDeviceCert(payload[8 : 8+certLen])
	if err != nil {
		t.Fatalf("UnmarshalDeviceCert: %v", err)
	}
	if dc2.DeviceID != dc.DeviceID {
		t.Errorf("cert DeviceID mismatch")
	}
	if err := dc2.Verify(aik.Public()); err != nil {
		t.Fatalf("cert verify: %v", err)
	}
}

func TestRotateAIKEntry(t *testing.T) {
	oldAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newAIK, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	payload := PayloadRotateAIK(newAIK.Public())
	e, err := oldAIK.AppendAudit(nil, AuditActionRotateAIK, payload, 1000)
	if err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := e.Verify(oldAIK.Public()); err != nil {
		t.Fatalf("Verify against OLD AIK: %v", err)
	}
	if err := e.Verify(newAIK.Public()); err == nil {
		t.Fatal("expected verify to fail against NEW AIK")
	}
}

func TestAuditMarshalRoundTrip(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e, err := aik.AppendAudit(nil, AuditActionAddDevice, []byte("some payload"), 9999)
	if err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	b := e.Marshal()
	e2, err := UnmarshalAuditEntry(b)
	if err != nil {
		t.Fatalf("UnmarshalAuditEntry: %v", err)
	}
	if e2.Seq != e.Seq {
		t.Errorf("Seq mismatch")
	}
	if e2.PrevHash != e.PrevHash {
		t.Errorf("PrevHash mismatch")
	}
	if e2.Action != e.Action {
		t.Errorf("Action mismatch")
	}
	if e2.Timestamp != e.Timestamp {
		t.Errorf("Timestamp mismatch")
	}
	if err := e2.Verify(aik.Public()); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}
