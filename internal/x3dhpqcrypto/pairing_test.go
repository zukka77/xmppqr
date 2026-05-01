// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpqcrypto

import (
	"bytes"
	"testing"
)

func runPairing(t *testing.T, e *PairingExisting, n *PairingNew) (*PairingResult, error) {
	t.Helper()

	// Step 1: E sends PAKE1
	eOut, eDone, err := e.Step(nil)
	if err != nil {
		return nil, err
	}
	if eDone {
		t.Fatal("E done too early after PAKE1")
	}

	// Step 2: N receives PAKE1, sends PAKE2
	nOut, nDone, err := n.Step(eOut)
	if err != nil {
		return nil, err
	}
	if nDone {
		t.Fatal("N done too early after PAKE2")
	}

	// Step 3: E receives PAKE2, sends ConfirmE
	eOut, eDone, err = e.Step(nOut)
	if err != nil {
		return nil, err
	}
	if eDone {
		t.Fatal("E done too early after ConfirmE")
	}

	// Step 4: N receives ConfirmE, sends ConfirmN
	nOut, nDone, err = n.Step(eOut)
	if err != nil {
		return nil, err
	}
	if nDone {
		t.Fatal("N done too early after ConfirmN")
	}

	// Step 5: E receives ConfirmN, verifies, returns nil (waiting for N's DIK)
	eOut, eDone, err = e.Step(nOut)
	if err != nil {
		return nil, err
	}
	if eDone {
		t.Fatal("E done too early after ConfirmN verify")
	}
	if eOut != nil {
		t.Fatal("E should return nil out after ConfirmN verify")
	}

	// Step 6: N sends DIK_pub (eOut is nil, that's fine)
	nOut, nDone, err = n.Step(eOut)
	if err != nil {
		return nil, err
	}
	if nDone {
		t.Fatal("N done too early after sending DIK")
	}

	// Step 7: E receives DIK, issues DC, sends payload
	eOut, eDone, err = e.Step(nOut)
	if err != nil {
		return nil, err
	}
	if eDone {
		t.Fatal("E done too early after sending payload")
	}

	// Step 8: N receives payload, decrypts, sends ACK, done
	nOut, nDone, err = n.Step(eOut)
	if err != nil {
		return nil, err
	}
	if !nDone {
		t.Fatal("N should be done after ACK")
	}

	// Step 9: E receives ACK, done
	_, eDone, err = e.Step(nOut)
	if err != nil {
		return nil, err
	}
	if !eDone {
		t.Fatal("E should be done after ACK")
	}

	return n.Result(), nil
}

func TestPairingHappyPath(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("test-session-id-1")

	e, err := NewPairingExisting(aik, code, sid, PairingOptions{NewDeviceID: 42})
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewPairingNew(dik, code, sid)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runPairing(t, e, n)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Cert == nil {
		t.Fatal("cert is nil")
	}
	if result.AIKPub == nil {
		t.Fatal("AIKPub is nil")
	}
	if result.AIKPriv != nil {
		t.Fatal("AIKPriv should be nil when SharePrimary=false")
	}
	if !bytes.Equal(result.AIKPub.PubEd25519, aik.Public().PubEd25519) {
		t.Fatal("AIKPub mismatch")
	}
	if result.Cert.DeviceID != 42 {
		t.Fatalf("expected DeviceID=42 got %d", result.Cert.DeviceID)
	}
	if err := result.Cert.Verify(result.AIKPub); err != nil {
		t.Fatalf("cert verification failed: %v", err)
	}
	if e.IssuedCert() == nil {
		t.Fatal("E.IssuedCert() is nil")
	}
	if e.IssuedCert().DeviceID != 42 {
		t.Fatalf("E.IssuedCert() device ID mismatch")
	}
}

func TestPairingHappyPathSharePrimary(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("test-session-id-2")

	e, err := NewPairingExisting(aik, code, sid, PairingOptions{
		NewDeviceID:  7,
		SharePrimary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewPairingNew(dik, code, sid)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runPairing(t, e, n)
	if err != nil {
		t.Fatal(err)
	}

	if result.AIKPriv == nil {
		t.Fatal("AIKPriv should be non-nil when SharePrimary=true")
	}
	if !bytes.Equal(result.AIKPriv.PubEd25519, aik.Public().PubEd25519) {
		t.Fatal("AIKPriv.PubEd25519 mismatch")
	}
	if result.Cert.Flags&DeviceFlagPrimary == 0 {
		t.Fatal("cert should have DeviceFlagPrimary set")
	}
}

func TestPairingWrongCode(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}

	sid := []byte("test-session-id-3")

	e, err := NewPairingExisting(aik, "1234567890", sid, PairingOptions{NewDeviceID: 1})
	if err != nil {
		t.Fatal(err)
	}
	// N uses a different code (will pass Luhn check for simplicity — just use a valid but different code)
	n, err := NewPairingNew(dik, "0000000000", sid)
	if err != nil {
		t.Fatal(err)
	}

	// PAKE1
	eOut, _, err := e.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	// PAKE2
	nOut, _, err := n.Step(eOut)
	if err != nil {
		t.Fatal(err)
	}
	// E sends ConfirmE
	eOut, _, err = e.Step(nOut)
	if err != nil {
		t.Fatal(err)
	}
	// N receives ConfirmE — should fail because keys differ
	nOut, _, err = n.Step(eOut)
	if err == ErrPairingAuth {
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// If N didn't fail, E should fail when verifying ConfirmN
	_, _, err = e.Step(nOut)
	if err != ErrPairingAuth {
		t.Fatalf("expected ErrPairingAuth, got %v", err)
	}
}

func TestPairingTamperedPayload(t *testing.T) {
	aik, err := GenerateAccountIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dik, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("test-session-id-4")

	e, err := NewPairingExisting(aik, code, sid, PairingOptions{NewDeviceID: 3})
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewPairingNew(dik, code, sid)
	if err != nil {
		t.Fatal(err)
	}

	eOut, _, _ := e.Step(nil)
	nOut, _, _ := n.Step(eOut)
	eOut, _, _ = e.Step(nOut)
	nOut, _, _ = n.Step(eOut)
	eOut, _, _ = e.Step(nOut)
	nOut, _, _ = n.Step(eOut)
	eOut, _, _ = e.Step(nOut)

	// tamper with E's issuance payload
	if len(eOut.Payload) > 0 {
		eOut.Payload[len(eOut.Payload)/2] ^= 0xff
	}

	_, _, err = n.Step(eOut)
	if err == nil {
		t.Fatal("expected error on tampered payload, got nil")
	}
}

func TestPairingCodeRoundTrip(t *testing.T) {
	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 10 {
		t.Fatalf("expected 10-digit code, got %d digits", len(code))
	}
	formatted := FormatPairingCode(code)
	parsed, err := ParsePairingCode(formatted)
	if err != nil {
		t.Fatalf("ParsePairingCode(%q) error: %v", formatted, err)
	}
	if parsed != code {
		t.Fatalf("round-trip mismatch: got %q want %q", parsed, code)
	}
}

func TestPairingCodeBadChecksum(t *testing.T) {
	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	last := code[9]
	var bad byte
	if last == '9' {
		bad = '0'
	} else {
		bad = last + 1
	}
	corrupted := code[:9] + string(bad)
	_, err = ParsePairingCode(corrupted)
	if err != ErrPairingCodeBadCheck {
		t.Fatalf("expected ErrPairingCodeBadCheck, got %v", err)
	}
}

func TestLuhnVectors(t *testing.T) {
	tests := []struct {
		digits string
		want   byte
	}{
		{"123456789", '7'},
		{"000000000", '0'},
		{"999999999", '9'},
	}
	for _, tc := range tests {
		got, err := LuhnCheck(tc.digits)
		if err != nil {
			t.Fatalf("LuhnCheck(%q) error: %v", tc.digits, err)
		}
		if got != tc.want {
			t.Fatalf("LuhnCheck(%q) = %c, want %c", tc.digits, got, tc.want)
		}
	}
}
