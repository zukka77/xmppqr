package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// RFC 7677 Appendix B test vectors for SCRAM-SHA-256
const (
	rfc7677ClientNonce    = "rOprNGfwEbeRWgbNEkqO"
	rfc7677ServerNonce    = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	rfc7677SaltB64        = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfc7677Iter           = 4096
	rfc7677ClientProofB64 = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfc7677ServerSigB64   = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	rfc7677StoredKeyHex   = "586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6"
	rfc7677ServerKeyHex   = "c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5"

	// Precomputed for SCRAM-SHA-256-PLUS with cbData="fake-tls-exporter-bytes-1234", cbType="tls-exporter"
	plusCBData         = "fake-tls-exporter-bytes-1234"
	plusClientProofB64 = "W+GETgleBxzkiJO8QTgeyzA3gz57sn1rEXNh8n6smgc="
	plusServerSigB64   = "hozawrhEGHzmCWmVrj3pPDv46ADlRmd8eHt2lU47zoI="
)

func mustHexDecode(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		fmt.Sscanf(s[i:i+2], "%02x", &v)
		b[i/2] = v
	}
	return b
}

func rfc7677Creds() *StoredCreds {
	salt, _ := base64.StdEncoding.DecodeString(rfc7677SaltB64)
	return &StoredCreds{
		Salt:      salt,
		Iter:      rfc7677Iter,
		StoredKey: mustHexDecode(rfc7677StoredKeyHex),
		ServerKey: mustHexDecode(rfc7677ServerKeyHex),
	}
}

func lookup(_ string) (*StoredCreds, error) { return rfc7677Creds(), nil }

func newFixed(t *testing.T, mech Mechanism, cb ChannelBinding) *Server {
	t.Helper()
	s, err := NewServer(mech, lookup, cb)
	if err != nil {
		t.Fatal(err)
	}
	s.serverNonce = rfc7677ServerNonce
	return s
}

func TestSCRAMSHA256RFC7677(t *testing.T) {
	s := newFixed(t, SCRAMSHA256, nil)

	clientFirst := "n,,n=user,r=" + rfc7677ClientNonce
	serverFirst, done, err := s.Step([]byte(clientFirst))
	if err != nil {
		t.Fatalf("step1: %v", err)
	}
	if done {
		t.Fatal("step1: expected not done")
	}
	wantServerFirst := fmt.Sprintf("r=%s%s,s=%s,i=%d",
		rfc7677ClientNonce, rfc7677ServerNonce, rfc7677SaltB64, rfc7677Iter)
	if string(serverFirst) != wantServerFirst {
		t.Fatalf("server-first\ngot  %s\nwant %s", serverFirst, wantServerFirst)
	}

	cbindB64 := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinal := fmt.Sprintf("c=%s,r=%s%s,p=%s",
		cbindB64, rfc7677ClientNonce, rfc7677ServerNonce, rfc7677ClientProofB64)
	serverFinal, done, err := s.Step([]byte(clientFinal))
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	if !done {
		t.Fatal("step2: expected done")
	}
	if string(serverFinal) != "v="+rfc7677ServerSigB64 {
		t.Fatalf("server-final\ngot  %s\nwant %s", serverFinal, "v="+rfc7677ServerSigB64)
	}
	if s.Username() != "user" {
		t.Fatalf("username: %q", s.Username())
	}
}

type fakeCB struct{ cbType string; data []byte }

func (f *fakeCB) Type() string { return f.cbType }
func (f *fakeCB) Data() []byte { return f.data }

func TestSCRAMSHA256PlusChannelBinding(t *testing.T) {
	cb := &fakeCB{cbType: "tls-exporter", data: []byte(plusCBData)}
	s := newFixed(t, SCRAMSHA256Plus, cb)

	gs2Header := "p=tls-exporter,,"
	cbindInput := append([]byte(gs2Header), cb.data...)
	cbindB64 := base64.StdEncoding.EncodeToString(cbindInput)

	clientFirst := "p=tls-exporter,,n=user,r=" + rfc7677ClientNonce
	_, _, err := s.Step([]byte(clientFirst))
	if err != nil {
		t.Fatalf("step1: %v", err)
	}

	clientFinal := fmt.Sprintf("c=%s,r=%s%s,p=%s",
		cbindB64, rfc7677ClientNonce, rfc7677ServerNonce, plusClientProofB64)
	serverFinal, done, err := s.Step([]byte(clientFinal))
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	if !done {
		t.Fatal("expected done")
	}
	if string(serverFinal) != "v="+plusServerSigB64 {
		t.Fatalf("server-final\ngot  %s\nwant v=%s", serverFinal, plusServerSigB64)
	}

	// Wrong binding data must fail
	s2 := newFixed(t, SCRAMSHA256Plus, cb)
	s2.Step([]byte(clientFirst)) //nolint
	wrongInput := append([]byte(gs2Header), []byte("wrong-data")...)
	wrongB64 := base64.StdEncoding.EncodeToString(wrongInput)
	wrongFinal := fmt.Sprintf("c=%s,r=%s%s,p=%s",
		wrongB64, rfc7677ClientNonce, rfc7677ServerNonce, plusClientProofB64)
	_, _, err = s2.Step([]byte(wrongFinal))
	if err == nil {
		t.Fatal("expected failure with wrong channel binding")
	}
}

func TestSCRAMDowngradeProtection(t *testing.T) {
	advertised := []string{"SCRAM-SHA-512", "SCRAM-SHA-256"}
	s := newFixed(t, SCRAMSHA256, nil)
	s.BindMechanismList(advertised)

	s.Step([]byte("n,,n=user,r=" + rfc7677ClientNonce)) //nolint

	// Client sends hash for a reduced list (downgrade attempt)
	attackHash := ComputeMechanismListHash([]string{"SCRAM-SHA-256"})
	attackHashB64 := base64.StdEncoding.EncodeToString(attackHash)
	cbindB64 := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinal := fmt.Sprintf("c=%s,r=%s%s,h=%s,p=%s",
		cbindB64, rfc7677ClientNonce, rfc7677ServerNonce, attackHashB64, rfc7677ClientProofB64)
	_, _, err := s.Step([]byte(clientFinal))
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected downgrade error, got: %v", err)
	}
}

func TestDeriveSCRAMCredsReproducible(t *testing.T) {
	salt := []byte("testsalt1234")
	a, err := DeriveSCRAMCreds([]byte("mypassword"), salt, 4096, SCRAMSHA256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSCRAMCreds([]byte("mypassword"), salt, 4096, SCRAMSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.StoredKey, b.StoredKey) || !bytes.Equal(a.ServerKey, b.ServerKey) {
		t.Fatal("DeriveSCRAMCreds not reproducible")
	}

	c, err := DeriveSCRAMCreds([]byte("otherpassword"), salt, 4096, SCRAMSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.StoredKey, c.StoredKey) {
		t.Fatal("different passwords yielded same StoredKey")
	}
}
