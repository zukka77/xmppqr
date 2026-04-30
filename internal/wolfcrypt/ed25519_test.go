package wolfcrypt

import "testing"

func TestEd25519(t *testing.T) {
	pub, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	sig, err := Ed25519Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Ed25519Verify(pub, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid signature failed verification")
	}
	sig[0] ^= 0xff
	ok, _ = Ed25519Verify(pub, msg, sig)
	if ok {
		t.Fatal("bad signature should not verify")
	}
}
