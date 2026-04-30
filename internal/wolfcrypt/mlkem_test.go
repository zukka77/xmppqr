package wolfcrypt

import (
	"bytes"
	"testing"
)

func TestMLKEM768(t *testing.T) {
	pub, priv, err := GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	ct, ssEnc, err := MLKEM768Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	ssDec, err := MLKEM768Decapsulate(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("shared secrets do not match")
	}

	_, privB, _ := GenerateMLKEM768()
	ssBad, err := MLKEM768Decapsulate(privB, ct)
	if err == nil && bytes.Equal(ssBad, ssEnc) {
		t.Fatal("wrong private key should not produce matching shared secret")
	}
}
