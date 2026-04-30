package wolfcrypt

import (
	"bytes"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	a, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	plaintext := []byte("hello, wolfcrypt!")
	aad := []byte("additional data")
	ct, err := a.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := a.Open(nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted mismatch: %s", pt)
	}
}

func TestAESGCMTamper(t *testing.T) {
	key := make([]byte, 32)
	a, _ := NewAESGCM(key)
	nonce := make([]byte, 12)
	ct, _ := a.Seal(nonce, []byte("secret"), nil)
	ct[0] ^= 0xff
	_, err := a.Open(nonce, ct, nil)
	if err == nil {
		t.Fatal("expected error on tampered ciphertext")
	}
}
