package wolfcrypt

import (
	"encoding/hex"
	"testing"
)

func TestSHA256Empty(t *testing.T) {
	got := SHA256([]byte{})
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("got %x", got)
	}
}

func TestSHA512Empty(t *testing.T) {
	got := SHA512([]byte{})
	want := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("got %x", got)
	}
}
