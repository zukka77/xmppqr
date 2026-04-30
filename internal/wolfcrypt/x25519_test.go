package wolfcrypt

import (
	"bytes"
	"testing"
)

func TestX25519(t *testing.T) {
	pubA, privA, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	ssA, err := X25519SharedSecret(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	ssB, err := X25519SharedSecret(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssA, ssB) {
		t.Fatal("shared secrets do not match")
	}
}
