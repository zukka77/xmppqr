package wolfcrypt

import (
	"bytes"
	"testing"
)

func TestHKDFRoundTrip(t *testing.T) {
	salt := []byte("test-salt")
	ikm := []byte("input-keying-material")
	prk, err := HKDFExtract(salt, ikm)
	if err != nil {
		t.Fatal(err)
	}
	if len(prk) == 0 {
		t.Fatal("empty prk")
	}
	okm1, err := HKDFExpand(prk, []byte("info1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	okm2, err := HKDFExpand(prk, []byte("info2"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(okm1, okm2) {
		t.Fatal("different info should yield different okm")
	}
	okm1b, err := HKDFExpand(prk, []byte("info1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm1, okm1b) {
		t.Fatal("same inputs should yield same okm")
	}
}
