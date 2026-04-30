package wolfcrypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestScryptRFC7914(t *testing.T) {
	// RFC 7914 §12 test vector: password="password", salt="NaCl", N=1024, r=8, p=16, dkLen=64
	expected, _ := hex.DecodeString(
		"fdbabe1c9d3472007856e7190d01e9fe" +
			"7c6ad7cbc8237830e77376634b373162" +
			"2eaf30d92e22a3886ff109279d9830da" +
			"c727afb94a83ee6d8360cbdfa2cc0640",
	)
	out, err := Scrypt([]byte("password"), []byte("NaCl"), 1024, 8, 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Fatalf("got %x\nwant %x", out, expected)
	}
}

func TestScryptRoundTrip(t *testing.T) {
	a, err := Scrypt([]byte("secret"), []byte("saltsalt"), 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Scrypt([]byte("secret"), []byte("saltsalt"), 1024, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs must produce same output")
	}
}
