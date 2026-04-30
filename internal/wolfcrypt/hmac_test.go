package wolfcrypt

import (
	"encoding/hex"
	"testing"
)

// RFC 4231 Test Case 1
func TestHMACSHA256RFC4231TC1(t *testing.T) {
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	msg := []byte("Hi There")
	got, err := HMACSHA256(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x", got)
	}
}

func TestHMACSHA512RFC4231TC1(t *testing.T) {
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	msg := []byte("Hi There")
	got, err := HMACSHA512(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	want := "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x", got)
	}
}
