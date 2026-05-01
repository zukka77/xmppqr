package auth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHashAndVerifyRoundTrip(t *testing.T) {
	encoded, err := HashPasswordForStorage([]byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyStoredPassword(encoded, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("correct password should verify")
	}

	ok, err = VerifyStoredPassword(encoded, []byte("wrongpassword"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password should not verify")
	}
}

func TestHashPasswordForStorageFormat(t *testing.T) {
	encoded, err := HashPasswordForStorage([]byte("testpw"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "{") {
		t.Fatalf("unexpected format: %s", encoded)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(encoded), &doc); err != nil {
		t.Fatalf("expected json encoding: %v", err)
	}
	if doc["kdf"] != "scrypt" {
		t.Fatalf("expected scrypt identifier, got %v", doc["kdf"])
	}

	// Two hashes of same password must differ (random salt)
	encoded2, err := HashPasswordForStorage([]byte("testpw"))
	if err != nil {
		t.Fatal(err)
	}
	if encoded == encoded2 {
		t.Fatal("two hashes of same password should differ (random salt)")
	}
}

func TestParseEncodedLegacyFormat(t *testing.T) {
	legacy := "$scrypt$N=32768,r=8,p=1$dGVzdHNhbHR0ZXN0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg"
	n, r, p, salt, hash, err := parseEncoded(legacy)
	if err != nil {
		t.Fatalf("legacy parse failed: %v", err)
	}
	if n != 32768 || r != 8 || p != 1 {
		t.Fatalf("unexpected params: n=%d r=%d p=%d", n, r, p)
	}
	if len(salt) == 0 || len(hash) == 0 {
		t.Fatal("expected decoded salt and hash")
	}
}

func TestVerifyStoredPasswordInvalidFormat(t *testing.T) {
	_, err := VerifyStoredPassword("notvalid", []byte("pw"))
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}
