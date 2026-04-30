package auth

import (
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
	if !strings.HasPrefix(encoded, "$scrypt$N=") {
		t.Fatalf("unexpected format: %s", encoded)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d: %s", len(parts), encoded)
	}
	if parts[1] != "scrypt" {
		t.Fatalf("expected scrypt identifier, got %q", parts[1])
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

func TestVerifyStoredPasswordInvalidFormat(t *testing.T) {
	_, err := VerifyStoredPassword("notvalid", []byte("pw"))
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}
