package stanza

import (
	"strings"
	"testing"
)

func TestJIDParseBare(t *testing.T) {
	j, err := Parse("user@example.com")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if j.Local != "user" || j.Domain != "example.com" || j.Resource != "" {
		t.Errorf("got %+v", j)
	}
	if j.String() != "user@example.com" {
		t.Errorf("String=%q", j.String())
	}
	if !j.IsBare() {
		t.Error("expected IsBare")
	}
}

func TestJIDParseFull(t *testing.T) {
	j, err := Parse("user@example.com/phone")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if j.Local != "user" || j.Domain != "example.com" || j.Resource != "phone" {
		t.Errorf("got %+v", j)
	}
	if j.String() != "user@example.com/phone" {
		t.Errorf("String=%q", j.String())
	}
	if j.IsBare() {
		t.Error("expected not IsBare")
	}
}

func TestJIDDomainOnly(t *testing.T) {
	j, err := Parse("example.com")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if j.Domain != "example.com" || j.Local != "" || j.Resource != "" {
		t.Errorf("got %+v", j)
	}
}

func TestJIDResourceWithSlash(t *testing.T) {
	// Resource is everything after the first slash.
	j, err := Parse("user@example.com/res/with/slashes")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if j.Resource != "res/with/slashes" {
		t.Errorf("Resource=%q", j.Resource)
	}
}

func TestJIDEmptyDomain(t *testing.T) {
	_, err := Parse("user@")
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestJIDEqual(t *testing.T) {
	j1, _ := Parse("user@example.com/phone")
	j2, _ := Parse("user@example.com/phone")
	j3, _ := Parse("user@example.com/tablet")
	if !j1.Equal(j2) {
		t.Error("expected equal")
	}
	if j1.Equal(j3) {
		t.Error("expected not equal")
	}
}

func TestJIDBare(t *testing.T) {
	j, _ := Parse("user@example.com/phone")
	b := j.Bare()
	if b.Resource != "" {
		t.Errorf("Bare has resource: %q", b.Resource)
	}
	if b.String() != "user@example.com" {
		t.Errorf("Bare.String=%q", b.String())
	}
}

func TestJIDOversized(t *testing.T) {
	big := strings.Repeat("a", 1024)
	_, err := Parse(big + "@example.com")
	if err == nil {
		t.Fatal("expected error for oversized local part")
	}
}

func TestJIDIDNDomain(t *testing.T) {
	// Internationalized domain — parsing should succeed (no IDN processing required by spec at this layer).
	j, err := Parse("user@münchen.de")
	if err != nil {
		t.Fatalf("Parse IDN domain: %v", err)
	}
	if j.Domain != "münchen.de" {
		t.Errorf("Domain=%q", j.Domain)
	}
}
