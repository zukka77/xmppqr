package ibr

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func makeGetIQ(id string) *stanza.IQ {
	payload := []byte(`<query xmlns='jabber:iq:register'/>`)
	return &stanza.IQ{ID: id, Type: stanza.IQGet, Payload: payload}
}

func makeSetIQ(id, username, password string) *stanza.IQ {
	payload := []byte(fmt.Sprintf(
		`<query xmlns='jabber:iq:register'><username>%s</username><password>%s</password></query>`,
		username, password,
	))
	return &stanza.IQ{ID: id, Type: stanza.IQSet, Payload: payload}
}

func TestRegisterGetForm(t *testing.T) {
	stores := memstore.New()
	svc := New(stores, "example.com", true)

	raw, err := svc.HandleIQ(context.Background(), makeGetIQ("1"))
	if err != nil {
		t.Fatalf("HandleIQ get: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "instructions") {
		t.Errorf("expected instructions element; got: %s", s)
	}
	if !strings.Contains(s, "<username") {
		t.Errorf("expected username element; got: %s", s)
	}
	if !strings.Contains(s, "<password") {
		t.Errorf("expected password element; got: %s", s)
	}
}

func TestRegisterCreatesUser(t *testing.T) {
	stores := memstore.New()
	svc := New(stores, "example.com", true)

	raw, err := svc.HandleIQ(context.Background(), makeSetIQ("2", "newuser", "s3cr3tpass"))
	if err != nil {
		t.Fatalf("HandleIQ set: %v", err)
	}
	if !bytes.Contains(raw, []byte("result")) {
		t.Errorf("expected result IQ; got: %s", raw)
	}

	u, err := stores.Users.Get(context.Background(), "newuser@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u == nil {
		t.Fatal("expected user to exist after registration")
	}
	if len(u.StoredKey256) == 0 {
		t.Error("expected non-empty StoredKey256")
	}
	if len(u.StoredKey512) == 0 {
		t.Error("expected non-empty StoredKey512")
	}
}

func TestRegisterRejectsDuplicate(t *testing.T) {
	stores := memstore.New()
	svc := New(stores, "example.com", true)

	_, err := svc.HandleIQ(context.Background(), makeSetIQ("3", "dupeuser", "password1"))
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}

	_, err = svc.HandleIQ(context.Background(), makeSetIQ("4", "dupeuser", "password2"))
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok {
		t.Fatalf("expected StanzaError, got %T", err)
	}
	if se.Condition != stanza.ErrConflict {
		t.Errorf("expected conflict condition, got %s", se.Condition)
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	stores := memstore.New()
	svc := New(stores, "example.com", true)

	_, err := svc.HandleIQ(context.Background(), makeSetIQ("5", "shortpass", "abc"))
	if err == nil {
		t.Fatal("expected error for short password")
	}
	se, ok := err.(*stanza.StanzaError)
	if !ok {
		t.Fatalf("expected StanzaError, got %T", err)
	}
	if se.Condition != stanza.ErrNotAcceptable {
		t.Errorf("expected not-acceptable condition, got %s", se.Condition)
	}
}

func TestRegisterDisabled(t *testing.T) {
	stores := memstore.New()
	svc := New(stores, "example.com", false)

	for _, iq := range []*stanza.IQ{makeGetIQ("6"), makeSetIQ("7", "user", "password123")} {
		_, err := svc.HandleIQ(context.Background(), iq)
		if err == nil {
			t.Fatalf("expected error when IBR disabled (id=%s)", iq.ID)
		}
		se, ok := err.(*stanza.StanzaError)
		if !ok {
			t.Fatalf("expected StanzaError, got %T", err)
		}
		if se.Condition != stanza.ErrNotAllowed {
			t.Errorf("expected not-allowed condition, got %s", se.Condition)
		}
	}
}
