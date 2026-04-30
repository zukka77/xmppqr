package push

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/danielinux/xmppqr/internal/storage"
)

func staticTokenSource(tok string) oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: tok,
		Expiry:      time.Now().Add(time.Hour),
	})
}

func regWithToken(varName, tokenVal string) *storage.PushRegistration {
	form := []byte(`<x xmlns='jabber:x:data'><field var='` + varName + `'><value>` + tokenVal + `</value></field></x>`)
	return &storage.PushRegistration{FormXML: form}
}

func TestFCMUnconfigured(t *testing.T) {
	p, err := NewFCMProvider("proj", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, sendErr := p.Send(context.Background(), &storage.PushRegistration{}, Payload{})
	if sendErr == nil || sendErr.Error() != "FCM provider not configured" {
		t.Fatalf("expected not-configured error, got %v", sendErr)
	}
}

func TestFCMSendOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"name": "projects/p/messages/42"})
	}))
	defer srv.Close()

	p := &FCMProvider{
		projectID: "p",
		ts:        staticTokenSource("test-token"),
		client:    srv.Client(),
		endpoint:  srv.URL,
	}

	reg := regWithToken("device_token", "dev-tok-abc")
	receipt, err := p.Send(context.Background(), reg, Payload{LastFromJID: "bob@example.com", MessageCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID != "42" {
		t.Errorf("expected ID=42, got %q", receipt.ID)
	}
	if receipt.Status != 200 {
		t.Errorf("expected Status=200, got %d", receipt.Status)
	}
}

func TestFCMSend404Unregistered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"NOT_FOUND"}`))
	}))
	defer srv.Close()

	p := &FCMProvider{
		projectID: "p",
		ts:        staticTokenSource("tok"),
		client:    srv.Client(),
		endpoint:  srv.URL,
	}

	reg := regWithToken("device_token", "dev-tok-xyz")
	_, err := p.Send(context.Background(), reg, Payload{})
	if !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("expected ErrNotRegistered, got %v", err)
	}
}

func TestFCMMissingDeviceToken(t *testing.T) {
	p := &FCMProvider{
		projectID: "p",
		ts:        staticTokenSource("tok"),
		client:    http.DefaultClient,
		endpoint:  "http://localhost",
	}
	reg := &storage.PushRegistration{FormXML: []byte(`<x xmlns='jabber:x:data'><field var='other'><value>x</value></field></x>`)}
	_, err := p.Send(context.Background(), reg, Payload{})
	if err == nil {
		t.Fatal("expected error for missing device token")
	}
}
