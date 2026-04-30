package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/storage"
)

func generateTestP8() ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block), key, nil
}

func TestAPNsUnconfigured(t *testing.T) {
	p, err := NewAPNsProvider("TEAM", "KID", nil, "com.example.app", true)
	if err != nil {
		t.Fatal(err)
	}
	_, sendErr := p.Send(context.Background(), &storage.PushRegistration{}, Payload{})
	if sendErr == nil || sendErr.Error() != "APNs provider not configured" {
		t.Fatalf("expected not-configured error, got %v", sendErr)
	}
}

func TestAPNsParseValidP8(t *testing.T) {
	p8, _, err := generateTestP8()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewAPNsProvider("TEAMID", "KEYID", p8, "com.example.app", true)
	if err != nil {
		t.Fatalf("NewAPNsProvider failed: %v", err)
	}
	if p.signKey == nil {
		t.Fatal("expected signKey to be set")
	}
}

func TestAPNsSendOK(t *testing.T) {
	p8, _, err := generateTestP8()
	if err != nil {
		t.Fatal(err)
	}

	var gotTopic, gotPushType, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTopic = r.Header.Get("apns-topic")
		gotPushType = r.Header.Get("apns-push-type")
		gotAuth = r.Header.Get("authorization")
		w.Header().Set("apns-id", "test-apns-id-123")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewAPNsProvider("TEAM1", "KEY1", p8, "com.example.app", false)
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()
	p.endpoint = srv.URL

	reg := regWithToken("token", "device-token-abc")
	receipt, err := p.Send(context.Background(), reg, Payload{LastFromJID: "a@b.com", MessageCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != 200 {
		t.Errorf("expected 200, got %d", receipt.Status)
	}
	if receipt.ID != "test-apns-id-123" {
		t.Errorf("expected apns-id header, got %q", receipt.ID)
	}
	if gotTopic != "com.example.app" {
		t.Errorf("apns-topic: got %q, want com.example.app", gotTopic)
	}
	if gotPushType != "background" {
		t.Errorf("apns-push-type: got %q, want background", gotPushType)
	}
	if !strings.HasPrefix(gotAuth, "bearer ") {
		t.Errorf("authorization header should start with 'bearer ', got %q", gotAuth)
	}
}

func TestAPNsSend410(t *testing.T) {
	p8, _, err := generateTestP8()
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	p, err := NewAPNsProvider("TEAM2", "KEY2", p8, "com.example.app", false)
	if err != nil {
		t.Fatal(err)
	}
	p.client = srv.Client()
	p.endpoint = srv.URL

	reg := regWithToken("device_token", "dead-token")
	_, sendErr := p.Send(context.Background(), reg, Payload{})
	if !errors.Is(sendErr, ErrNotRegistered) {
		t.Fatalf("expected ErrNotRegistered, got %v", sendErr)
	}
}
