package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/danielinux/xmppqr/internal/storage"
)

type APNsProvider struct {
	teamID   string
	keyID    string
	topic    string
	signKey  *ecdsa.PrivateKey
	client   *http.Client
	endpoint string

	jwtMu     sync.Mutex
	jwtToken  string
	jwtExpiry time.Time
}

func NewAPNsProvider(teamID, keyID string, p8Key []byte, topic string, sandbox bool) (*APNsProvider, error) {
	if len(p8Key) == 0 {
		return &APNsProvider{}, nil
	}

	block, _ := pem.Decode(p8Key)
	if block == nil {
		return nil, errors.New("apns: invalid PEM block in p8 key")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: parse PKCS8 key: %w", err)
	}
	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns: p8 key is not ECDSA")
	}

	ep := "https://api.push.apple.com"
	if sandbox {
		ep = "https://api.sandbox.push.apple.com"
	}

	return &APNsProvider{
		teamID:   teamID,
		keyID:    keyID,
		topic:    topic,
		signKey:  ecKey,
		client:   &http.Client{Timeout: 30 * time.Second},
		endpoint: ep,
	}, nil
}

func (a *APNsProvider) Name() string { return "apns" }

func (a *APNsProvider) Send(ctx context.Context, reg *storage.PushRegistration, p Payload) (Receipt, error) {
	if a.signKey == nil {
		return Receipt{}, errors.New("APNs provider not configured")
	}

	token, err := extractDeviceToken(reg.FormXML)
	if err != nil {
		return Receipt{}, fmt.Errorf("apns: missing device token in registration")
	}

	payload, err := json.Marshal(map[string]any{
		"aps": map[string]any{
			"content-available": 1,
		},
		"from_jid":  p.LastFromJID,
		"msg_count": p.MessageCount,
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("apns: marshal payload: %w", err)
	}

	signed, err := a.bearerToken()
	if err != nil {
		return Receipt{}, fmt.Errorf("apns: sign jwt: %w", err)
	}

	url := a.endpoint + "/3/device/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Receipt{}, fmt.Errorf("apns: build request: %w", err)
	}
	req.Header.Set("authorization", "bearer "+signed)
	req.Header.Set("apns-topic", a.topic)
	req.Header.Set("apns-push-type", "background")
	req.Header.Set("apns-priority", "5")
	req.Header.Set("apns-expiration", "0")
	req.Header.Set("content-type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("apns: http: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusOK {
		return Receipt{ID: resp.Header.Get("apns-id"), Status: 200}, nil
	}
	if resp.StatusCode == http.StatusGone {
		return Receipt{Status: 410}, ErrNotRegistered
	}
	return Receipt{Status: resp.StatusCode}, fmt.Errorf("apns: %d", resp.StatusCode)
}

func (a *APNsProvider) bearerToken() (string, error) {
	a.jwtMu.Lock()
	defer a.jwtMu.Unlock()

	if a.jwtToken != "" && time.Now().Before(a.jwtExpiry) {
		return a.jwtToken, nil
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": a.teamID,
		"iat": now.Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = a.keyID

	signed, err := t.SignedString(a.signKey)
	if err != nil {
		return "", err
	}

	a.jwtToken = signed
	a.jwtExpiry = now.Add(50 * time.Minute)
	return signed, nil
}
