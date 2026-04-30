// Package push implements outbound push notification providers for FCM and APNs.
// This is the ONLY place in xmppqr that uses stdlib crypto/tls for cryptographic
// purposes — specifically inside the HTTP/2 client transports for outbound HTTPS to
// FCM and APNs. All other TLS in xmppqr uses wolfSSL.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/danielinux/xmppqr/internal/storage"
)

var ErrNotRegistered = errors.New("push: device not registered")

type FCMProvider struct {
	projectID string
	ts        oauth2.TokenSource
	client    *http.Client
	endpoint  string
}

func NewFCMProvider(projectID string, serviceAccountJSON []byte) (*FCMProvider, error) {
	if len(serviceAccountJSON) == 0 {
		return &FCMProvider{projectID: projectID}, nil
	}
	cfg, err := google.JWTConfigFromJSON(serviceAccountJSON, "https://www.googleapis.com/auth/firebase.messaging")
	if err != nil {
		return nil, fmt.Errorf("fcm: parse service account: %w", err)
	}
	ts := cfg.TokenSource(context.Background())
	return &FCMProvider{
		projectID: projectID,
		ts:        ts,
		client:    &http.Client{Timeout: 30 * time.Second},
		endpoint:  "https://fcm.googleapis.com/v1/projects/" + projectID + "/messages:send",
	}, nil
}

func (f *FCMProvider) Name() string { return "fcm" }

func (f *FCMProvider) Send(ctx context.Context, reg *storage.PushRegistration, p Payload) (Receipt, error) {
	if f.ts == nil {
		return Receipt{}, errors.New("FCM provider not configured")
	}

	token, err := extractDeviceToken(reg.FormXML)
	if err != nil {
		return Receipt{}, fmt.Errorf("FCM: missing device_token in registration")
	}

	body, err := json.Marshal(map[string]any{
		"message": map[string]any{
			"token": token,
			"data": map[string]string{
				"from_jid":  p.LastFromJID,
				"msg_count": fmt.Sprintf("%d", p.MessageCount),
			},
			"android": map[string]any{
				"priority": "HIGH",
			},
		},
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("fcm: marshal request: %w", err)
	}

	return f.sendOnce(ctx, body, true)
}

func (f *FCMProvider) sendOnce(ctx context.Context, body []byte, retry bool) (Receipt, error) {
	tok, err := f.ts.Token()
	if err != nil {
		return Receipt{}, fmt.Errorf("fcm: acquire token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("fcm: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("fcm: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(respBody, &result)
		id := result.Name
		if idx := lastSegment(id); idx != "" {
			id = idx
		}
		return Receipt{ID: id, Status: 200}, nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return Receipt{Status: 404}, ErrNotRegistered
	}

	if resp.StatusCode == http.StatusServiceUnavailable && retry {
		time.Sleep(time.Duration(rand.Intn(500)+500) * time.Millisecond)
		return f.sendOnce(ctx, body, false)
	}

	if resp.StatusCode >= 500 {
		time.Sleep(time.Duration(rand.Intn(500)+500) * time.Millisecond)
	}

	return Receipt{Status: resp.StatusCode}, fmt.Errorf("fcm: %d %s", resp.StatusCode, string(respBody))
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
