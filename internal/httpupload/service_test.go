package httpupload

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func newTestService(t *testing.T, dir string) *Service {
	t.Helper()
	secret := []byte("test-secret")
	backend := NewDiskBackend(dir, nil) // service pointer set below
	svc := New("upload.example.com", "http://upload.example.com", backend, 10*1024*1024, secret, time.Hour, slog.Default())
	backend.service = svc
	return svc
}

func makeRequestPayload(filename string, size int64, ct string) []byte {
	return []byte(fmt.Sprintf(
		`<request xmlns='urn:xmpp:http:upload:0' filename='%s' size='%d' content-type='%s'/>`,
		filename, size, ct,
	))
}

func TestHandleIQ_SlotIssuance(t *testing.T) {
	dir := t.TempDir()
	svc := newTestService(t, dir)

	iq := &stanza.IQ{
		ID:      "req1",
		Type:    stanza.IQSet,
		Payload: makeRequestPayload("test.txt", 1024, "text/plain"),
	}

	result, err := svc.HandleIQ(context.Background(), iq)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(result), "put url=") && !strings.Contains(string(result), "put url='") {
		t.Errorf("result missing put url: %s", result)
	}
	if !strings.Contains(string(result), "get url=") && !strings.Contains(string(result), "get url='") {
		t.Errorf("result missing get url: %s", result)
	}
}

func TestHandleIQ_FileTooLarge(t *testing.T) {
	dir := t.TempDir()
	svc := newTestService(t, dir)

	iq := &stanza.IQ{
		ID:      "req2",
		Type:    stanza.IQSet,
		Payload: makeRequestPayload("big.bin", 100*1024*1024*1024, "application/octet-stream"),
	}

	result, err := svc.HandleIQ(context.Background(), iq)
	if err != nil {
		t.Fatal(err)
	}

	body := string(result)
	if !strings.Contains(body, "not-acceptable") && !strings.Contains(body, "file-too-large") {
		t.Errorf("expected file-too-large or not-acceptable, got: %s", body)
	}
}

func extractURL(payload []byte, attr string) string {
	type slot struct {
		XMLName xml.Name `xml:"slot"`
		Put     struct {
			URL string `xml:"url,attr"`
		} `xml:"put"`
		Get struct {
			URL string `xml:"url,attr"`
		} `xml:"get"`
	}
	var s slot
	if err := xml.Unmarshal(payload, &s); err != nil {
		return ""
	}
	if attr == "put" {
		return s.Put.URL
	}
	return s.Get.URL
}
