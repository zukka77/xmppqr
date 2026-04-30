package httpupload

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type slotResult struct {
	XMLName xml.Name `xml:"slot"`
	Put     struct {
		URL string `xml:"url,attr"`
	} `xml:"put"`
	Get struct {
		URL string `xml:"url,attr"`
	} `xml:"get"`
}

// newBackendSuite sets up a DiskBackend + Service pointing at a live httptest.Server.
// The server URL is discovered after construction, so we build in two steps.
func newBackendSuite(t *testing.T, ttl time.Duration) (svc *Service, srv *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	secret := []byte("test-backend-secret")
	db := NewDiskBackend(dir, nil)
	// placeholder URL; we replace it after we know the server address.
	svc = New("upload.example.com", "PLACEHOLDER", db, 10*1024*1024, secret, ttl, slog.Default())
	db.service = svc

	mux := http.NewServeMux()
	mux.Handle("/upload/", db.PutHandler())
	mux.Handle("/download/", db.GetHandler())
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Patch the base URL in the service so issued slot URLs point at srv.
	svc.baseURL = srv.URL
	return svc, srv
}

func issueSlot(t *testing.T, svc *Service, filename string, size int64) (putURL, getURL string) {
	t.Helper()
	iq := &stanza.IQ{
		ID:      "t1",
		Type:    stanza.IQSet,
		Payload: makeRequestPayload(filename, size, "application/octet-stream"),
	}
	payload, err := svc.HandleIQ(context.Background(), iq)
	if err != nil {
		t.Fatal(err)
	}
	var s slotResult
	if err := xml.Unmarshal(payload, &s); err != nil {
		t.Fatalf("unmarshal slot: %v (payload: %s)", err, payload)
	}
	return s.Put.URL, s.Get.URL
}

func TestDiskBackend_RoundTrip(t *testing.T) {
	svc, _ := newBackendSuite(t, time.Hour)

	putURL, getURL := issueSlot(t, svc, "hello.txt", 5)

	content := []byte("hello")
	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(content))
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status %d", putResp.StatusCode)
	}

	getResp, err := http.Get(getURL)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	got, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("got %q want %q", got, content)
	}
}

func TestDiskBackend_TamperedToken(t *testing.T) {
	svc, _ := newBackendSuite(t, time.Hour)
	putURL, _ := issueSlot(t, svc, "tamper.bin", 4)

	putURL = putURL + "XXXXXX"

	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader([]byte("data")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestDiskBackend_ExpiredToken(t *testing.T) {
	svc, _ := newBackendSuite(t, -time.Second)
	putURL, _ := issueSlot(t, svc, "expire.bin", 4)

	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader([]byte("data")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}
