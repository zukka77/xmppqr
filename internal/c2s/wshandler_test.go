package c2s

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/router"
	"github.com/danielinux/xmppqr/internal/sm"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func newWSTestHandler(stores *storage.Stores) *WSHandler {
	return NewWSHandler(SessionConfig{
		Domain:         "example.com",
		Stores:         stores,
		Router:         router.New(),
		ResumeStore:    sm.NewStore(64),
		MaxStanzaBytes: 1 << 20,
	})
}

func wsDialTest(t *testing.T, srv *httptest.Server, subprotocol string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	var opts *websocket.DialOptions
	if subprotocol != "" {
		opts = &websocket.DialOptions{Subprotocols: []string{subprotocol}}
	}
	return websocket.Dial(ctx, "ws://"+srv.Listener.Addr().String()+"/xmpp-websocket", opts)
}

func wsReadUntil(t *testing.T, ctx context.Context, ws *websocket.Conn, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var buf strings.Builder
	for time.Now().Before(deadline) {
		rCtx, cancel := context.WithDeadline(ctx, deadline)
		_, data, err := ws.Read(rCtx)
		cancel()
		if err != nil {
			return buf.String()
		}
		buf.Write(data)
		if strings.Contains(buf.String(), want) {
			return buf.String()
		}
	}
	return buf.String()
}

func wsSend(t *testing.T, ctx context.Context, ws *websocket.Conn, s string) {
	t.Helper()
	if err := ws.Write(ctx, websocket.MessageText, []byte(s)); err != nil {
		t.Fatalf("ws write: %v", err)
	}
}

func TestWebSocketHandshakeRequiresXMPPSubprotocol(t *testing.T) {
	stores := memstore.New()
	h := newWSTestHandler(stores)

	mux := http.NewServeMux()
	mux.Handle("/xmpp-websocket", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, resp, err := wsDialTest(t, srv, "")
	if err == nil {
		t.Fatal("expected error dialing without xmpp subprotocol")
	}
	_ = resp
}

func TestWebSocketSessionRoundtrip(t *testing.T) {
	stores := memstore.New()
	prepareUser(t, stores, "wsuser", "wspass")

	u, err := stores.Users.Get(context.Background(), "wsuser")
	if err != nil {
		t.Fatal(err)
	}
	u.Argon2Params, err = auth.HashPasswordForStorage([]byte("wspass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stores.Users.Put(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	h := newWSTestHandler(stores)
	mux := http.NewServeMux()
	mux.Handle("/xmpp-websocket", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, "ws://"+srv.Listener.Addr().String()+"/xmpp-websocket", &websocket.DialOptions{
		Subprotocols: []string{"xmpp"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	wsSend(t, ctx, ws, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)

	features := wsReadUntil(t, ctx, ws, "PLAIN", 3*time.Second)
	if !strings.Contains(features, "<stream:stream") {
		t.Errorf("missing stream header; got: %s", features)
	}
	if !strings.Contains(features, "PLAIN") {
		t.Errorf("missing PLAIN mechanism; got: %s", features)
	}

	payload := append([]byte{0}, []byte("wsuser")...)
	payload = append(payload, 0)
	payload = append(payload, []byte("wspass")...)
	plainB64 := base64.StdEncoding.EncodeToString(payload)

	wsSend(t, ctx, ws, fmt.Sprintf(`<auth xmlns='%s' mechanism='PLAIN'>%s</auth>`, nsSASL, plainB64))

	result := wsReadUntil(t, ctx, ws, "success", 3*time.Second)
	if !strings.Contains(result, "<success") {
		t.Fatalf("expected auth success; got: %s", result)
	}

	wsSend(t, ctx, ws, `<stream:stream to='example.com' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>`)
	postAuth := wsReadUntil(t, ctx, ws, "bind", 3*time.Second)
	if !strings.Contains(postAuth, "bind") {
		t.Fatalf("expected bind feature; got: %s", postAuth)
	}

	wsSend(t, ctx, ws, `<iq id='bind1' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>`)
	bindResp := wsReadUntil(t, ctx, ws, "<jid>", 3*time.Second)
	if !strings.Contains(bindResp, "wsuser@example.com") {
		t.Fatalf("expected JID in bind response; got: %s", bindResp)
	}

	wsSend(t, ctx, ws, `<iq id='ping1' type='get'><ping xmlns='urn:xmpp:ping'/></iq>`)
	pingResp := wsReadUntil(t, ctx, ws, "result", 3*time.Second)
	if !strings.Contains(pingResp, "ping1") || !strings.Contains(pingResp, "result") {
		t.Fatalf("expected ping result; got: %s", pingResp)
	}
}
