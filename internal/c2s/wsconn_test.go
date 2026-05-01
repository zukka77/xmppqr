package c2s

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func wsTestServer(t *testing.T) (*httptest.Server, chan *wsConn) {
	t.Helper()
	conns := make(chan *wsConn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"xmpp"},
		})
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		localAddr, _ := net.ResolveTCPAddr("tcp", r.Host)
		conn := newWSConn(r.Context(), ws, remoteAddr, localAddr)
		conns <- conn
		// keep alive until test ends
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv, conns
}

func TestWSConnReadAcrossFrames(t *testing.T) {
	srv, conns := wsTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientWS, _, err := websocket.Dial(ctx, "ws://"+srv.Listener.Addr().String(), &websocket.DialOptions{
		Subprotocols: []string{"xmpp"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientWS.Close(websocket.StatusNormalClosure, "")

	serverConn := <-conns

	if err := clientWS.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatalf("write frame 1: %v", err)
	}
	if err := clientWS.Write(ctx, websocket.MessageText, []byte(" world")); err != nil {
		t.Fatalf("write frame 2: %v", err)
	}

	buf := make([]byte, 64)
	n1, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	n2, err := serverConn.Read(buf[n1:])
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	got := string(buf[:n1+n2])
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("expected both frames; got %q", got)
	}
}

func TestWSConnWriteSingleFrame(t *testing.T) {
	frameCount := 0
	received := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"xmpp"},
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusNormalClosure, "")
		for {
			_, data, err := ws.Read(r.Context())
			if err != nil {
				return
			}
			frameCount++
			received <- data
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientWS, _, err := websocket.Dial(ctx, "ws://"+srv.Listener.Addr().String(), &websocket.DialOptions{
		Subprotocols: []string{"xmpp"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", srv.Listener.Addr().String())
	conn := newWSConn(ctx, clientWS, remoteAddr, remoteAddr)

	msg := []byte("<iq id='1' type='get'/>")
	n, err := conn.Write(msg)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(msg) {
		t.Errorf("wrote %d bytes, want %d", n, len(msg))
	}

	select {
	case data := <-received:
		if string(data) != string(msg) {
			t.Errorf("got %q, want %q", data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for frame")
	}

	if frameCount != 1 {
		t.Errorf("expected 1 frame, got %d", frameCount)
	}
}
