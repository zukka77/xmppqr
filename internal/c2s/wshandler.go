package c2s

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/coder/websocket"
)

type WSHandler struct {
	cfg SessionConfig
}

func NewWSHandler(cfg SessionConfig) *WSHandler {
	return &WSHandler{cfg: cfg}
}

func (h *WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqProtos := r.Header.Get("Sec-WebSocket-Protocol")
	hasXMPP := false
	for _, p := range strings.Split(reqProtos, ",") {
		if strings.TrimSpace(p) == "xmpp" {
			hasXMPP = true
			break
		}
	}
	if !hasXMPP {
		http.Error(w, "xmpp subprotocol required", http.StatusBadRequest)
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"xmpp"},
	})
	if err != nil {
		return
	}

	ctx := context.Background()
	remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	localAddr, _ := net.ResolveTCPAddr("tcp", r.Host)
	conn := newWSConn(ctx, ws, remoteAddr, localAddr)
	sess := newSession(conn, h.cfg)

	if err := sess.Run(ctx); err != nil && err != context.Canceled {
		log := h.cfg.Logger
		if log == nil {
			log = slog.Default()
		}
		if err != io.EOF {
			log.Info("ws session ended", "err", err)
		}
	}
}
