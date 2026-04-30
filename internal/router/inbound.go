package router

import (
	"bytes"
	"context"
	"log/slog"

	"github.com/danielinux/xmppqr/internal/stanza"
)

type RouterInboundAdapter struct {
	router *Router
	log    *slog.Logger
}

func NewRouterInboundAdapter(r *Router, log *slog.Logger) *RouterInboundAdapter {
	return &RouterInboundAdapter{router: r, log: log}
}

func (a *RouterInboundAdapter) RouteInbound(ctx context.Context, raw []byte) error {
	toStr := extractAttrInbound(raw, "to")
	if toStr == "" {
		return ErrNoSession
	}
	j, err := stanza.Parse(toStr)
	if err != nil {
		return ErrNoSession
	}
	if j.Resource != "" {
		return a.router.RouteToFull(ctx, j, raw)
	}
	_, err = a.router.RouteToBare(ctx, j, raw)
	return err
}

func extractAttrInbound(raw []byte, attr string) string {
	needle := []byte(attr + "=")
	idx := bytes.Index(raw, needle)
	if idx < 0 {
		return ""
	}
	rest := raw[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	q := rest[0]
	end := bytes.IndexByte(rest[1:], q)
	if end < 0 {
		return ""
	}
	return string(rest[1 : end+1])
}
