// Package log constructs an slog.Logger from a config with optional stanza redaction.
package log

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/danielinux/xmppqr/internal/config"
)

var redactKeys = map[string]struct{}{
	"body":           {},
	"password":       {},
	"sasl_response":  {},
	"sasl_initial":   {},
	"auth_response":  {},
	"key":            {},
	"seed":           {},
	"private_key":    {},
}

func New(cfg config.LogConfig) (*slog.Logger, error) {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info", "":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q", cfg.Level)
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	case "text", "":
		handler = slog.NewTextHandler(os.Stderr, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}

	if cfg.RedactStanzas {
		handler = &redactingHandler{inner: handler, keys: redactKeys}
	}

	return slog.New(handler), nil
}
