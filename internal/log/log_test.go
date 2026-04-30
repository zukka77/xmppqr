package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/danielinux/xmppqr/internal/config"
)

func TestNewTextHandler(t *testing.T) {
	cfg := config.LogConfig{Level: "debug", Format: "text", RedactStanzas: false}
	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewJSONHandler(t *testing.T) {
	cfg := config.LogConfig{Level: "info", Format: "json", RedactStanzas: false}
	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewInvalidLevel(t *testing.T) {
	cfg := config.LogConfig{Level: "verbose", Format: "text"}
	if _, err := New(cfg); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestNewInvalidFormat(t *testing.T) {
	cfg := config.LogConfig{Level: "info", Format: "logfmt"}
	if _, err := New(cfg); err == nil {
		t.Error("expected error for unknown format")
	}
}

func newBufferedLogger(redact bool) (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	var h slog.Handler = slog.NewTextHandler(buf, opts)
	if redact {
		h = &redactingHandler{inner: h, keys: redactKeys}
	}
	return slog.New(h), buf
}

func TestRedactionBlanksKeys(t *testing.T) {
	logger, buf := newBufferedLogger(true)
	logger.Info("test", "password", "s3cr3t", "user", "alice")
	out := buf.String()
	if strings.Contains(out, "s3cr3t") {
		t.Error("password value should be redacted")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Error("expected [REDACTED] in output")
	}
	if !strings.Contains(out, "alice") {
		t.Error("non-redacted key 'user' should be present")
	}
}

func TestNoRedactionWithoutFlag(t *testing.T) {
	logger, buf := newBufferedLogger(false)
	logger.Info("test", "password", "s3cr3t")
	if !strings.Contains(buf.String(), "s3cr3t") {
		t.Error("without redaction, password should appear in output")
	}
}
