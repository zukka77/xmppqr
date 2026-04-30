// Package httpupload implements XEP-0363 HTTP file upload slot issuance.
package httpupload

import (
	"log/slog"
	"time"
)

type Service struct {
	domain      string
	baseURL     string
	backend     Backend
	maxFileSize int64
	secret      []byte
	tokenTTL    time.Duration
	logger      *slog.Logger
}

func New(domain, baseURL string, backend Backend, maxFileSize int64, secret []byte, ttl time.Duration, l *slog.Logger) *Service {
	return &Service{
		domain:      domain,
		baseURL:     baseURL,
		backend:     backend,
		maxFileSize: maxFileSize,
		secret:      secret,
		tokenTTL:    ttl,
		logger:      l,
	}
}
