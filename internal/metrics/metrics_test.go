package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestNewRegistersWithoutPanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}
}

func TestCountersIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.StanzasIn.WithLabelValues("message").Add(3)
	m.AuthAttempts.WithLabelValues("SCRAM-SHA-256", "ok").Inc()
	m.PushesSent.WithLabelValues("fcm", "ok").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	found := make(map[string]bool)
	for _, mf := range mfs {
		found[mf.GetName()] = true
	}

	for _, name := range []string{"xmpp_stanzas_in_total", "xmpp_auth_attempts_total", "xmpp_pushes_sent_total"} {
		if !found[name] {
			t.Errorf("metric %s not found after increment", name)
		}
	}
}

func TestHandlerResponds200(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)

	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content-type, got %q", ct)
	}
}
