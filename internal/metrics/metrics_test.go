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

func TestX3DHPQCountersIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.X3DHPQBundleFetches.WithLabelValues("ok").Inc()
	m.X3DHPQBundleFetches.WithLabelValues("error").Add(2)
	m.X3DHPQEnvelopesIn.WithLabelValues("message").Inc()
	m.X3DHPQEnvelopesIn.WithLabelValues("presence").Inc()
	m.X3DHPQEnvelopesOut.WithLabelValues("message").Add(3)
	m.X3DHPQEnvelopesOut.WithLabelValues("presence").Inc()
	m.X3DHPQPairingAttempts.WithLabelValues("initiator", "success").Inc()
	m.X3DHPQPairingAttempts.WithLabelValues("responder", "failure").Inc()
	m.X3DHPQPairingAttempts.WithLabelValues("initiator", "in_progress").Add(2)
	m.X3DHPQDeviceListPublishes.Inc()
	m.X3DHPQAuditChainAppends.Add(5)
	m.X3DHPQRotationsObserved.Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	found := make(map[string]bool)
	for _, mf := range mfs {
		found[mf.GetName()] = true
	}

	for _, name := range []string{
		"x3dhpq_bundle_fetches_total",
		"x3dhpq_envelopes_in_total",
		"x3dhpq_envelopes_out_total",
		"x3dhpq_pairing_attempts_total",
		"x3dhpq_device_list_publishes_total",
		"x3dhpq_audit_chain_appends_total",
		"x3dhpq_rotations_observed_total",
	} {
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
