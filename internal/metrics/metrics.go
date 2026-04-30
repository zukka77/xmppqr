package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	ConnectionsActive     prometheus.Gauge
	HandshakesTotal       *prometheus.CounterVec
	AuthAttempts          *prometheus.CounterVec
	StanzasIn             *prometheus.CounterVec
	StanzasOut            *prometheus.CounterVec
	MAMQueries            prometheus.Counter
	PushesSent            *prometheus.CounterVec
	RouterShardContention prometheus.Histogram
}

func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		ConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "xmpp_connections_active",
			Help: "Active C2S connections.",
		}),
		HandshakesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xmpp_handshakes_total",
		}, []string{"pq", "version", "outcome"}),
		AuthAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xmpp_auth_attempts_total",
		}, []string{"mech", "outcome"}),
		StanzasIn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xmpp_stanzas_in_total",
		}, []string{"kind"}),
		StanzasOut: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xmpp_stanzas_out_total",
		}, []string{"kind"}),
		MAMQueries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "xmpp_mam_queries_total",
		}),
		PushesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xmpp_pushes_sent_total",
		}, []string{"provider", "outcome"}),
		RouterShardContention: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "xmpp_router_shard_contention_seconds",
			Buckets: []float64{1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 0.1},
		}),
	}

	reg.MustRegister(
		m.ConnectionsActive,
		m.HandshakesTotal,
		m.AuthAttempts,
		m.StanzasIn,
		m.StanzasOut,
		m.MAMQueries,
		m.PushesSent,
		m.RouterShardContention,
	)
	return m
}

func Handler() http.Handler {
	return promhttp.Handler()
}
