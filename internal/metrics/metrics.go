// Instrumentation sites (not yet wired):
//   X3DHPQBundleFetches       — internal/pubsub/ PEP bundle fetch handler
//   X3DHPQEnvelopesIn/Out     — internal/c2s/ envelope dispatch (stanza router)
//   X3DHPQPairingAttempts     — internal/x3dhpq/ session establishment handler
//   X3DHPQDeviceListPublishes — internal/pubsub/ PEP device-list publish handler
//   X3DHPQAuditChainAppends   — internal/x3dhpq/ audit chain append path
//   X3DHPQRotationsObserved   — internal/x3dhpq/ SPK/OPK rotation observer
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

	X3DHPQBundleFetches       *prometheus.CounterVec
	X3DHPQEnvelopesIn         *prometheus.CounterVec
	X3DHPQEnvelopesOut        *prometheus.CounterVec
	X3DHPQPairingAttempts     *prometheus.CounterVec
	X3DHPQDeviceListPublishes prometheus.Counter
	X3DHPQAuditChainAppends   prometheus.Counter
	X3DHPQRotationsObserved   prometheus.Counter
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
		X3DHPQBundleFetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x3dhpq_bundle_fetches_total",
		}, []string{"outcome"}),
		X3DHPQEnvelopesIn: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x3dhpq_envelopes_in_total",
		}, []string{"kind"}),
		X3DHPQEnvelopesOut: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x3dhpq_envelopes_out_total",
		}, []string{"kind"}),
		X3DHPQPairingAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x3dhpq_pairing_attempts_total",
		}, []string{"role", "outcome"}),
		X3DHPQDeviceListPublishes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "x3dhpq_device_list_publishes_total",
		}),
		X3DHPQAuditChainAppends: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "x3dhpq_audit_chain_appends_total",
		}),
		X3DHPQRotationsObserved: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "x3dhpq_rotations_observed_total",
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
		m.X3DHPQBundleFetches,
		m.X3DHPQEnvelopesIn,
		m.X3DHPQEnvelopesOut,
		m.X3DHPQPairingAttempts,
		m.X3DHPQDeviceListPublishes,
		m.X3DHPQAuditChainAppends,
		m.X3DHPQRotationsObserved,
	)
	return m
}

func Handler() http.Handler {
	return promhttp.Handler()
}
