package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HookDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "lsm",
			Name:      "decisions_total",
			Help:      "Total LSM hook decisions by hook type and action.",
		},
		[]string{"hook", "action"},
	)

	HookLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "warmor",
			Subsystem: "lsm",
			Name:      "decision_duration_seconds",
			Help:      "Time taken for LSM hook decision in seconds.",
			Buckets:   []float64{.000001, .000005, .00001, .00005, .0001, .0005, .001, .005, .01},
		},
		[]string{"hook"},
	)

	PolicyLoads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "policy",
			Name:      "loads_total",
			Help:      "Policy load attempts by status.",
		},
		[]string{"policy_id", "status"},
	)

	PolicyVersion = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "policy",
			Name:      "version",
			Help:      "Currently active policy version.",
		},
		[]string{"policy_id"},
	)

	AgentHeartbeats = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "heartbeats_total",
			Help:      "Total heartbeats sent to policy server.",
		},
	)

	AgentRegistrations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "agent",
			Name:      "registrations_total",
			Help:      "Total registration attempts.",
		},
	)

	WASMExecDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_duration_seconds",
			Help:      "WASM policy execution duration.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"policy_id"},
	)

	WASMExecErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "wasm",
			Name:      "exec_errors_total",
			Help:      "WASM execution errors.",
		},
		[]string{"policy_id"},
	)

	EventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "processed_total",
			Help:      "Events processed from ring buffer by type.",
		},
		[]string{"event_type"},
	)

	EventsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "warmor",
			Subsystem: "events",
			Name:      "dropped_total",
			Help:      "Events dropped due to processing backpressure.",
		},
	)

	MapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "warmor",
			Subsystem: "ebpf",
			Name:      "map_entries",
			Help:      "Number of entries in BPF maps.",
		},
		[]string{"map_name"},
	)
)

func init() {
	prometheus.MustRegister(
		HookDecisions,
		HookLatency,
		PolicyLoads,
		PolicyVersion,
		AgentHeartbeats,
		AgentRegistrations,
		WASMExecDuration,
		WASMExecErrors,
		EventsProcessed,
		EventsDropped,
		MapEntries,
	)
}

func Handler() http.Handler {
	return promhttp.Handler()
}

func ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return http.ListenAndServe(addr, mux)
}
