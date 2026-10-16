package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry                                                                               *prometheus.Registry
	Packets, Bytes, Matched, Dropped, Enqueued, Success, Errors, QueueDropped, KernelDrops *prometheus.CounterVec
	Depth                                                                                  *prometheus.GaugeVec
}

func New() *Metrics {
	m := &Metrics{Registry: prometheus.NewRegistry()}
	counter := func(name string, labels ...string) *prometheus.CounterVec {
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "n_udptee_" + name, Help: name}, labels)
		m.Registry.MustRegister(v)
		return v
	}
	m.Packets = counter("capture_packets_total", "interface")
	m.Bytes = counter("capture_bytes_total", "interface")
	m.Matched = counter("packets_matched_total", "rule")
	m.Dropped = counter("packets_dropped_total", "reason")
	m.Enqueued = counter("replicas_enqueued_total", "rule", "target")
	m.Success = counter("replicas_send_success_total", "rule", "target")
	m.Errors = counter("replicas_send_errors_total", "rule", "target", "reason")
	m.QueueDropped = counter("replicas_queue_dropped_total", "rule", "target")
	m.KernelDrops = counter("pcap_kernel_drops_total", "interface")
	m.Depth = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "n_udptee_target_queue_depth", Help: "Queued replicas awaiting a send attempt"}, []string{"target"})
	m.Registry.MustRegister(m.Depth, prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	return m
}
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// Summary returns totals for the bounded set of application metrics at shutdown.
func (m *Metrics) Summary() map[string]float64 {
	result := map[string]float64{}
	families, err := m.Registry.Gather()
	if err != nil {
		return result
	}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "n_udptee_") {
			continue
		}
		for _, v := range f.Metric {
			if v.Counter != nil {
				result[f.GetName()] += v.Counter.GetValue()
			}
			if v.Gauge != nil {
				result[f.GetName()] += v.Gauge.GetValue()
			}
		}
	}
	return result
}
