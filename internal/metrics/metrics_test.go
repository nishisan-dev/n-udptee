package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	m := New()
	m.Errors.WithLabelValues("r", "t", "mtu").Inc()
	m.KernelDrops.WithLabelValues("eth0").Add(3)
	r := httptest.NewRecorder()
	m.Handler().ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	for _, s := range []string{`n_udptee_replicas_send_errors_total{reason="mtu",rule="r",target="t"} 1`, `n_udptee_pcap_kernel_drops_total{interface="eth0"} 3`} {
		if !strings.Contains(r.Body.String(), s) {
			t.Fatalf("missing %s", s)
		}
	}
}
