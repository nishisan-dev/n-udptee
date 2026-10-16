package app

import (
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHealthLifecycle(t *testing.T) {
	var healthy atomic.Bool
	m := metrics.New()
	h := handler(m, &healthy)
	for _, state := range []bool{false, true, false} {
		healthy.Store(state)
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", "/healthz", nil))
		want := 503
		if state {
			want = 200
		}
		if r.Code != want {
			t.Fatalf("health=%v code=%d", state, r.Code)
		}
	}
	healthy.Store(true)
	m.Errors.WithLabelValues("rule", "target", "send").Inc()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/healthz", nil))
	if r.Code != 200 {
		t.Fatal("remote send failure affected health")
	}
}
