package engine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"github.com/nishisan-dev/n-udptee/internal/model"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

type fake struct {
	started  chan struct{}
	gate     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	payloads [][]byte
	err      error
}

func (f *fake) Send(d *model.Datagram) error {
	if f.started != nil {
		f.once.Do(func() { close(f.started) })
	}
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.payloads = append(f.payloads, append([]byte{}, d.Payload...))
	return f.err
}
func (f *fake) Close() error {
	if f.gate != nil {
		select {
		case <-f.gate:
		default:
			close(f.gate)
		}
	}
	return nil
}
func cfg() config.Config {
	return config.Config{Replication: config.Replication{Queue: 1}, Rules: []config.Rule{{Name: "r", Match: config.Match{Sources: []string{"0.0.0.0/0"}, Destinations: []string{"0.0.0.0/0"}, Ports: []int{162}}, Targets: []config.Target{{Name: "a", IP: "198.51.100.20"}, {Name: "b", IP: "198.51.100.21"}}}}}
}
func datagram() *model.Datagram {
	return &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), DestinationIPv4: netip.MustParseAddr("192.0.2.10"), DestinationPort: 162, Payload: []byte{0, 255, 128, 0}}
}
func TestIndependentQueuesAndShutdown(t *testing.T) {
	m := metrics.New()
	a := &fake{started: make(chan struct{}), gate: make(chan struct{})}
	b := &fake{}
	e, err := New(cfg(), m, slog.New(slog.NewTextHandler(io.Discard, nil)), func(t config.Target) (Sender, error) {
		if t.Name == "a" {
			return a, nil
		}
		return b, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.Submit(datagram())
	<-a.started
	e.Submit(datagram())
	start := time.Now()
	for range 100 {
		e.Submit(datagram())
	}
	if time.Since(start) > time.Second {
		t.Fatal("capture blocked")
	}
	if testutil.ToFloat64(m.QueueDropped.WithLabelValues("r", "a")) < 1 {
		t.Fatal("queue drops missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	e.Shutdown(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("shutdown exceeded bound")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.payloads) == 0 {
		t.Fatal("B blocked by A")
	}
	for _, p := range b.payloads {
		if !bytes.Equal(p, datagram().Payload) {
			t.Fatal("payload changed")
		}
	}
	if testutil.ToFloat64(m.Depth.WithLabelValues("a")) != 0 {
		t.Fatal("queue depth did not drain")
	}
}
func TestAllTargetsAndErrors(t *testing.T) {
	c := cfg()
	c.Replication.Queue = 8
	m := metrics.New()
	fs := []*fake{{err: unix.EMSGSIZE}, {}}
	n := 0
	e, err := New(c, m, slog.New(slog.NewTextHandler(io.Discard, nil)), func(config.Target) (Sender, error) { f := fs[n]; n++; return f, nil })
	if err != nil {
		t.Fatal(err)
	}
	e.Submit(datagram())
	empty := datagram()
	empty.Payload = nil
	e.Submit(empty)
	e.Shutdown(context.Background())
	for _, f := range fs {
		if len(f.payloads) != 2 {
			t.Fatal("each target must receive each datagram once")
		}
	}
	if testutil.ToFloat64(m.Errors.WithLabelValues("r", "a", "mtu")) != 2 || testutil.ToFloat64(m.Success.WithLabelValues("r", "b")) != 2 {
		t.Fatal("incorrect send counters")
	}
}
func TestOriginalSuppression(t *testing.T) {
	m := metrics.New()
	e, err := New(cfg(), m, slog.Default(), func(config.Target) (Sender, error) { return &fake{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	d := datagram()
	d.DestinationIPv4 = netip.MustParseAddr("198.51.100.20")
	e.Submit(d)
	e.Shutdown(context.Background())
	if testutil.ToFloat64(m.Dropped.WithLabelValues("original_destination")) != 1 {
		t.Fatal("original target not suppressed")
	}
}
func BenchmarkFanout(b *testing.B) {
	c := cfg()
	c.Replication.Queue = 4096
	m := metrics.New()
	e, _ := New(c, m, slog.New(slog.NewTextHandler(io.Discard, nil)), func(config.Target) (Sender, error) { return discard{}, nil })
	defer e.Shutdown(context.Background())
	d := datagram()
	d.Payload = make([]byte, 256)
	b.ReportAllocs()
	for b.Loop() {
		e.Submit(d)
	}
}

type discard struct{}

func (discard) Send(*model.Datagram) error { return nil }
func (discard) Close() error               { return nil }
