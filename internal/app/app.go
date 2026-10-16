package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"github.com/nishisan-dev/n-udptee/internal/capture"
	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/decode"
	"github.com/nishisan-dev/n-udptee/internal/engine"
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"github.com/nishisan-dev/n-udptee/internal/reassembly"
	"github.com/nishisan-dev/n-udptee/internal/send/rawipv4"
	"github.com/nishisan-dev/n-udptee/internal/send/udpsocket"
)

func rejectBroadcast(c config.Config) error {
	is, e := net.Interfaces()
	if e != nil {
		return e
	}
	for _, i := range is {
		as, e := i.Addrs()
		if e != nil {
			return e
		}
		for _, a := range as {
			p, e := netip.ParsePrefix(a.String())
			if e != nil || !p.Addr().Is4() || p.Bits() > 30 {
				continue
			}
			v := p.Masked().Addr().As4()
			for n := p.Bits(); n < 32; n++ {
				v[n/8] |= 1 << uint(7-n%8)
			}
			b := netip.AddrFrom4(v)
			for _, r := range c.Rules {
				for _, t := range r.Targets {
					if netip.MustParseAddr(t.IP) == b {
						return fmt.Errorf("target %s is a local subnet broadcast", t.Name)
					}
				}
			}
		}
	}
	return nil
}
func Run(ctx context.Context, c config.Config, log *slog.Logger) error {
	log.Info("effective configuration", "config", c)
	if e := rejectBroadcast(c); e != nil {
		return e
	}
	h, e := capture.Open(c.Capture)
	if e != nil {
		return e
	}
	defer h.Close()
	m := metrics.New()
	en, e := engine.New(c, m, log, func(t config.Target) (engine.Sender, error) {
		a := netip.AddrPortFrom(netip.MustParseAddr(t.IP), uint16(t.Port))
		if c.Replication.Mode == "raw_ipv4" {
			if c.Replication.Fragmentation == "auto" {
				return rawipv4.NewFragmenting(a, c.Replication.TTL)
			}
			return rawipv4.New(a, c.Replication.TTL)
		}
		if c.Replication.Fragmentation == "auto" {
			return udpsocket.NewFragmenting(a)
		}
		return udpsocket.New(a)
	})
	if e != nil {
		return e
	}
	var assembler *reassembly.Reassembler
	if c.Reassembly.Enabled {
		assembler = reassembly.New(c.Reassembly, m)
		log.Info("IPv4 reassembly enabled; BPF must include non-initial UDP fragments", "timeout_seconds", c.Reassembly.TimeoutSeconds)
	}
	var healthy atomic.Bool
	var server *http.Server
	httpErr := make(chan error, 1)
	defer func() {
		healthy.Store(false)
		if assembler != nil {
			assembler.Close()
		}
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		en.Shutdown(stop)
		if server != nil {
			if err := server.Shutdown(stop); err != nil {
				_ = server.Close()
			}
		}
		log.Info("service stopped", "interface", c.Capture.Interface, "totals", m.Summary())
	}()
	if c.Metrics.Enabled {
		listener, err := net.Listen("tcp", c.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("HTTP bind: %w", err)
		}
		mux := handler(m, &healthy)
		server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { httpErr <- server.Serve(listener) }()
	}
	healthy.Store(true)
	log.Info("service ready", "interface", c.Capture.Interface, "bpf", c.Capture.BPF, "mode", c.Replication.Mode, "rules", len(c.Rules), "queue_size_per_target", c.Replication.Queue, "ttl", c.Replication.TTL, "promiscuous", c.Capture.Promiscuous)
	packets := m.Packets.WithLabelValues(c.Capture.Interface)
	bytes := m.Bytes.WithLabelValues(c.Capture.Interface)
	lastStats := time.Now()
	lastDrops := 0
	statsWarned := false
	stats := func() {
		s, err := h.Stats()
		if err != nil {
			if !statsWarned {
				log.Warn("pcap statistics unavailable", "error", err)
				statsWarned = true
			}
			return
		}
		delta := s.PacketsDropped - lastDrops
		if delta < 0 {
			delta = s.PacketsDropped
		}
		m.KernelDrops.WithLabelValues(c.Capture.Interface).Add(float64(delta))
		lastDrops = s.PacketsDropped
	}
	defer stats()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-httpErr:
			if !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("HTTP server: %w", err)
			}
			return err
		default:
		}
		b, ci, err := h.ReadPacketData()
		if time.Since(lastStats) >= time.Second {
			stats()
			lastStats = time.Now()
		}
		if assembler != nil {
			assembler.Tick(time.Now())
		}
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return fmt.Errorf("capture: %w", err)
		}
		packets.Inc()
		bytes.Add(float64(ci.CaptureLength))
		if ci.CaptureLength < ci.Length {
			m.Dropped.WithLabelValues("truncated").Inc()
			continue
		}
		p, err := decode.ParseIPv4Frame(b, c.Capture.Interface, ci.Timestamp)
		if err != nil {
			m.Dropped.WithLabelValues(err.Error()).Inc()
			continue
		}
		if p.Fragmented() {
			if assembler == nil {
				m.Dropped.WithLabelValues("fragment").Inc()
				continue
			}
			if !en.MayMatchAddresses(p.Source, p.Destination) {
				m.Dropped.WithLabelValues("unmatched").Inc()
				continue
			}
			if d := assembler.Push(p, time.Now()); d != nil {
				en.Submit(d)
			}
			continue
		}
		d, err := decode.UDP(p, p.Payload)
		if err != nil {
			m.Dropped.WithLabelValues(err.Error()).Inc()
			continue
		}
		en.Submit(d)
	}
}

func handler(m *metrics.Metrics, healthy *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
