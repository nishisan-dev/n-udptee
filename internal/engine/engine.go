// Package engine runs bounded, isolated target queues. Submit has one producer.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/match"
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"github.com/nishisan-dev/n-udptee/internal/model"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

type Sender interface {
	Send(*model.Datagram) error
	Close() error
}
type Factory func(config.Target) (Sender, error)
type worker struct {
	q                          chan *model.Datagram
	s                          Sender
	rule, target               string
	ip                         netip.Addr
	depth                      prometheus.Gauge
	enqueued, success, dropped prometheus.Counter
	lastLog                    time.Time
}
type Engine struct {
	m       *metrics.Metrics
	log     *slog.Logger
	matcher *match.Matcher
	rules   [][]*worker
	wg      sync.WaitGroup
	stop    chan struct{}
	once    sync.Once
}

func New(c config.Config, m *metrics.Metrics, log *slog.Logger, f Factory) (*Engine, error) {
	e := &Engine{m: m, log: log, matcher: match.New(c.Rules), stop: make(chan struct{})}
	for _, r := range c.Rules {
		var ws []*worker
		for _, t := range r.Targets {
			s, err := f(t)
			if err != nil {
				for _, rs := range e.rules {
					for _, w := range rs {
						w.s.Close()
					}
				}
				for _, w := range ws {
					w.s.Close()
				}
				return nil, err
			}
			w := &worker{q: make(chan *model.Datagram, c.Replication.Queue), s: s, rule: r.Name, target: t.Name, ip: netip.MustParseAddr(t.IP), depth: m.Depth.WithLabelValues(t.Name), enqueued: m.Enqueued.WithLabelValues(r.Name, t.Name), success: m.Success.WithLabelValues(r.Name, t.Name), dropped: m.QueueDropped.WithLabelValues(r.Name, t.Name)}
			ws = append(ws, w)
		}
		e.rules = append(e.rules, ws)
	}
	for _, rs := range e.rules {
		for _, w := range rs {
			e.wg.Add(1)
			go e.run(w)
		}
	}
	return e, nil
}
func (e *Engine) Submit(d *model.Datagram) {
	i := e.matcher.Match(d)
	if i < 0 {
		e.m.Dropped.WithLabelValues("unmatched").Inc()
		return
	}
	ws := e.rules[i]
	e.m.Matched.WithLabelValues(ws[0].rule).Inc()
	for _, w := range ws {
		if w.ip == d.DestinationIPv4 {
			e.m.Dropped.WithLabelValues("original_destination").Inc()
			continue
		}
		w.depth.Inc()
		select {
		case w.q <- d:
			w.enqueued.Inc()
		default:
			w.depth.Dec()
			w.dropped.Inc()
		}
	}
}
func Reason(err error) string {
	switch {
	case errors.Is(err, unix.EMSGSIZE):
		return "mtu"
	case errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM):
		return "permission"
	case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.ENOBUFS):
		return "backpressure"
	default:
		return "send"
	}
}
func (e *Engine) run(w *worker) {
	defer e.wg.Done()
	defer w.s.Close()
	for d := range w.q {
		w.depth.Dec()
		select {
		case <-e.stop:
			e.m.Dropped.WithLabelValues("shutdown").Inc()
			continue
		default:
		}
		type fragmentReporter interface{ FragmentStats() (uint64, uint64) }
		reporter, hasStats := w.s.(fragmentReporter)
		var beforeAttempts, beforeFragments uint64
		if hasStats {
			beforeAttempts, beforeFragments = reporter.FragmentStats()
		}
		err := w.s.Send(d)
		if hasStats {
			attempts, fragments := reporter.FragmentStats()
			e.m.RawFragmentAttempts.WithLabelValues(w.rule, w.target).Add(float64(attempts - beforeAttempts))
			e.m.RawFragments.WithLabelValues(w.rule, w.target).Add(float64(fragments - beforeFragments))
		}
		if err != nil {
			reason := Reason(err)
			e.m.Errors.WithLabelValues(w.rule, w.target, reason).Inc()
			if time.Since(w.lastLog) >= time.Second {
				e.log.Warn("replica send failed", "rule", w.rule, "target", w.target, "reason", reason, "error", err)
				w.lastLog = time.Now()
			}
		} else {
			w.success.Inc()
		}
	}
}

// Shutdown must run after the producer has stopped. Implementations of Sender
// must bound Send and unblock it on Close.
func (e *Engine) Shutdown(ctx context.Context) {
	e.once.Do(func() {
		for _, rs := range e.rules {
			for _, w := range rs {
				close(w.q)
			}
		}
		done := make(chan struct{})
		go func() { e.wg.Wait(); close(done) }()
		select {
		case <-done:
			return
		case <-ctx.Done():
			close(e.stop)
			for _, rs := range e.rules {
				for _, w := range rs {
					w.s.Close()
				}
			}
			<-done
		}
	})
}

func (e *Engine) MayMatchAddresses(src, dst netip.Addr) bool {
	return e.matcher.MayMatchAddresses(src, dst)
}
