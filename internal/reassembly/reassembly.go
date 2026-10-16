// Package reassembly implements bounded, single-reader IPv4 UDP reassembly.
package reassembly

import (
	"bytes"
	"net/netip"
	"sort"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/decode"
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"github.com/nishisan-dev/n-udptee/internal/model"
)

type key struct {
	source, destination netip.Addr
	id                  uint16
	iface               string
	vlan                [2]uint32
	tags                uint8
}
type fragment struct {
	offset int
	more   bool
	data   []byte
}
type context struct {
	deadline  time.Time
	parts     []fragment
	first     decode.IPv4
	haveFirst bool
	end       int
	size      int
	terminal  bool
}
type Reassembler struct {
	cfg           config.Reassembly
	contexts      map[key]*context
	bytes, active int
	nextSweep     time.Time
	m             *metrics.Metrics
}

func New(c config.Reassembly, m *metrics.Metrics) *Reassembler {
	return &Reassembler{cfg: c, contexts: make(map[key]*context), m: m}
}
func (r *Reassembler) event(s string) {
	if r.m != nil {
		r.m.ReassemblyEvents.WithLabelValues(s).Inc()
	}
}
func (r *Reassembler) gauges() {
	if r.m != nil {
		r.m.ReassemblyContexts.Set(float64(len(r.contexts)))
		r.m.ReassemblyActive.Set(float64(r.active))
		r.m.ReassemblyBytes.Set(float64(r.bytes))
	}
}
func (r *Reassembler) finish(c *context) {
	if !c.terminal {
		r.bytes -= c.size
		r.active--
		c.size = 0
		c.parts = nil
		c.first = decode.IPv4{}
		c.terminal = true
	}
}
func (r *Reassembler) reject(c *context, reason string) {
	r.finish(c)
	r.event(reason)
	if r.m != nil {
		r.m.Dropped.WithLabelValues("reassembly_" + reason).Inc()
	}
}

// Expire uses local monotonic time, independently from capture timestamps.
func (r *Reassembler) Expire(now time.Time) {
	for k, c := range r.contexts {
		if !now.Before(c.deadline) {
			if !c.terminal {
				r.reject(c, "timeout")
			}
			delete(r.contexts, k)
		}
	}
	r.nextSweep = now.Add(250 * time.Millisecond)
	r.gauges()
}
func (r *Reassembler) Close() {
	for k, c := range r.contexts {
		if !c.terminal {
			r.reject(c, "shutdown")
		}
		delete(r.contexts, k)
	}
	r.gauges()
}

// Push accepts a validated UDP/IPv4 fragment and copies only bytes retained in
// bounded contexts. nil means pending or dropped; it never emits partial data.
func (r *Reassembler) Push(p decode.IPv4, now time.Time) *model.Datagram {
	r.Tick(now)
	r.event("fragment")
	defer r.gauges()
	k := key{p.Source, p.Destination, p.ID, p.Interface, p.VLAN, p.VLANCount}
	c := r.contexts[k]
	if c != nil && !now.Before(c.deadline) {
		if !c.terminal {
			r.reject(c, "timeout")
		}
		delete(r.contexts, k)
		c = nil
	}
	if c == nil {
		if len(r.contexts) >= r.cfg.MaxDatagrams {
			r.event("capacity")
			if r.m != nil {
				r.m.Dropped.WithLabelValues("reassembly_capacity").Inc()
			}
			return nil
		}
		c = &context{deadline: now.Add(time.Duration(r.cfg.TimeoutSeconds) * time.Second), end: -1}
		r.contexts[k] = c
		r.active++
	}
	if c.terminal {
		r.event("suppressed")
		return nil
	}
	n := len(p.Payload)
	end := p.Offset + n
	if !p.Fragmented() || p.DF || p.HeaderLength < 20 || p.HeaderLength > 60 || p.Offset < 0 || p.Offset%8 != 0 || n == 0 || end > 65515 || (p.More && n%8 != 0) {
		r.reject(c, "invalid")
		return nil
	}
	if c.end >= 0 && (end > c.end || (p.More && end >= c.end) || (!p.More && end != c.end)) {
		r.reject(c, "invalid")
		return nil
	}
	if p.Offset == 0 && c.haveFirst && p.HeaderLength != c.first.HeaderLength {
		r.reject(c, "invalid")
		return nil
	}
	for _, f := range c.parts {
		fe := f.offset + len(f.data)
		if p.Offset == 0 && fe > 65535-p.HeaderLength {
			r.reject(c, "invalid")
			return nil
		}
		if p.Offset == f.offset && end == fe && p.More == f.more && bytes.Equal(p.Payload, f.data) {
			r.event("duplicate")
			return nil
		}
		if p.Offset < fe && end > f.offset {
			r.reject(c, "overlap")
			return nil
		}
		if !p.More && (fe > end || (f.more && fe >= end)) {
			r.reject(c, "invalid")
			return nil
		}
	}
	if !p.More {
		c.end = end
	}
	if p.Offset == 0 {
		c.first = p
		c.first.Payload = nil
		c.haveFirst = true
	}
	if c.haveFirst && (end > 65535-c.first.HeaderLength || (c.end >= 0 && c.end > 65535-c.first.HeaderLength)) {
		r.reject(c, "invalid")
		return nil
	}
	if len(c.parts) >= r.cfg.MaxFragments {
		r.reject(c, "fragment_limit")
		return nil
	}
	if n > r.cfg.MaxBytes-r.bytes {
		r.reject(c, "byte_limit")
		return nil
	}
	data := append([]byte(nil), p.Payload...)
	c.parts = append(c.parts, fragment{p.Offset, p.More, data})
	c.size += n
	r.bytes += n
	if !c.haveFirst || c.end < 0 || c.size != c.end {
		return nil
	}
	sort.Slice(c.parts, func(i, j int) bool { return c.parts[i].offset < c.parts[j].offset })
	cursor := 0
	for _, f := range c.parts {
		if f.offset != cursor {
			return nil
		}
		cursor += len(f.data)
	}
	// Allocate the final immutable datagram only after all bytes are present.
	u := make([]byte, c.end)
	for _, f := range c.parts {
		copy(u[f.offset:], f.data)
	}
	d, err := decode.UDP(c.first, u)
	if err != nil {
		r.reject(c, "invalid")
		return nil
	}
	r.finish(c)
	r.event("completed")
	return d
}

// Tick amortizes full sweeps, including during idle capture timeouts.
func (r *Reassembler) Tick(now time.Time) {
	if !now.Before(r.nextSweep) {
		r.Expire(now)
	}
}
