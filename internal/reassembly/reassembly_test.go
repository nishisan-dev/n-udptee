package reassembly

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/decode"
	"github.com/nishisan-dev/n-udptee/internal/metrics"
	"github.com/nishisan-dev/n-udptee/internal/model"
	"github.com/nishisan-dev/n-udptee/internal/send/rawipv4"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func limits() config.Reassembly {
	return config.Reassembly{Enabled: true, TimeoutSeconds: 1, MaxDatagrams: 16, MaxBytes: 65535, MaxFragments: 128}
}
func fragments(payload []byte, id uint16) []decode.IPv4 {
	d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), SourcePort: 40000, Payload: payload}
	b, _ := rawipv4.Packet(d, netip.MustParseAddrPort("192.0.2.10:162"), 64)
	parts, _ := rawipv4.FragmentPacket(b, 1200, id)
	var result []decode.IPv4
	for _, part := range parts {
		eth := make([]byte, 14)
		eth[12] = 8
		eth = append(eth, part...)
		p, err := decode.ParseIPv4Frame(eth, "eth0", time.Unix(1, 0))
		if err != nil {
			panic(err)
		}
		result = append(result, p)
	}
	return result
}
func event(m *metrics.Metrics, s string) float64 {
	return testutil.ToFloat64(m.ReassemblyEvents.WithLabelValues(s))
}

func TestOutOfOrderDuplicateAndOwnership(t *testing.T) {
	m := metrics.New()
	r := New(limits(), m)
	now := time.Now()
	payload := bytes.Repeat([]byte{0, 255, 1, 128}, 700)
	ps := fragments(payload, 42)
	if r.Push(ps[2], now) != nil || r.Push(ps[0], now) != nil || r.Push(ps[0], now) != nil {
		t.Fatal("emitted incomplete datagram")
	}
	// Capture storage may be immediately recycled after each Push.
	old := append([]byte(nil), ps[0].Payload...)
	for i := range ps[0].Payload {
		ps[0].Payload[i] = 0
	}
	ps[0].Payload = old
	d := r.Push(ps[1], now)
	if d == nil || !bytes.Equal(d.Payload, payload) || d.SourcePort != 40000 || d.DestinationPort != 162 {
		t.Fatal("reassembly changed datagram")
	}
	for _, p := range ps {
		if r.Push(p, now) != nil {
			t.Fatal("late duplicate replicated again")
		}
	}
	if r.bytes != 0 || r.active != 0 || len(r.contexts) != 1 || event(m, "completed") != 1 || event(m, "duplicate") != 1 || event(m, "suppressed") != 3 {
		t.Fatal("incorrect counters or tombstone")
	}
	r.Close()
	if len(r.contexts) != 0 || testutil.ToFloat64(m.ReassemblyContexts) != 0 {
		t.Fatal("close retained state")
	}
}
func TestTimeoutIsNotExtended(t *testing.T) {
	m := metrics.New()
	r := New(limits(), m)
	ps := fragments(make([]byte, 2500), 1)
	now := time.Now()
	r.Push(ps[0], now)
	r.Push(ps[0], now.Add(900*time.Millisecond))
	if r.Push(ps[1], now.Add(time.Second+time.Millisecond)) != nil {
		t.Fatal("completed expired datagram")
	}
	if event(m, "timeout") != 1 {
		t.Fatal("duplicate extended timeout")
	}
	r.Tick(now.Add(3 * time.Second))
	if r.bytes != 0 || r.active != 0 || len(r.contexts) != 0 {
		t.Fatal("idle expiry failed")
	}
}
func TestConflictPoisoning(t *testing.T) {
	for _, kind := range []string{"partial", "duplicate", "df", "alignment", "headers", "udp"} {
		t.Run(kind, func(t *testing.T) {
			m := metrics.New()
			r := New(limits(), m)
			ps := fragments(make([]byte, 2500), 1)
			now := time.Now()
			bad := ps[0]
			bad.Payload = append([]byte(nil), bad.Payload...)
			switch kind {
			case "partial":
				r.Push(ps[0], now)
				bad = ps[1]
				bad.Offset = 8
			case "duplicate":
				r.Push(ps[0], now)
				bad.Payload[10] ^= 1
			case "df":
				bad.DF = true
			case "alignment":
				bad.Payload = bad.Payload[:len(bad.Payload)-1]
			case "headers":
				r.Push(ps[0], now)
				bad.HeaderLength = 24
			case "udp":
				binary.BigEndian.PutUint16(bad.Payload[4:6], 8)
			}
			if r.Push(bad, now) != nil {
				t.Fatal("bad fragment emitted")
			}
			for _, p := range ps[1:] {
				if r.Push(p, now) != nil {
					t.Fatal("bad context emitted")
				}
			}
			if kind != "udp" && r.bytes != 0 {
				t.Fatal("rejected context retained payload")
			}
			if event(m, "completed") != 0 {
				t.Fatal("bad context completed")
			}
			r.Close()
		})
	}
}
func TestLimits(t *testing.T) {
	for _, kind := range []string{"capacity", "byte_limit", "fragment_limit"} {
		t.Run(kind, func(t *testing.T) {
			c := limits()
			m := metrics.New()
			ps := fragments(make([]byte, 5000), 1)
			switch kind {
			case "capacity":
				c.MaxDatagrams = 1
			case "byte_limit":
				c.MaxBytes = 1200
			case "fragment_limit":
				c.MaxFragments = 2
			}
			r := New(c, m)
			now := time.Now()
			r.Push(ps[0], now)
			if kind == "capacity" {
				other := ps[0]
				other.ID = 2
				r.Push(other, now)
			} else {
				for _, p := range ps[1:] {
					r.Push(p, now)
				}
			}
			if event(m, kind) != 1 || r.bytes > c.MaxBytes || len(r.contexts) > c.MaxDatagrams {
				t.Fatal("limit not enforced")
			}
			r.Close()
			if r.active != 0 || r.bytes != 0 {
				t.Fatal("shutdown retained data")
			}
		})
	}
}
func TestInterfaceVLANIsolation(t *testing.T) {
	for _, isVLAN := range []bool{false, true} {
		c := limits()
		r := New(c, nil)
		now := time.Now()
		a := fragments(bytes.Repeat([]byte{'a'}, 2500), 7)
		b := fragments(bytes.Repeat([]byte{'b'}, 2500), 7)
		for i := range b {
			if isVLAN {
				b[i].VLANCount = 1
				b[i].VLAN[0] = 0x81000002
			} else {
				b[i].Interface = "eth1"
			}
		}
		r.Push(a[0], now)
		r.Push(b[0], now)
		r.Push(a[2], now)
		r.Push(b[2], now)
		ad := r.Push(a[1], now)
		bd := r.Push(b[1], now)
		if ad == nil || bd == nil || ad.Payload[0] != 'a' || bd.Payload[0] != 'b' {
			t.Fatal("mixed VLAN or interface contexts")
		}
	}
}
func TestBoundariesAndLastFragment(t *testing.T) {
	for _, kind := range []string{"last_conflict", "beyond_end", "oversize", "empty", "misaligned_offset"} {
		t.Run(kind, func(t *testing.T) {
			m := metrics.New()
			r := New(limits(), m)
			ps := fragments(make([]byte, 2500), 1)
			now := time.Now()
			p := ps[1]
			switch kind {
			case "last_conflict":
				r.Push(ps[2], now)
				p.More = false
			case "beyond_end":
				r.Push(ps[2], now)
				p.Offset = ps[2].Offset + len(ps[2].Payload)
			case "oversize":
				p.Offset = 65528
			case "empty":
				p.Payload = nil
			case "misaligned_offset":
				p.Offset = 1
			}
			r.Push(p, now)
			if event(m, "invalid") != 1 || r.bytes != 0 {
				t.Fatal("invalid geometry accepted")
			}
		})
	}
}
func FuzzReassembly(f *testing.F) {
	ps := fragments(make([]byte, 2500), 2)
	frames := func(p decode.IPv4) []byte {
		d := &model.Datagram{SourceIPv4: p.Source, SourcePort: 40000, Payload: make([]byte, 2500)}
		b, _ := rawipv4.Packet(d, netip.MustParseAddrPort("192.0.2.10:162"), 64)
		parts, _ := rawipv4.FragmentPacket(b, 1200, 2)
		eth := make([]byte, 14)
		eth[12] = 8
		return append(eth, parts[p.Offset/1176]...)
	}
	f.Add(frames(ps[0]), frames(ps[1]), frames(ps[2]))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		r := New(limits(), nil)
		now := time.Unix(0, 0)
		for _, frame := range [][]byte{c, a, b, a, c} {
			p, err := decode.ParseIPv4Frame(frame, "fuzz", now)
			if err != nil || !p.Fragmented() {
				continue
			}
			if d := r.Push(p, now); d != nil && len(d.Payload) > 65507 {
				t.Fatal("oversize output")
			}
			if r.bytes < 0 || r.bytes > r.cfg.MaxBytes || r.active < 0 || len(r.contexts) > r.cfg.MaxDatagrams {
				t.Fatal("unbounded state")
			}
		}
		r.Expire(now.Add(2 * time.Second))
		if r.bytes != 0 || len(r.contexts) != 0 {
			t.Fatal("expiry leak")
		}
	})
}

func TestFirstFragmentOptionsAndLengthBound(t *testing.T) {
	now := time.Now()
	r := New(limits(), nil)
	ps := fragments(bytes.Repeat([]byte{42}, 2500), 9)
	ps[0].HeaderLength = 24
	r.Push(ps[2], now)
	r.Push(ps[0], now)
	if d := r.Push(ps[1], now); d == nil || len(d.Payload) != 2500 {
		t.Fatal("first-fragment IP options lost UDP bytes")
	}
	r = New(limits(), nil)
	ps = fragments(make([]byte, 65507), 10)
	ps[0].HeaderLength = 60
	for _, p := range ps {
		if r.Push(p, now) != nil {
			t.Fatal("accepted datagram exceeding IPv4 length with options")
		}
	}
	if r.bytes != 0 {
		t.Fatal("invalid options length retained payload")
	}
}
