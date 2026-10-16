package match

import (
	"net/netip"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/model"
)

type rule struct {
	sources, destinations []netip.Prefix
	ports                 map[uint16]bool
}
type Matcher struct{ rules []rule }

func New(rs []config.Rule) *Matcher {
	m := &Matcher{}
	for _, r := range rs {
		v := rule{ports: map[uint16]bool{}}
		for _, s := range r.Match.Sources {
			v.sources = append(v.sources, netip.MustParsePrefix(s))
		}
		for _, s := range r.Match.Destinations {
			v.destinations = append(v.destinations, netip.MustParsePrefix(s))
		}
		for _, p := range r.Match.Ports {
			v.ports[uint16(p)] = true
		}
		m.rules = append(m.rules, v)
	}
	return m
}
func contains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func (m *Matcher) Match(d *model.Datagram) int {
	for i, r := range m.rules {
		if r.ports[d.DestinationPort] && contains(r.sources, d.SourceIPv4) && contains(r.destinations, d.DestinationIPv4) {
			return i
		}
	}
	return -1
}

// MayMatchAddresses prefilters fragments without reading nonexistent UDP ports.
func (m *Matcher) MayMatchAddresses(src, dst netip.Addr) bool {
	for _, r := range m.rules {
		if contains(r.sources, src) && contains(r.destinations, dst) {
			return true
		}
	}
	return false
}
