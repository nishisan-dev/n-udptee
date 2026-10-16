package match

import (
	"net/netip"
	"testing"

	"github.com/nishisan-dev/n-udptee/internal/config"
	"github.com/nishisan-dev/n-udptee/internal/model"
)

func TestFirstRule(t *testing.T) {
	r := config.Rule{Match: config.Match{Sources: []string{"192.0.2.0/24"}, Destinations: []string{"198.51.100.0/24"}, Ports: []int{162}}}
	m := New([]config.Rule{r, r})
	d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), DestinationIPv4: netip.MustParseAddr("198.51.100.1"), DestinationPort: 162}
	if m.Match(d) != 0 {
		t.Fatal("first rule must win")
	}
	d.DestinationPort = 161
	if m.Match(d) != -1 {
		t.Fatal("port mismatch")
	}
	d.DestinationPort = 162
	d.SourceIPv4 = netip.MustParseAddr("203.0.113.1")
	if m.Match(d) != -1 {
		t.Fatal("source mismatch")
	}
	d.SourceIPv4 = netip.MustParseAddr("192.0.2.1")
	d.DestinationIPv4 = netip.MustParseAddr("203.0.113.1")
	if m.Match(d) != -1 {
		t.Fatal("destination mismatch")
	}
}
