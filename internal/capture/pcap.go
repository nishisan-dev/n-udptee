package capture

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/nishisan-dev/n-udptee/internal/config"
)

func Open(c config.Capture) (*pcap.Handle, error) {
	iface, e := net.InterfaceByName(c.Interface)
	if e != nil {
		return nil, e
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("loopback capture is unsupported; use an Ethernet or VLAN interface")
	}
	i, e := pcap.NewInactiveHandle(c.Interface)
	if e != nil {
		return nil, e
	}
	defer i.CleanUp()
	for _, e = range []error{i.SetSnapLen(c.Snaplen), i.SetBufferSize(c.Buffer), i.SetPromisc(c.Promiscuous), i.SetTimeout(100 * time.Millisecond), i.SetImmediateMode(true)} {
		if e != nil {
			return nil, e
		}
	}
	h, e := i.Activate()
	if e != nil {
		return nil, fmt.Errorf("pcap activation (capture permissions/CAP_NET_RAW required): %w", e)
	}
	fail := func(e error) (*pcap.Handle, error) { h.Close(); return nil, e }
	if h.LinkType() != layers.LinkTypeEthernet {
		return fail(fmt.Errorf("unsupported link type %s", h.LinkType()))
	}
	if e = h.SetDirection(pcap.DirectionIn); e != nil {
		return fail(fmt.Errorf("cannot guarantee ingress: %w", e))
	}
	if e = h.SetBPFFilter(c.BPF); e != nil {
		return fail(e)
	}
	return h, nil
}
