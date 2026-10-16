// Package decode accepts only bounded Ethernet/VLAN IPv4 UDP frames.
package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
)

var (
	ErrMalformed = errors.New("malformed")
	ErrFragment  = errors.New("fragment")
	ErrNonIPv4   = errors.New("non_ipv4")
	ErrNonUDP    = errors.New("non_udp")
)

// IPv4 references capture storage. Payload must be copied before retaining it.
// VLAN includes TPID and VLAN ID, excluding priority/DEI bits.
type IPv4 struct {
	Source, Destination netip.Addr
	ID                  uint16
	HeaderLength        int
	Offset              int
	More, DF            bool
	VLAN                [2]uint32
	VLANCount           uint8
	Payload             []byte
	Interface           string
	Timestamp           time.Time
}

func (p IPv4) Fragmented() bool { return p.More || p.Offset != 0 }

func ParseIPv4Frame(b []byte, iface string, ts time.Time) (IPv4, error) {
	p := IPv4{Interface: iface, Timestamp: ts}
	if len(b) < 14 {
		return p, ErrMalformed
	}
	off := 14
	et := binary.BigEndian.Uint16(b[12:14])
	for et == 0x8100 || et == 0x88a8 {
		if len(b) < off+4 || p.VLANCount >= 2 {
			return p, ErrMalformed
		}
		p.VLAN[p.VLANCount] = uint32(et)<<16 | uint32(binary.BigEndian.Uint16(b[off:off+2])&0xfff)
		p.VLANCount++
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if et != 0x0800 {
		return p, ErrNonIPv4
	}
	b = b[off:]
	if len(b) < 20 {
		return p, ErrMalformed
	}
	ihl := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if b[0]>>4 != 4 || ihl < 20 || total < ihl || len(b) < total {
		return p, ErrMalformed
	}
	flags := binary.BigEndian.Uint16(b[6:8])
	p.Offset = int(flags&0x1fff) * 8
	p.More = flags&0x2000 != 0
	p.DF = flags&0x4000 != 0
	p.ID = binary.BigEndian.Uint16(b[4:6])
	p.HeaderLength = ihl
	p.Payload = b[ihl:total]
	var src, dst [4]byte
	copy(src[:], b[12:16])
	copy(dst[:], b[16:20])
	p.Source = netip.AddrFrom4(src)
	p.Destination = netip.AddrFrom4(dst)
	// Keep the legacy fragment reason for disabled reassembly, including other
	// fragmented protocols. Enabled processing additionally checks Protocol.
	if b[9] != 17 {
		if p.Fragmented() {
			return p, ErrFragment
		}
		return p, ErrNonUDP
	}
	return p, nil
}

// UDP returns an immutable datagram owning a copy of its UDP payload.
func UDP(p IPv4, u []byte) (*model.Datagram, error) {
	if len(u) < 8 || len(u) > 65535-p.HeaderLength {
		return nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(u[4:6]))
	if n < 8 || n != len(u) {
		return nil, ErrMalformed
	}
	payload := make([]byte, n-8)
	copy(payload, u[8:])
	return &model.Datagram{SourceIPv4: p.Source, DestinationIPv4: p.Destination, SourcePort: binary.BigEndian.Uint16(u[:2]), DestinationPort: binary.BigEndian.Uint16(u[2:4]), Payload: payload, IngressInterface: p.Interface, CaptureTimestamp: p.Timestamp}, nil
}
func Decode(b []byte, iface string, ts time.Time) (*model.Datagram, error) {
	p, err := ParseIPv4Frame(b, iface, ts)
	if err != nil {
		return nil, err
	}
	if p.Fragmented() {
		return nil, ErrFragment
	}
	return UDP(p, p.Payload)
}
