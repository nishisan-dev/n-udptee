// Package decode accepts only bounded Ethernet/VLAN IPv4 UDP frames.
package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
)

var ErrMalformed = errors.New("malformed")

func Decode(b []byte, iface string, ts time.Time) (*model.Datagram, error) {
	fail := func(s string) (*model.Datagram, error) { return nil, errors.New(s) }
	if len(b) < 14 {
		return nil, ErrMalformed
	}
	off := 14
	et := binary.BigEndian.Uint16(b[12:14])
	tags := 0
	for et == 0x8100 || et == 0x88a8 {
		if len(b) < off+4 || tags >= 2 {
			return nil, ErrMalformed
		}
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
		tags++
	}
	if et != 0x0800 {
		return fail("non_ipv4")
	}
	b = b[off:]
	if len(b) < 20 {
		return nil, ErrMalformed
	}
	ihl := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if b[0]>>4 != 4 || ihl < 20 || total < ihl || len(b) < total {
		return nil, ErrMalformed
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return fail("fragment")
	}
	if b[9] != 17 {
		return fail("non_udp")
	}
	if total < ihl+8 {
		return nil, ErrMalformed
	}
	u := b[ihl:total]
	n := int(binary.BigEndian.Uint16(u[4:6]))
	if n < 8 || n != len(u) {
		return nil, ErrMalformed
	}
	var src, dst [4]byte
	copy(src[:], b[12:16])
	copy(dst[:], b[16:20])
	payload := make([]byte, n-8)
	copy(payload, u[8:])
	return &model.Datagram{SourceIPv4: netip.AddrFrom4(src), DestinationIPv4: netip.AddrFrom4(dst), SourcePort: binary.BigEndian.Uint16(u[:2]), DestinationPort: binary.BigEndian.Uint16(u[2:4]), Payload: payload, IngressInterface: iface, CaptureTimestamp: ts}, nil
}
