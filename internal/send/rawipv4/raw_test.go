package rawipv4

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/nishisan-dev/n-udptee/internal/model"
)

func TestPacket(t *testing.T) {
	for _, payload := range [][]byte{nil, {0, 255, 128, 1}, make([]byte, 65507)} {
		d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.2"), SourcePort: 0x1234, Payload: payload}
		for _, endpoint := range []string{"198.51.100.20:162", "198.51.100.21:1162"} {
			a := netip.MustParseAddrPort(endpoint)
			got, e := Packet(d, a, 37)
			if e != nil {
				t.Fatal(e)
			}
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 37, Protocol: layers.IPProtocolUDP, SrcIP: d.SourceIPv4.AsSlice(), DstIP: a.Addr().AsSlice(), Flags: layers.IPv4DontFragment}
			u := &layers.UDP{SrcPort: layers.UDPPort(d.SourcePort), DstPort: layers.UDPPort(a.Port())}
			if e = u.SetNetworkLayerForChecksum(ip); e != nil {
				t.Fatal(e)
			}
			buf := gopacket.NewSerializeBuffer()
			if e = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, u, gopacket.Payload(payload)); e != nil {
				t.Fatal(e)
			}
			want := buf.Bytes()
			if binary.BigEndian.Uint16(want[26:28]) == 0 {
				want[26] = 255
				want[27] = 255
			}
			if !bytes.Equal(got, want) {
				t.Fatal("packet differs from independent gopacket serialization")
			}
		}
	}
}
func TestCalculatedZeroChecksum(t *testing.T) {
	d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), SourcePort: 123, Payload: make([]byte, 2)}
	a := netip.MustParseAddrPort("198.51.100.20:162")
	b, _ := Packet(d, a, 64)
	value := binary.BigEndian.Uint16(b[26:28])
	binary.BigEndian.PutUint16(d.Payload, value)
	b, _ = Packet(d, a, 64)
	if binary.BigEndian.Uint16(b[26:28]) != 65535 {
		t.Fatalf("zero checksum not encoded ffff: %x", b)
	}
}
func TestOversize(t *testing.T) {
	if _, e := Packet(&model.Datagram{Payload: make([]byte, 65508)}, netip.MustParseAddrPort("192.0.2.1:1"), 64); e == nil {
		t.Fatal("oversize accepted")
	}
}

func TestUnspecifiedSourceRejected(t *testing.T) {
	if _, e := Packet(&model.Datagram{SourceIPv4: netip.MustParseAddr("0.0.0.0")}, netip.MustParseAddrPort("192.0.2.1:162"), 64); e == nil {
		t.Fatal("kernel would replace source 0.0.0.0, breaking transparency")
	}
}
