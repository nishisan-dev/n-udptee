package decode

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
	"github.com/nishisan-dev/n-udptee/internal/send/rawipv4"
)

func frame(payload []byte) []byte {
	d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), SourcePort: 40000, Payload: payload}
	b, _ := rawipv4.Packet(d, netip.MustParseAddrPort("192.0.2.10:162"), 64)
	eth := make([]byte, 14)
	eth[12] = 8
	return append(eth, b...)
}
func TestDecode(t *testing.T) {
	for _, p := range [][]byte{nil, {0, 255, 0, 128}, bytes.Repeat([]byte{42}, 256)} {
		b := frame(p)
		d, e := Decode(b, "test", time.Unix(1, 0))
		if e != nil || !bytes.Equal(d.Payload, p) || d.SourcePort != 40000 || d.DestinationPort != 162 {
			t.Fatalf("decode: %v %v", d, e)
		}
		b[len(b)-1] ^= 1
		if !bytes.Equal(d.Payload, p) {
			t.Fatal("payload aliases capture buffer")
		}
	}
}
func TestVLAN(t *testing.T) {
	b := frame([]byte("vlan"))
	tagged := append([]byte{}, b[:12]...)
	tagged = append(tagged, 0x81, 0, 0, 1, 8, 0)
	tagged = append(tagged, b[14:]...)
	if _, e := Decode(tagged, "eth", time.Time{}); e != nil {
		t.Fatal(e)
	}
}
func TestReject(t *testing.T) {
	cases := map[string]func([]byte) []byte{"fragment": func(b []byte) []byte { b[20] = 0x20; return b }, "offset": func(b []byte) []byte { b[21] = 1; return b }, "non_udp": func(b []byte) []byte { b[23] = 6; return b }, "non_ipv4": func(b []byte) []byte { b[12] = 0x86; b[13] = 0xdd; return b }, "malformed": func(b []byte) []byte { binary.BigEndian.PutUint16(b[38:40], 65535); return b }}
	for reason, f := range cases {
		t.Run(reason, func(t *testing.T) {
			want := reason
			if reason == "offset" {
				want = "fragment"
			}
			if _, e := Decode(f(frame([]byte("test"))), "", time.Time{}); e == nil || e.Error() != want {
				t.Fatalf("expected %s: %v", reason, e)
			}
		})
	}
	b := frame([]byte("test"))
	for i := 0; i < len(b); i++ {
		if _, e := Decode(b[:i], "", time.Time{}); e == nil {
			t.Fatalf("accepted truncated length %d", i)
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(frame([]byte{0, 1, 2, 255}))
	f.Add(frame(nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, e := Decode(b, "fuzz", time.Time{})
		if e == nil {
			if !d.SourceIPv4.Is4() || !d.DestinationIPv4.Is4() || len(d.Payload) > 65507 {
				t.Fatal("invalid successful decode")
			}
		}
	})
}
func BenchmarkDecode(b *testing.B) {
	f := frame(make([]byte, 256))
	b.ReportAllocs()
	b.SetBytes(256)
	for b.Loop() {
		_, _ = Decode(f, "bench", time.Time{})
	}
}

func TestIPv4OptionsAndPadding(t *testing.T) {
	b := frame([]byte("options"))
	ip := append([]byte{}, b[14:34]...)
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(b)-14+4))
	withOptions := append([]byte{}, b[:14]...)
	withOptions = append(withOptions, ip...)
	withOptions = append(withOptions, 1, 1, 0, 0)
	withOptions = append(withOptions, b[34:]...)
	withOptions = append(withOptions, 0, 0, 0, 0)
	d, e := Decode(withOptions, "", time.Time{})
	if e != nil || string(d.Payload) != "options" {
		t.Fatalf("options/padding: %v", e)
	}
}

func TestFixture(t *testing.T) {
	b, e := os.ReadFile("../../tests/fixtures/ethernet-udp.hex")
	if e != nil {
		t.Fatal(e)
	}
	f, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	d, e := Decode(f, "eth0", time.Unix(0, 0))
	if e != nil || !bytes.Equal(d.Payload, []byte{0, 1, 255}) || d.SourceIPv4.String() != "192.0.2.1" {
		t.Fatalf("fixture: %v %v", d, e)
	}
}
