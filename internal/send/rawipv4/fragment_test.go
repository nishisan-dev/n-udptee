package rawipv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/nishisan-dev/n-udptee/internal/model"
	"golang.org/x/sys/unix"
)

func TestFragmentsIndependentChecksums(t *testing.T) {
	for _, size := range []int{0, 1, 2500, 65507} {
		for _, mtu := range []int{68, 576, 1200, 1400, 1500, 9000, 65535} {
			d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), SourcePort: 40000, Payload: bytes.Repeat([]byte{0xff}, size)}
			b, _ := Packet(d, netip.MustParseAddrPort("198.51.100.1:162"), 64)
			parts, err := FragmentPacket(b, mtu, 0xbeef)
			if err != nil {
				t.Fatal(err)
			}
			var udp []byte
			for i, part := range parts {
				if len(part) > mtu {
					t.Fatal("MTU exceeded")
				}
				if len(parts) > 1 {
					flags := binary.BigEndian.Uint16(part[6:8])
					if int(flags&0x1fff)*8 != len(udp) || flags&0x4000 != 0 || binary.BigEndian.Uint16(part[4:6]) != 0xbeef {
						t.Fatal("invalid ID/offset/DF")
					}
					more := i < len(parts)-1
					if (flags&0x2000 != 0) != more || (more && (len(part)-20)%8 != 0) {
						t.Fatal("invalid MF/alignment")
					}
				}
				var ip layers.IPv4
				if err = ip.DecodeFromBytes(part, gopacket.NilDecodeFeedback); err != nil {
					t.Fatal(err)
				}
				buf := gopacket.NewSerializeBuffer()
				if err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip, gopacket.Payload(part[20:])); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(part, buf.Bytes()) {
					t.Fatal("independent IPv4 checksum mismatch")
				}
				udp = append(udp, part[20:]...)
			}
			if !bytes.Equal(udp, b[20:]) {
				t.Fatal("fragmentation changed UDP datagram/checksum")
			}
		}
	}
}
func TestFragmentValidationAndPartialFailure(t *testing.T) {
	if _, e := FragmentPacket(nil, 1500, 1); e == nil {
		t.Fatal("invalid input accepted")
	}
	d := &model.Datagram{SourceIPv4: netip.MustParseAddr("192.0.2.1"), Payload: make([]byte, 3000)}
	b, _ := Packet(d, netip.MustParseAddrPort("192.0.2.2:162"), 64)
	if _, e := FragmentPacket(b, 67, 1); !errors.Is(e, unix.EMSGSIZE) {
		t.Fatal(e)
	}
	if _, e := FragmentPacket(b, 1200, 0); e == nil {
		t.Fatal("zero ID accepted")
	}
	parts, _ := FragmentPacket(b, 1200, 1)
	calls := 0
	e := transmitFragments(parts, func([]byte) error {
		calls++
		if calls == 2 {
			return unix.EHOSTUNREACH
		}
		return nil
	})
	if calls != 2 || !errors.Is(e, unix.EHOSTUNREACH) {
		t.Fatal("retried or continued after failure")
	}
}
func TestIDReservationAndExhaustion(t *testing.T) {
	a := &idAllocator{}
	now := time.Now()
	for i := 1; i <= 65535; i++ {
		id, e := a.next(now)
		if e != nil || int(id) != i {
			t.Fatalf("id %d: %v", id, e)
		}
	}
	if _, e := a.next(now.Add(59 * time.Second)); !errors.Is(e, unix.ENOBUFS) {
		t.Fatal("reused active ID")
	}
	if id, e := a.next(now.Add(60 * time.Second)); e != nil || id != 1 {
		t.Fatalf("expired ID not released %d: %v", id, e)
	}
}
func TestIDConcurrentWorkers(t *testing.T) {
	a := &idAllocator{}
	ids := make(chan uint16, 2000)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				id, err := a.next(time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				ids <- id
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[uint16]bool{}
	for id := range ids {
		if id == 0 || seen[id] {
			t.Fatal("ID collision")
		}
		seen[id] = true
	}
	if len(seen) != 2000 {
		t.Fatal("missing IDs")
	}
}
