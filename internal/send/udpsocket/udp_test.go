package udpsocket

import (
	"bytes"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
)

func TestPayload(t *testing.T) {
	r, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s, e := New(r.LocalAddr().(*net.UDPAddr).AddrPort())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, p := range [][]byte{nil, {0, 255, 0, 128}} {
		if e = s.Send(&model.Datagram{Payload: p}); e != nil {
			t.Fatal(e)
		}
		r.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 100)
		n, _, e := r.ReadFromUDP(b)
		if e != nil || !bytes.Equal(b[:n], p) {
			t.Fatalf("payload %v %v", b[:n], e)
		}
	}
}

func TestFragmentingSocketPolicy(t *testing.T) {
	s, e := NewFragmenting(netip.MustParseAddrPort("127.0.0.1:162"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, e := s.conn.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var policy int
	var optionErr error
	if e = raw.Control(func(fd uintptr) {
		policy, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	}); e != nil || optionErr != nil || policy != unix.IP_PMTUDISC_DONT {
		t.Fatalf("kernel fragmentation not enabled: policy=%d errors=%v,%v", policy, e, optionErr)
	}
}
