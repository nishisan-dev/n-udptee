// Package rawipv4 isolates Linux IP_HDRINCL and packet serialization.
package rawipv4

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
	"golang.org/x/sys/unix"
)

func checksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func Packet(d *model.Datagram, target netip.AddrPort, ttl int) ([]byte, error) {
	if len(d.Payload) > 65507 {
		return nil, unix.EMSGSIZE
	}
	if !d.SourceIPv4.Is4() || !target.Addr().Is4() {
		return nil, fmt.Errorf("IPv4 required")
	}
	if d.SourceIPv4.IsUnspecified() {
		return nil, fmt.Errorf("IP_HDRINCL cannot preserve unspecified IPv4 source; replica rejected")
	}
	b := make([]byte, 28+len(d.Payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[6] = 0x40
	b[8] = byte(ttl)
	b[9] = 17
	s := d.SourceIPv4.As4()
	t := target.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], t[:])
	u := b[20:]
	binary.BigEndian.PutUint16(u, uint16(d.SourcePort))
	binary.BigEndian.PutUint16(u[2:], target.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], d.Payload)
	pseudo := make([]byte, 12+len(u))
	copy(pseudo, b[12:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(u)))
	copy(pseudo[12:], u)
	cs := checksum(pseudo)
	if cs == 0 {
		cs = 65535
	}
	binary.BigEndian.PutUint16(u[6:], cs)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	return b, nil
}

type Sender struct {
	fragment            bool
	attempts, fragments atomic.Uint64
	mu                  sync.Mutex
	fd                  int
	target              netip.AddrPort
	ttl                 int
}

func New(target netip.AddrPort, ttl int) (*Sender, error) { return newSender(target, ttl, false) }
func NewFragmenting(target netip.AddrPort, ttl int) (*Sender, error) {
	return newSender(target, ttl, true)
}
func newSender(target netip.AddrPort, ttl int, fragment bool) (*Sender, error) {
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if e != nil {
		return nil, fmt.Errorf("raw socket requires CAP_NET_RAW: %w", e)
	}
	if e = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); e != nil {
		unix.Close(fd)
		return nil, e
	}
	return &Sender{fd: fd, target: target, ttl: ttl, fragment: fragment}, nil
}
func (s *Sender) Send(d *model.Datagram) error {
	b, e := Packet(d, s.target, s.ttl)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return unix.EBADF
	}
	address := &unix.SockaddrInet4{Addr: s.target.Addr().As4()}
	if !s.fragment {
		return unix.Sendto(s.fd, b, 0, address)
	}
	if e := unix.Connect(s.fd, address); e != nil {
		return e
	}
	mtu, e := unix.GetsockoptInt(s.fd, unix.IPPROTO_IP, unix.IP_MTU)
	if e != nil {
		return e
	}
	if len(b) <= mtu {
		return unix.Sendto(s.fd, b, 0, address)
	}
	s.attempts.Add(1)
	id, e := fragmentIDs.next(time.Now())
	if e != nil {
		return e
	}
	parts, e := FragmentPacket(b, mtu, id)
	if e != nil {
		return e
	}
	return transmitFragments(parts, func(part []byte) error {
		if err := unix.Sendto(s.fd, part, 0, address); err != nil {
			return err
		}
		s.fragments.Add(1)
		return nil
	})
}
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	e := unix.Close(s.fd)
	s.fd = -1
	return e
}

// FragmentStats counts logical attempts requiring fragmentation and successful
// fragment syscalls, including partial attempts that later fail.
func (s *Sender) FragmentStats() (uint64, uint64) { return s.attempts.Load(), s.fragments.Load() }
func transmitFragments(parts [][]byte, send func([]byte) error) error {
	for _, part := range parts {
		if err := send(part); err != nil {
			return err
		}
	}
	return nil
}
