package udpsocket

import (
	"net"
	"net/netip"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
	"golang.org/x/sys/unix"
)

type Sender struct {
	conn   *net.UDPConn
	target netip.AddrPort
}

func New(t netip.AddrPort) (*Sender, error)            { return newSender(t, false) }
func NewFragmenting(t netip.AddrPort) (*Sender, error) { return newSender(t, true) }
func newSender(t netip.AddrPort, fragment bool) (*Sender, error) {
	c, e := net.ListenUDP("udp4", nil)
	if e != nil {
		return nil, e
	}
	if fragment {
		raw, err := c.SyscallConn()
		if err != nil {
			c.Close()
			return nil, err
		}
		var optionErr error
		err = raw.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
		})
		if err == nil {
			err = optionErr
		}
		if err != nil {
			c.Close()
			return nil, err
		}
	}
	return &Sender{conn: c, target: t}, nil
}
func (s *Sender) Send(d *model.Datagram) error {
	if e := s.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); e != nil {
		return e
	}
	_, e := s.conn.WriteToUDPAddrPort(d.Payload, s.target)
	return e
}
func (s *Sender) Close() error { return s.conn.Close() }
