package udpsocket

import (
	"net"
	"net/netip"
	"time"

	"github.com/nishisan-dev/n-udptee/internal/model"
)

type Sender struct {
	conn   *net.UDPConn
	target netip.AddrPort
}

func New(t netip.AddrPort) (*Sender, error) {
	c, e := net.ListenUDP("udp4", nil)
	if e != nil {
		return nil, e
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
