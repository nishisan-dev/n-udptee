package model

import (
	"net/netip"
	"time"
)

// Datagram owns Payload; callers must not mutate it after decoding.
type Datagram struct {
	SourceIPv4, DestinationIPv4 netip.Addr
	SourcePort, DestinationPort uint16
	Payload                     []byte
	IngressInterface            string
	CaptureTimestamp            time.Time
}
