package rawipv4

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// FragmentPacket splits our canonical IPv4/UDP packet without changing it.
// Unfragmented output aliases packet. Non-final payloads are 8-byte aligned.
func FragmentPacket(packet []byte, mtu int, id uint16) ([][]byte, error) {
	if len(packet) < 28 || len(packet) > 65535 || packet[0] != 0x45 || packet[9] != 17 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return nil, fmt.Errorf("invalid canonical IPv4 UDP packet")
	}
	if mtu < 68 {
		return nil, unix.EMSGSIZE
	}
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	if id == 0 {
		return nil, fmt.Errorf("fragment ID must be nonzero")
	}
	chunk := (mtu - 20) / 8 * 8
	u := packet[20:]
	parts := make([][]byte, 0, (len(u)+chunk-1)/chunk)
	for offset := 0; offset < len(u); offset += chunk {
		end := min(offset+chunk, len(u))
		part := make([]byte, 20+end-offset)
		copy(part, packet[:20])
		copy(part[20:], u[offset:end])
		binary.BigEndian.PutUint16(part[2:4], uint16(len(part)))
		binary.BigEndian.PutUint16(part[4:6], id)
		flags := uint16(offset / 8)
		if end < len(u) {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(part[6:8], flags)
		part[10], part[11] = 0, 0
		binary.BigEndian.PutUint16(part[10:12], checksum(part[:20]))
		parts = append(parts, part)
	}
	return parts, nil
}

// A process-wide bounded allocator avoids collisions across workers targeting
// the same IPv4 address, even when UDP ports differ. Never wait for a free ID.
type idAllocator struct {
	mu       sync.Mutex
	cursor   uint16
	reserved [65536]time.Time
}

func (a *idAllocator) next(now time.Time) (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := a.cursor + 1
	if id == 0 {
		id = 1
	}
	if now.Before(a.reserved[id]) {
		return 0, fmt.Errorf("fragment ID reuse window exhausted: %w", unix.ENOBUFS)
	}
	a.cursor = id
	a.reserved[id] = now.Add(60 * time.Second)
	return id, nil
}

var fragmentIDs = func() *idAllocator {
	var seed [2]byte
	_, _ = rand.Read(seed[:])
	return &idAllocator{cursor: binary.BigEndian.Uint16(seed[:])}
}()
