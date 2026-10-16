// Package bpf compiles filters offline without opening a capture device.
package bpf

/*
#cgo LDFLAGS: -lpcap
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
static int check_filter(const char *filter, int snaplen, char *err) {
 pcap_t *h = pcap_open_dead(DLT_EN10MB, snaplen);
 if (!h) { strcpy(err, "pcap_open_dead failed"); return -1; }
 struct bpf_program p;
 int rc = pcap_compile(h, &p, filter, 1, PCAP_NETMASK_UNKNOWN);
 if (rc) { strncpy(err, pcap_geterr(h), PCAP_ERRBUF_SIZE-1); }
 else { pcap_freecode(&p); }
 pcap_close(h);
 return rc;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Compile avoids gopacket v1.7.4 Handle.Close calling breakloop on dead handles.
func Compile(filter string, snaplen int) error {
	s := C.CString(filter)
	defer C.free(unsafe.Pointer(s))
	var buf [C.PCAP_ERRBUF_SIZE]C.char
	if C.check_filter(s, C.int(snaplen), &buf[0]) != 0 {
		return fmt.Errorf("BPF: %s", C.GoString(&buf[0]))
	}
	return nil
}
