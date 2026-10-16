// Package config loads and validates the static control plane.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/nishisan-dev/n-udptee/internal/bpf"
	"go.yaml.in/yaml/v3"
)

type Capture struct {
	Interface   string `yaml:"interface"`
	BPF         string `yaml:"bpf"`
	Direction   string `yaml:"direction"`
	Promiscuous bool   `yaml:"promiscuous"`
	Snaplen     int    `yaml:"snaplen"`
	Buffer      int    `yaml:"buffer_size_bytes"`
}
type Reassembly struct {
	Enabled        bool `yaml:"enabled"`
	TimeoutSeconds int  `yaml:"timeout_seconds"`
	MaxDatagrams   int  `yaml:"max_datagrams"`
	MaxBytes       int  `yaml:"max_bytes"`
	MaxFragments   int  `yaml:"max_fragments_per_datagram"`
}

type Replication struct {
	Fragmentation string `yaml:"fragmentation"`
	Mode          string `yaml:"mode"`
	TTL           int    `yaml:"ttl"`
	Queue         int    `yaml:"queue_size_per_target"`
	OnFull        string `yaml:"on_queue_full"`
}
type Match struct {
	Sources      []string `yaml:"source_cidrs"`
	Destinations []string `yaml:"destination_cidrs"`
	Ports        []int    `yaml:"destination_ports"`
}
type Target struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}
type Rule struct {
	Name    string   `yaml:"name"`
	Match   Match    `yaml:"match"`
	Targets []Target `yaml:"targets"`
}
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}
type Config struct {
	Version     int         `yaml:"version"`
	Reassembly  Reassembly  `yaml:"reassembly"`
	Capture     Capture     `yaml:"capture"`
	Replication Replication `yaml:"replication"`
	Rules       []Rule      `yaml:"rules"`
	Metrics     Metrics     `yaml:"metrics"`
	Logging     Logging     `yaml:"logging"`
}

func Load(path string) (Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return Config{}, e
	}
	defer f.Close()
	return Read(f)
}
func Read(r io.Reader) (Config, error) {
	c := Config{Reassembly: Reassembly{TimeoutSeconds: 30, MaxDatagrams: 1024, MaxBytes: 33554432, MaxFragments: 128}, Capture: Capture{Direction: "in", Snaplen: 65535, Buffer: 33554432}, Replication: Replication{Fragmentation: "drop", Mode: "raw_ipv4", TTL: 64, Queue: 4096, OnFull: "drop_newest"}, Metrics: Metrics{Enabled: true, Listen: "127.0.0.1:9109"}, Logging: Logging{Level: "info", Format: "json"}}
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return c, err
	}
	if len(data) > 1<<20 {
		return c, fmt.Errorf("configuration exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if e := d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return c, fmt.Errorf("expected one YAML document")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	fail := func(s string) error { return fmt.Errorf("configuration: %s", s) }
	if c.Version != 1 {
		return fail("version must be 1")
	}
	if c.Capture.Interface == "" || c.Capture.Interface == "any" {
		return fail("explicit interface required; any is unsupported")
	}
	if c.Capture.Direction != "in" {
		return fail("direction must be in")
	}
	if c.Capture.Snaplen < 64 || c.Capture.Snaplen > 262144 || c.Capture.Buffer < 1 || c.Capture.Buffer > 1<<30 {
		return fail("invalid capture buffer/snaplen")
	}
	if strings.TrimSpace(c.Capture.BPF) == "" || strings.ContainsRune(c.Capture.BPF, 0) {
		return fail("bpf required")
	}
	if e := bpf.Compile(c.Capture.BPF, c.Capture.Snaplen); e != nil {
		return fmt.Errorf("BPF: %w", e)
	}
	if c.Replication.Mode != "raw_ipv4" && c.Replication.Mode != "udp_socket" {
		return fail("unsupported replication mode")
	}
	if c.Replication.TTL < 1 || c.Replication.TTL > 255 || c.Replication.Queue < 1 || c.Replication.Queue > 65536 || c.Replication.OnFull != "drop_newest" {
		return fail("invalid TTL, queue or on_queue_full")
	}
	if c.Replication.Fragmentation != "drop" && c.Replication.Fragmentation != "auto" {
		return fail("replication.fragmentation must be drop or auto")
	}
	if c.Reassembly.TimeoutSeconds < 1 || c.Reassembly.TimeoutSeconds > 60 || c.Reassembly.MaxDatagrams < 1 || c.Reassembly.MaxDatagrams > 65536 || c.Reassembly.MaxBytes < 65535 || c.Reassembly.MaxBytes > 268435456 || c.Reassembly.MaxFragments < 2 || c.Reassembly.MaxFragments > 8192 {
		return fail("invalid reassembly limits: timeout 1..60 s, contexts 1..65536, bytes 65535..268435456, fragments 2..8192")
	}
	if len(c.Rules) == 0 {
		return fail("rules required")
	}
	names := map[string]bool{}
	targets := map[string]bool{}
	total := 0
	for _, r := range c.Rules {
		if r.Name == "" || names[r.Name] {
			return fail("empty or duplicate rule name")
		}
		names[r.Name] = true
		if len(r.Match.Sources) == 0 || len(r.Match.Destinations) == 0 || len(r.Match.Ports) == 0 || len(r.Targets) == 0 {
			return fail("match CIDRs, ports and targets required")
		}
		for _, list := range [][]string{r.Match.Sources, r.Match.Destinations} {
			for _, s := range list {
				p, e := netip.ParsePrefix(s)
				if e != nil || !p.Addr().Is4() {
					return fail("invalid IPv4 CIDR: " + s)
				}
			}
		}
		for _, p := range r.Match.Ports {
			if p < 1 || p > 65535 {
				return fail("invalid match port")
			}
		}
		endpoints := map[netip.AddrPort]bool{}
		for _, t := range r.Targets {
			a, e := netip.ParseAddr(t.IP)
			if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") {
				return fail("invalid target IPv4")
			}
			if t.Name == "" || targets[t.Name] {
				return fail("empty or duplicate target name")
			}
			targets[t.Name] = true
			if t.Port < 1 || t.Port > 65535 {
				return fail("invalid target port")
			}
			ep := netip.AddrPortFrom(a, uint16(t.Port))
			if endpoints[ep] {
				return fail("duplicate target endpoint")
			}
			endpoints[ep] = true
			for _, s := range r.Match.Destinations {
				p, _ := netip.ParsePrefix(s)
				if p.Bits() == 32 && p.Addr() == a {
					return fail("target equals original /32 destination")
				}
			}
			total++
			if total > 16384/c.Replication.Queue {
				return fail("aggregate queue limit is 16384 positions")
			}
		}
	}
	if c.Metrics.Enabled {
		if a, e := netip.ParseAddrPort(c.Metrics.Listen); e != nil || a.Port() == 0 {
			return fail("metrics.listen must be an IP:port")
		}
	}
	if c.Logging.Level != "debug" && c.Logging.Level != "info" && c.Logging.Level != "warn" && c.Logging.Level != "error" {
		return fail("invalid logging level")
	}
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return fail("invalid logging format")
	}
	return nil
}
