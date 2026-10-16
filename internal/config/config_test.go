package config

import (
	"os"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	b, e := os.ReadFile("../../configs/example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(strings.NewReader(string(b))); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{string(b) + "\nunknown: 1", strings.Replace(string(b), "version: 1", "version: 2", 1), strings.Replace(string(b), "198.51.100.20", "::1", 1), strings.Replace(string(b), "queue_size_per_target: 4096", "queue_size_per_target: 0", 1), strings.Replace(string(b), "ip and udp and dst port 162", "bad bpf !!!", 1), string(b) + "\n---\nversion: 1"} {
		if _, e := Read(strings.NewReader(s)); e == nil {
			t.Errorf("accepted invalid config %s", s)
		}
	}
}

func TestValidationMatrix(t *testing.T) {
	data, err := os.ReadFile("../../configs/example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base := string(data)
	tests := map[string]func(*Config){
		"version": func(c *Config) { c.Version = 0 }, "interface": func(c *Config) { c.Capture.Interface = "" }, "any": func(c *Config) { c.Capture.Interface = "any" },
		"direction": func(c *Config) { c.Capture.Direction = "inout" }, "snaplen": func(c *Config) { c.Capture.Snaplen = 0 }, "buffer": func(c *Config) { c.Capture.Buffer = -1 },
		"mode": func(c *Config) { c.Replication.Mode = "other" }, "ttl": func(c *Config) { c.Replication.TTL = 256 }, "onfull": func(c *Config) { c.Replication.OnFull = "block" },
		"port": func(c *Config) { c.Rules[0].Targets[0].Port = 65536 }, "matchport": func(c *Config) { c.Rules[0].Match.Ports = []int{0} },
		"source": func(c *Config) { c.Rules[0].Match.Sources = []string{"::/0"} }, "destination": func(c *Config) { c.Rules[0].Match.Destinations = []string{"bad"} },
		"missingtargets": func(c *Config) { c.Rules[0].Targets = nil }, "missingrules": func(c *Config) { c.Rules = nil }, "missingmatch": func(c *Config) { c.Rules[0].Match.Ports = nil },
		"emptyname": func(c *Config) { c.Rules[0].Name = "" }, "rulesduplicate": func(c *Config) { c.Rules = append(c.Rules, c.Rules[0]) },
		"targetname": func(c *Config) { c.Rules[0].Targets[1].Name = c.Rules[0].Targets[0].Name },
		"endpoint":   func(c *Config) { c.Rules[0].Targets[1].IP = c.Rules[0].Targets[0].IP },
		"original":   func(c *Config) { c.Rules[0].Targets[0].IP = "192.0.2.10" }, "multicast": func(c *Config) { c.Rules[0].Targets[0].IP = "224.0.0.1" },
		"unspecified": func(c *Config) { c.Rules[0].Targets[0].IP = "0.0.0.0" }, "broadcast": func(c *Config) { c.Rules[0].Targets[0].IP = "255.255.255.255" },
		"aggregate": func(c *Config) { c.Replication.Queue = 16384 }, "http": func(c *Config) { c.Metrics.Listen = "0.0.0.0:0" },
		"logging": func(c *Config) { c.Logging.Level = "trace" }, "format": func(c *Config) { c.Logging.Format = "xml" }, "nulbpf": func(c *Config) { c.Capture.BPF = "ip\x00invalid" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c, e := Read(strings.NewReader(base))
			if e != nil {
				t.Fatal(e)
			}
			change(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	for _, invalid := range []string{base + "\nversion: 1", base + strings.Repeat(" ", 1<<20), strings.Replace(base, "version: 1\n", "", 1)} {
		if _, e := Read(strings.NewReader(invalid)); e == nil {
			t.Fatal("accepted malformed/oversized/missing config")
		}
	}
}

func TestFragmentOptions(t *testing.T) {
	b, e := os.ReadFile("../../configs/example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	legacy := strings.ReplaceAll(string(b), "reassembly:\n  enabled: false\n", "")
	legacy = strings.ReplaceAll(legacy, "  fragmentation: drop\n", "")
	c, e := Read(strings.NewReader(legacy))
	if e != nil {
		t.Fatal(e)
	}
	if c.Reassembly.Enabled || c.Replication.Fragmentation != "drop" {
		t.Fatal("legacy defaults changed")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Reassembly.TimeoutSeconds = 0 }, func(c *Config) { c.Reassembly.MaxDatagrams = 65537 }, func(c *Config) { c.Reassembly.MaxBytes = 1 }, func(c *Config) { c.Reassembly.MaxFragments = 1 }, func(c *Config) { c.Replication.Fragmentation = "retry" }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid fragment config accepted")
		}
	}
	c.Reassembly.Enabled = true
	c.Replication.Fragmentation = "auto"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}

func TestFragmentExample(t *testing.T) {
	c, err := Load("../../configs/fragments.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Reassembly.Enabled || c.Replication.Fragmentation != "auto" || c.Capture.Snaplen != 262144 {
		t.Fatal("opt-in example incomplete")
	}
}
