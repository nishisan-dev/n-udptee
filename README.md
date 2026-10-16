# n-udptee — Transparent UDP Packet Replication & Fan-out for Linux

[![CI](https://github.com/nishisan-dev/n-udptee/actions/workflows/ci.yaml/badge.svg)](https://github.com/nishisan-dev/n-udptee/actions/workflows/ci.yaml)
![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)
![Linux](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-555?logo=linux&logoColor=white)
![UDP/IPv4](https://img.shields.io/badge/protocol-UDP%20%2F%20IPv4-2563eb)

**Capture one UDP datagram and replicate it to multiple destinations — without load balancing, changing the payload, or interrupting the original listener.**

**n-udptee** is a Linux-native **UDP packet duplicator, UDP mirror, and 1:N UDP fan-out relay** written in Go. It uses **libpcap/BPF** for passive ingress capture and supports **source IP and source UDP port preservation** through raw IPv4 packet transmission.

Built for **SNMP trap forwarding and duplication**, it also handles **Syslog over UDP, NetFlow, and other UDP traffic** without parsing their application protocols.

**[English](README.md) | [Português (Brasil)](README.pt-BR.md)**

> [!IMPORTANT]
> This is **UDP/IPv4 only** (not TCP, IPv6, or a generic network tap). Delivery is **best effort**. Preserving an original source address depends on routing, firewall, NAT, and anti-spoofing policies along the path.

## Why n-udptee?

A typical DNAT rule changes a packet's destination; it does **not** automatically send the same UDP datagram to multiple independent collectors. Likewise, ordinary load balancing chooses a destination rather than replicating to **all** destinations.

n-udptee passively observes matching inbound traffic, leaves the original UDP receiver alone, and independently attempts to forward an identical UDP **payload** to every configured target.

```text
                    SNMP device / UDP sender
                               |
                        UDP datagram
                               |
                   Linux host: eth0 ingress
                         /            \
           normal Linux receive       libpcap + BPF
                   |                         |
          original UDP receiver       decode + first-match rule
                                             |
                                      UDP packet fan-out
                                      /             \
                              bounded queue A   bounded queue B
                                    |                 |
                              target A           target B
                               (copy)             (copy)
```

### Features

- **True 1:N UDP replication:** every selected datagram triggers an independent attempt for each configured receiver, never round-robin.
- **Passive packet capture:** does not bind to UDP/162, modify iptables/nftables, intercept traffic, or stop the original receiver.
- **Two forwarding modes:** `raw_ipv4` preserves the original source IPv4 address and UDP port; `udp_socket` forwards the same payload through a normal UDP socket.
- **Byte-for-byte payload preservation:** SNMP traps, UDP syslog, NetFlow, or arbitrary binary UDP payloads are not decoded or modified.
- **Filtering:** libpcap BPF expression plus first-matching rule for source CIDRs, original destination CIDRs, and UDP destination ports.
- **Independent bounded queues:** one worker per configured target; a slow or unreachable receiver does not block the others.
- **Operational visibility:** Prometheus metrics, `/healthz`, structured logs, and per-target transmission/drop counters.
- **Linux deployment:** Go + CGO/libpcap, systemd example, CI and namespace/veth integration tests on amd64 and arm64 runners.

## Use cases

| Scenario | What n-udptee does |
| --- | --- |
| **SNMP trap duplication** | Mirror UDP/162 traps to two or more fault-management or NMS collectors while keeping the existing `snmptrapd` receiver |
| **Monitoring migration** | Feed old and new monitoring platforms simultaneously during a cutover |
| **UDP syslog replication** | Forward selected UDP syslog payloads to independent logging collectors |
| **NetFlow / UDP telemetry fan-out** | Replicate incoming UDP telemetry to multiple analysis pipelines |
| **Packet analysis and troubleshooting** | Passively copy selected datagrams to a controlled test receiver |

The tool does **not** interpret SNMP PDUs, acknowledge traps, reconstruct fragmented UDP messages, or provide delivery guarantees.

## Forwarding modes

| Mode | Payload delivered | Source address seen by additional receivers |
| --- | --- | --- |
| `raw_ipv4` (**default**) | Identical UDP payload | Original source IPv4 address and UDP port, unless the network rewrites/blocks them |
| `udp_socket` | Identical UDP payload | Source address and port selected by the relay host's kernel |

In `raw_ipv4` mode, n-udptee **constructs a new IPv4/UDP packet** and recalculates both checksums. It preserves the source IPv4, source UDP port, and payload, but **does not** preserve Ethernet headers, VLAN tags, IPv4 options, original packet ID, TTL, DSCP, or ECN.

Use raw mode only in networks where you are authorized to emit packets with the original sender's IP. Anti-spoofing rules, reverse-path filtering, NAT, VRFs, or routing may cause packets to disappear or change source IP. Validate the result with `tcpdump` on each receiver.

## Quick start (Ubuntu / Debian)

**Requirements:** Linux amd64 or arm64, the Go version specified by `go.mod` (currently 1.27.2), a C compiler, and libpcap development headers. The binary uses **CGO**. Cross-compiling is not as simple as setting `GOARCH` because a compatible C toolchain and libpcap are required.

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev iproute2 tcpdump python3

git clone https://github.com/nishisan-dev/n-udptee.git
cd n-udptee

make build
./build/n-udptee --help
./build/n-udptee version
./build/n-udptee check --config configs/example.yaml
```

`check` validates YAML and compiles the BPF filter for Ethernet offline. It does **not** need root, open the interface, or require that the configured interface exists.

Update `configs/example.yaml` for your network before running. The example uses documentation-only IP ranges, not working destination addresses:

```yaml
version: 1
capture:
  interface: eth0
  bpf: "ip and udp and dst port 162"
  direction: in
  promiscuous: false
  snaplen: 65535
  buffer_size_bytes: 33554432

replication:
  mode: raw_ipv4
  ttl: 64
  queue_size_per_target: 4096
  on_queue_full: drop_newest

rules:
  - name: snmp-traps
    match:
      source_cidrs: ["0.0.0.0/0"]
      destination_cidrs: ["192.0.2.10/32"]
      destination_ports: [162]
    targets:
      - {name: fm-primary, ip: 198.51.100.20, port: 162}
      - {name: fm-secondary, ip: 198.51.100.21, port: 162}

metrics:
  enabled: true
  listen: "127.0.0.1:9109"

logging:
  level: info
  format: json
```

This SNMP-trap example sends one copy to **each** of `fm-primary` and `fm-secondary`, while the receiver at the original destination remains independent. To use normal UDP socket forwarding instead, set `replication.mode: udp_socket`.

Once the configuration contains your **real** interface, destinations, and routing, grant the executable packet-capture privileges and run it:

```bash
sudo setcap cap_net_raw+ep ./build/n-udptee
./build/n-udptee run --config configs/example.yaml
```

Packet capture requires privileges even in `udp_socket` mode; only the raw-socket sender is avoided in that mode. `CAP_NET_RAW` works on many installations, but the environment/driver/security policy may require additional permissions. The program reports errors and does not change host privileges automatically. Reapply file capabilities after replacing the binary.

## Architecture and packet flow

The daemon has one capture loop and one independent sender worker per configured target — **not one goroutine per packet**. Each matching datagram is associated with the **first matching rule**; targets are statically configured, never extracted from incoming packet data.

```text
   Ethernet / VLAN ingress
           |
    libpcap + ingress BPF
           |
     IPv4/UDP decoder
           |
    first-matching rule
           |
   shared immutable payload
           |
      fan-out engine
     /       |       \
 queue A  queue B  queue N     (bounded, drop_newest)
    |        |        |
 sender A sender B sender N   (raw_ipv4 or udp_socket)
```

Ingress-only capture (`PCAP_D_IN`) prevents the process from capturing its own locally transmitted packets again. The runtime **fails closed** if ingress-only direction cannot be enforced; it does not silently fall back to capturing both directions. Only Ethernet physical/VLAN interfaces are supported, with up to two VLAN tags. `any` and loopback interfaces are not supported.

## Configuration and behavior

- **Rules:** each rule combines source CIDR, original destination CIDR, and destination-port matches with AND. Values *within* a list are OR. The first matching rule wins.
- **Mandatory fields:** version 1, explicit interface and BPF expression, named rules, non-empty matching CIDR/port lists, and named targets with IP/port.
- **Validation:** unknown/duplicate YAML keys, extra YAML documents, IPv6, invalid ports, duplicate rule/target names, and duplicate IP:port targets within the same rule are rejected.
- **Output safety:** multicast/unspecified/limited-broadcast targets are disallowed; local subnet broadcasts are rejected at runtime. Remote directed broadcasts require operator review.
- **Original destination:** a target equal to an original destination `/32` is rejected. For wider CIDRs, sending a copy to the packet's original destination IP is suppressed at runtime, even with a different target port.
- **Queue limits:** `queue_size_per_target` from 1 to 65536, with an aggregate maximum of **16384** slots. The only queue-full strategy is `drop_newest`. Payloads are shared between target jobs to limit allocations, but queued payloads still consume memory.
- **Datagram limits:** at most 65507 UDP payload bytes. Supported TTL 1–255, snaplen 64–262144, and capture buffer 1 byte–1 GiB. Increase snaplen for large packets when necessary.
- **Defaults:** as shown in the example, except interface, BPF, and rules. Logging defaults to JSON/info and HTTP to the loopback interface. Disabling `metrics.enabled` also disables `/healthz`.
- **No automatic reconfiguration:** the process does not manage routing, ARP, network interfaces, firewall rules, or system security settings.

### Fragmentation, MTU, and checksums

Incoming fragmented IPv4 packets (`MF` or a nonzero fragment offset) are discarded: **IP reassembly is not implemented**. Some BPF filters can exclude non-initial fragments before the decoder sees them.

The raw IPv4 sender builds a 20-byte IPv4 header with zero TOS, DF set, configurable TTL, and software-calculated IPv4/UDP checksums. `IP_HDRINCL` allows Linux to populate some IPv4 fields. When route MTU is insufficient, sending may fail with `EMSGSIZE`; **no truncation, fragmentation, or retry** occurs. A captured source address of `0.0.0.0` is rejected for raw transmission because the kernel would replace it.

Incoming packet checksums are not a decode acceptance criterion because capture/offload effects can interfere with their visibility. The output checksums are recalculated.

## Observability

The optional HTTP endpoint defaults to `127.0.0.1:9109`:

```bash
curl -f http://127.0.0.1:9109/healthz
curl http://127.0.0.1:9109/metrics

# Verify original inbound traffic at the relay:
sudo tcpdump -ni eth0 -Q in 'ip and udp and dst port 162' -vvv -XX

# Verify copied UDP packets at each additional receiver:
sudo tcpdump -ni eth0 'ip and udp and dst port 162' -vvv -XX
```

Key Prometheus metrics use the `n_udptee_` prefix:

| Metric | What it tracks |
| --- | --- |
| `capture_packets_total`, `capture_bytes_total` | Captured traffic by interface |
| `packets_matched_total` | Traffic selected by rule |
| `packets_dropped_total` | Drops and suppressed copies by reason |
| `replicas_enqueued_total` | Accepted replica jobs per rule/target |
| `replicas_send_success_total` | Successful send syscalls, **not guaranteed delivery** |
| `replicas_send_errors_total` | Failed send attempts per rule/target/reason |
| `replicas_queue_dropped_total` | Queue-full drops per rule/target |
| `target_queue_depth` | Waiting jobs per target |
| `pcap_kernel_drops_total` | Kernel/libpcap capture-drop statistics |

Decoding/drop reasons include `malformed`, `fragment`, `non_ipv4`, `non_udp`, `truncated`, `unmatched`, `original_destination`, and `shutdown`. Send error reasons include `mtu`, `unreachable`, `permission`, `backpressure`, and `send`.

Structured logs support JSON/text and debug/info/warn/error. Payload bytes are not logged; repeated target send errors are rate-limited in logs while counters still track every error. `SIGINT`/`SIGTERM` stop ingress and drain queues for up to five seconds.

`/healthz` reports successful service initialization, **not** delivery health for every remote destination. There is no built-in HTTP authentication/TLS; bind locally or protect externally.

## systemd deployment

Review [the example service unit](deploy/systemd/n-udptee.service), update its paths, and change the configuration before enabling the service:

```bash
sudo install -m 0755 build/n-udptee /usr/local/bin/n-udptee
sudo install -d /etc/n-udptee
sudo install -m 0644 configs/example.yaml /etc/n-udptee/config.yaml
# Edit /etc/n-udptee/config.yaml for your real interface, IPs, and targets.
sudo install -m 0644 deploy/systemd/n-udptee.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now n-udptee
journalctl -u n-udptee -f
```

The example unit uses a dynamic user and `CAP_NET_RAW`. Its shutdown timeout allows the queue drain to finish. It does not isolate network access because capture requires the real ingress interface.

## Testing and benchmarking

```bash
make fmt-check vet test race check
make fuzz
make integration
make bench
make benchmark
```

Standard tests do not silently run privileged integration tests. `make integration` explicitly enables a sandboxed Linux network namespace/veth lab; missing tools or privileges cause an explicit failure. The lab covers an original receiver, two additional receivers, packet identity, source preservation, independent target failures, same-interface output, MTU behavior, bursts, and shutdown.

`make bench` is an in-memory decoder/fan-out microbenchmark, **not a network throughput claim**. `make benchmark` exercises a 20,000-datagram, two-target raw IPv4 lab and reports measured CPU, RSS, rates, and drop counts. See the [implementation report](docs/IMPLEMENTATION-REPORT.md) and [validation artifacts](docs/validation/) for actual test runs and methodology.

The GitHub Actions workflow builds/tests on native Linux amd64 and arm64 runners with libpcap/CGO. The recorded local execution in the report was on amd64; do not infer extra validation or production SLAs.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `pcap.h` / `-lpcap` error | Install libpcap headers and enable CGO |
| Capture or raw socket permission denied | File capabilities, environment policy, network interface |
| Runtime rejects ingress capture | Libpcap/driver must support `PCAP_D_IN` |
| Nothing captured | Correct ingress interface, VLANs, BPF expression, actual inbound traffic |
| Captured but not replicated | Original destination, port, CIDR matches, rule ordering |
| Only one target loses packets | Its queue drops, send errors, route and remote firewall |
| `mtu` errors | Route MTU vs. IPv4 + UDP + payload, no fragmentation |
| Receiver sees a different source IP | NAT, anti-spoofing, reverse-path filtering, network policy |
| Original gets duplicate packets | Remove it from targets and investigate external return paths |
| `/metrics` or `/healthz` not reachable | Bind address, port collision, `metrics.enabled` |

## Scope and limitations

**Supported:** passive Ethernet/VLAN ingress capture, Linux, UDP over IPv4, BPF filtering, static 1:N fan-out, raw source-IP-preserving transmission, ordinary UDP socket forwarding, Prometheus metrics, systemd.

**Not supported:** TCP, IPv6, IP-fragment reassembly, application-level SNMP parsing, delivery acknowledgements, retries, disk spool, dynamic reload, distributed clustering, or more than one capture interface per process.

The original UDP application remains independent from the replicator. **Successful forwarding means a send syscall accepted the packet; it does not prove the receiver application processed it.**

## Documentation

- [Português (Brasil): installation and operation](README.pt-BR.md)
- [Technical specification](docs/N-UDPTEE-SPEC.md) (Portuguese)
- [Implementation and validation report](docs/IMPLEMENTATION-REPORT.md) (Portuguese)
- [Example configuration](configs/example.yaml)
- [systemd service](deploy/systemd/n-udptee.service)
- [Continuous integration](.github/workflows/ci.yaml)

**License:** no license has been selected/published by the author yet. Public source availability does not imply an open-source license grant.
