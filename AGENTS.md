# n-udptee

Read docs/N-UDPTEE-SPEC.md completely before changing behavior. It is the
source of acceptance criteria. Preserve passive capture and first-rule-wins
1:N replication: every accepted datagram gets an independent, bounded attempt
for each target, never round-robin or load balancing. Preserve payload bytes;
raw_ipv4 preserves source IPv4/UDP port and recomputes both checksums.

Run make fmt-check vet test race check and make fuzz. Run make integration
when Linux user/mount/network namespaces are available; enabling integration
must fail on insufficient privileges, not silently skip. Report actual test
results and any environmental block. Never modify host network settings.
Update README when changing config, CLI, metrics or operational behavior.
Do not add stubs, blocking TODOs, runtime retries or unbounded packet queues.
Do not add a LICENSE without the author's explicit choice.
