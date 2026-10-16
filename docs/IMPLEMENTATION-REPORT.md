# Relatório de implementação — n-udptee v0.1.0

Data: 16/10/2026 (America/Sao_Paulo). Fonte de aceite: `N-UDPTEE-SPEC.md`, lida integralmente antes da implementação.

## Resultado funcional

Implementação completa do fluxo passivo UDP/IPv4 com libpcap ingress/BPF, configuração YAML estrita, CLI, decoder Ethernet/VLAN, primeira regra vencedora, fan-out com filas limitadas independentes e os senders `raw_ipv4` e `udp_socket`. Inclui métricas Prometheus, healthz, logs estruturados, limitação de logs repetidos e shutdown com drain de cinco segundos.

**O critério central foi executado e passou em namespaces/veth Linux:** um datagrama destinado a UDP/162 do receptor original foi entregue uma vez ao original e uma vez a cada receptor adicional, com payload idêntico. Em raw, ambos observaram `10.10.0.2:40000`, a origem do emissor. O daemon não ocupa a porta de entrada. Também passaram payload vazio/binário, reescrita de porta de destino para 1162, saída pela mesma interface sem loop, falha isolada de A, erro de rota, MTU raw, burst, memória e SIGTERM.

O módulo `github.com/nishisan-dev/n-udptee` foi obtido do remote `https://github.com/nishisan-dev/n-udptee.git`. O repositório não possuía commits nem código inicial; a especificação preexistente foi preservada. Não foi criada licença nem realizado commit/push. `version` informa commit `unknown` enquanto não houver commit ou override de build.

## Etapas entregues

| Etapa | Implementação e verificação |
|---|---|
| Bootstrap/configuração | Módulo real, CLI e defaults, validação YAML/CIDRs/portas/nomes/endpoints/limites; testes de configuração e CLI |
| Captura libpcap/BPF | Ativação configurada, interface explícita, Ethernet/VLAN, `DirectionIn` obrigatório, BPF offline e runtime, timeout e estatísticas reais |
| Decoder | Tamanhos e offsets verificados, payload próprio imutável, fragmentos/protocolos/truncamentos rejeitados; fixture, unitários e fuzz |
| Regras/filas | Primeira regra vence, fila/worker por destino, enqueue não bloqueante, métricas e drain/cancelamento; testes determinísticos com sender bloqueado |
| Senders | UDP socket com deadline; raw Linux isolado com `IP_HDRINCL`, DF, origem preservada e checksums IPv4/UDP; comparação independente com gopacket e checksum zero |
| Observabilidade | Métricas exigidas, healthz, HTTP local por padrão, falha de bind fatal, logs JSON/text e resumo de encerramento |
| Integração | Laboratório isolado com emissor, original/replicador, dois receptores e bridge; testes executados sem sudo usando capabilities nos namespaces |
| Documentação/empacotamento | README operacional, YAML completo, Makefile, AGENTS, unit systemd, CI nativa amd64/arm64 e benchmarks |

## Comandos e resultados reais

Executados com Go `go1.27.2 linux/amd64`, GCC e libpcap `1.10.1`, em Linux `6.8.0-138-generic`, Intel Core 7 150U. Headers libpcap foram extraídos de pacotes Debian em `/tmp/n-udptee-deps`; não houve instalação de pacotes nem alteração de rede/serviços do host.

Para compilar neste ambiente específico, foram usados:

```sh
export CGO_CFLAGS=-I/tmp/n-udptee-deps/root/usr/include
export CGO_LDFLAGS=-L/tmp/n-udptee-deps/root/usr/lib/x86_64-linux-gnu
make fmt-check vet test race check
make fuzz
N_UDPTEE_LAB_OUTPUT="$PWD/build/reports/integration" make integration
make bench
./tests/integration/run.sh --binary ./build/n-udptee \
  --output ./build/reports/benchmark --benchmark 20000
```

Em uma instalação normal, `libpcap-dev` dispensa essas duas variáveis. Os comandos equivalentes de integração foram executados diretamente com `N_UDPTEE_INTEGRATION=1 go test -v -count=1 -timeout=120s ./tests/integration`.

| Verificação | Resultado |
|---|---|
| `gofmt` / `make fmt-check` | Sem diferenças |
| `go vet ./...` | Passou |
| `go test ./...` | Passou; integração opt-in explicitamente desabilitada nessa invocação |
| `go test -race ./...` | Passou |
| Build e `n-udptee check` | Passaram como usuário sem capabilities de rede |
| Fuzz decoder, 10 s, 2 workers | Passou; 306048 execuções, 7 novos casos interessantes |
| Integração opt-in namespaces/veth | Passou em 8,011 s, incluindo raw, relay e porta reescrita |
| Execução sem permissão de captura | Exit 1 com erro explícito `capture permissions/CAP_NET_RAW required: Permission Denied` |
| `systemd-analyze verify` | Reportou binário ausente em `/usr/local/bin/n-udptee` e avisos de units do host; não é validação operacional do serviço instalado |

Saídas persistidas: [qualidade](validation/final-checks.log), [fuzz](validation/fuzz.log), [integração](validation/integration.log), [microbenchmarks](validation/bench.log), [benchmark](validation/benchmark.json), [permissão](validation/unprivileged-run.log), [systemd](validation/systemd-verify.log).

Evidências de captura: [raw PCAP](validation/raw_ipv4.pcap), [raw tcpdump](validation/raw_ipv4-tcpdump.txt), [relay PCAP](validation/udp_socket.pcap), [relay tcpdump](validation/udp_socket-tcpdump.txt). O tcpdump confirmou `[udp sum ok]` em raw, sem `bad udp cksum`. Os logs do daemon, incluindo erros de rota/MTU e encerramento, estão no mesmo diretório.

Falhas intermediárias reais e resoluções:

- O linker inicialmente selecionou a biblioteca estática extraída e reportou referências `dbus_*` indefinidas; passou após apontar o linker para a biblioteca compartilhada já existente.
- `pcap.CompileBPFFilter` do gopacket v1.7.4 causou `SIGSEGV` ao fechar um handle offline com libpcap 1.10.1. A compilação offline usa agora `pcap_open_dead`/`pcap_compile`/`pcap_close` diretamente, sem `Handle.Close`/`pcap_breakloop`. A captura continua usando o pacote pcap exigido.
- O primeiro laboratório não pôde criar arquivos em `/run/netns`; o runner passou a montar `/run` privado dentro do mount namespace.
- O tcpdump confinado pelo ambiente teve falhas de mudança de usuário e de descritores herdados, produzindo inicialmente PCAP inválido. O runner não root preserva capabilities com `--keep-caps`; tcpdump grava em arquivo temporário próprio, recebe diagnósticos por pipe e termina por contagem. A suíte final e a leitura independente dos PCAPs passaram.

## Benchmark medido

Rodada final isolada com **256 bytes**, **dois targets**, modo raw, filas de **128 posições** por destino e 20000 datagramas injetados. Houve aquecimento de vizinhos/ARP antes da medição. Duração inclui inicialização do gerador e **1,1 s de espera** para drain/coleta libpcap; não representa a taxa instantânea durante o burst.

| Medida | Resultado |
|---|---:|
| Duração medida | 1.326780 s |
| Datagramas capturados | 20000 |
| Envios aceitos pela syscall | 39887 |
| Capturas por segundo, janela completa | 15074.09 |
| Envios por segundo, janela completa | 30063.00 |
| CPU do daemon | 0.47 s / 35.42% de um núcleo |
| RSS ao final | 90955776 bytes / 86.74 MiB |
| Drops reportados por libpcap | 0 |
| Réplicas descartadas por fila cheia | 113 |

Os 40000 jobs potenciais se dividiram em 39887 envios aceitos e 113 descartes de fila. O sucesso da syscall não confirma recepção pelo aplicativo remoto. Filas maiores podem reduzir descartes em bursts ao custo de memória e latência. Não há throughput garantido.

Microbenchmarks anteriores: decoder 265,3 ns/op, 384 B/op e 2 allocs/op; fan-out 308,2 ns/op e 0 allocs/op. O sender do microbenchmark descarta jobs e filas podem descartar sob carga; esses números não são throughput de rede.

## Decisões e limites explícitos

- Conforme escolha do usuário: targets iguais a destinos `/32` são rejeitados na configuração. Para CIDRs amplos, a réplica ao mesmo IP do destino original é suprimida com `original_destination`, inclusive com porta diferente. É uma exceção deliberada à tentativa por target.
- Máximo agregado de 16384 posições; payload compartilhado e sem goroutine por pacote. Memória inclui payloads retidos, jobs ativos, buffers pcap/socket e GC; o README apresenta o limite conservador e recomenda reduzir filas conforme orçamento.
- Origem `0.0.0.0` em raw é rejeitada no envio, pois `IP_HDRINCL` faria o kernel substituí-la; o serviço não afirma preservá-la silenciosamente.
- Destinos unspecified/multicast/broadcast limitado são rejeitados offline; broadcasts locais são rejeitados no runtime. Detectar broadcast dirigido remoto depende da máscara/topologia externa, explicitamente documentado.
- Checksum de entrada não é usado para rejeitar pacotes por conta de offload; estrutura/comprimentos são validados e checksums de saída são calculados em software.
- Captura Ethernet, até duas tags VLAN, uma interface, sem `any` ou loopback. Sem IPv6, parsing SNMP, reassemblagem, retries, spool, reload ou controle de rede do host.
- HTTP desabilitado por `metrics.enabled: false` também desabilita healthz. BPF é validado sintaticamente; eficiência/equivalência com regras depende da configuração.
- MTU, NAT, antispoofing, rp_filter, VRF e retornos por equipamentos externos permanecem limitações operacionais documentadas. Ingress impede recaptura da própria saída local.
- Nenhum teste privilegiado ficou bloqueado nesta entrega: o laboratório passou via user/network/mount namespaces. **arm64 não foi executado localmente**; a CI entregue usa runner nativo arm64, mas não foi disparada/publicada nesta sessão.
- O unit systemd foi entregue para instalação pelo operador; não foi instalado nem iniciado no host. A licença aguarda escolha do autor.

## Arquivos entregues

A árvore abaixo lista fontes, testes e documentação; evidências adicionais ficam em `docs/validation/`, e binário/artefatos locais em `build/` (ignorado pelo Git).

```text
.github/workflows/ci.yaml
.gitignore
AGENTS.md
Makefile
README.md
cmd/n-udptee/main.go
cmd/n-udptee/main_test.go
configs/example.yaml
deploy/systemd/n-udptee.service
docs/N-UDPTEE-SPEC.md
go.mod
go.sum
internal/app/app.go
internal/app/app_test.go
internal/bpf/compile.go
internal/capture/pcap.go
internal/capture/pcap_test.go
internal/config/config.go
internal/config/config_test.go
internal/decode/decode.go
internal/decode/decode_test.go
internal/engine/engine.go
internal/engine/engine_test.go
internal/match/match.go
internal/match/match_test.go
internal/metrics/metrics.go
internal/metrics/metrics_test.go
internal/model/datagram.go
internal/send/rawipv4/raw.go
internal/send/rawipv4/raw_test.go
internal/send/udpsocket/udp.go
internal/send/udpsocket/udp_test.go
tests/fixtures/ethernet-udp.hex
tests/integration/integration_test.go
tests/integration/lab.py
tests/integration/run.sh
docs/IMPLEMENTATION-REPORT.md
```
