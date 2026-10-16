<!-- Portuguese translation of the main README. Keep the English and Portuguese documentation aligned when changing CLI, configuration, metrics, or behavior. -->

# n-udptee

Captura passiva e replicação 1:N de UDP sobre IPv4 para Linux, em Go com
CGO/libpcap. Cada datagrama selecionado gera uma tentativa independente por
destino configurado. O listener original continua recebendo pela pilha Linux:
o programa não ocupa UDP/162, não intercepta pacotes nem altera firewall.

```text
interface ingress ── libpcap/BPF ── decoder ── primeira regra correspondente
       │                                         ├─ fila A ─ sender A
       └─ pilha Linux ─ receptor original        └─ fila B ─ sender B
```

| Modo | Payload | Origem observada pelos receptores extras |
|---|---|---|
| `raw_ipv4` (padrão) | Idêntico byte a byte | IPv4 e porta UDP originais, salvo interferência da rede/NAT |
| `udp_socket` | Idêntico byte a byte | IPv4 e porta escolhidos pelo kernel do relay |

O serviço não interpreta SNMP. Traps, Syslog e NetFlow são apenas bytes UDP.
A entrega é **best effort**: sucesso significa aceitação da syscall, sem ACK,
retries, spool ou garantia de chegada. Filas cheias descartam a réplica nova
apenas daquele destino. O original não depende do processo.

## Instalação e uso

Requer Linux amd64 ou arm64, Go compatível com `go.mod`, GCC e libpcap com headers.
Build nativo com CGO; não basta definir GOARCH para cross-compilar libpcap.

```sh
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev iproute2 tcpdump python3
make build
./build/n-udptee --help
./build/n-udptee version
./build/n-udptee check --config configs/example.yaml
./build/n-udptee check -c configs/example.yaml
```

`check` valida YAML e compila BPF para Ethernet offline, sem root e sem abrir
ou exigir a existência da interface. `run` confirma interface, link type,
BPF e `PCAP_D_IN`; falha se ingress não puder ser garantido. Não há fallback
para `inout`. São aceitas interfaces Ethernet físicas ou VLAN; `any`, loopback e outros tipos de enlace não são suportados.

Adapte `configs/example.yaml`: os blocos 192.0.2.0/24 e 198.51.100.0/24 são
reservados para documentação. Exemplo completo:

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

Use `udp_socket` em `replication.mode` para relay. Todos os demais componentes
são os mesmos. Uma goroutine lê a captura e um worker por target transmite,
sem goroutine por pacote. Os destinos são estáticos, nunca fornecidos pelo tráfego.

```sh
sudo setcap cap_net_raw+ep ./build/n-udptee
./build/n-udptee run --config configs/example.yaml
```

A captura libpcap requer permissões mesmo no modo `udp_socket`; o relay dispensa
o socket IPv4 raw, não as permissões da captura. `CAP_NET_RAW` basta em muitas
instalações Linux; políticas de segurança, driver ou ambiente podem exigir
permissões adicionais. O programa informa o erro e não tenta ajustar privilégios.
Capabilities de arquivo precisam ser reaplicadas após substituir o binário.
Não é necessário manter o daemon como root. Use spoofing somente em redes sob
administração/autorização do operador.

## Configuração e limites

- Obrigatórios: versão 1, interface explícita, BPF, regras nomeadas, listas não
  vazias de CIDRs de origem/destino, portas e targets com nome/IP/porta.
- Defaults para campos omitidos: os valores do exemplo, exceto interface, BPF e
  regras. JSON/info, HTTP habilitado no loopback. `metrics.enabled: false`
  desabilita todo o servidor, inclusive healthz. Endereço HTTP deve ser IP:porta.
- YAML desconhecido, chaves duplicadas, documentos extras, IPv6, portas fora de
  1–65535, nomes de target duplicados globalmente e nomes de regra duplicados
  são rejeitados. Endpoints IP/porta duplicados na mesma regra também.
- CIDRs e portas dentro de cada lista são alternativas (OR); entre origem,
  destino e porta aplica-se AND. A primeira regra correspondente vence.
- Multicast, unspecified e broadcast limitado são proibidos como targets.
  Broadcasts das sub-redes locais são rejeitados no `run`; broadcasts dirigidos
  remotos dependem da máscara da rede remota e precisam ser evitados pelo operador.
- Um target com IP igual a um destino `/32` é rejeitado. Com CIDRs amplos, somente
  a réplica cujo IP coincide com o destino original é suprimida em runtime,
  contando `original_destination`, mesmo que a porta configurada seja diferente.
  Essa é a exceção deliberada à tentativa por target para evitar duplicação no original.
- Apenas `direction: in`, `on_queue_full: drop_newest`, TTL 1–255,
  snaplen 64–262144 e buffer pcap 1 byte–1 GiB. O snaplen padrão pode truncar
  datagramas IPv4 máximos com cabeçalhos Ethernet; aumente para 262144 se necessário.
- Filas: 1–65536 posições por target, com soma máxima de **16384 posições**;
  portanto, na prática uma fila não pode exceder o limite agregado. Até 65507
  bytes de payload por datagrama. O limite conservador dos payloads enfileirados
  é aproximadamente 1 GiB, mais um job ativo por worker, buffers pcap, sockets,
  estruturas Go e margem do GC. Payload é compartilhado entre réplicas.
  Diminua filas/buffer para implantações com menor orçamento de memória.
- Regras não substituem BPF eficiente. Restrinja protocolo e porta na captura;
  o compilador valida sintaxe, não demonstra equivalência semântica às regras.

## Rede e transparência

`raw_ipv4` cria um novo pacote IP com cabeçalho de 20 bytes, TOS zero, DF,
TTL configurado e checksums IPv4 e UDP recalculados, incluindo pseudo-header.
Preserva apenas payload e origem IP/porta; não clona MAC, VLAN, opções IP,
ID, TTL ou DSCP/ECN. Origem `0.0.0.0` em raw gera erro de envio: o kernel
substituiria esse endereço com `IP_HDRINCL`, impedindo sua preservação. `IP_HDRINCL` permite ao Linux preencher comprimento,
checksum e ID zero. O roteamento e ARP são do kernel.

Pacotes acima da MTU da rota podem falhar com `EMSGSIZE`: não há truncamento,
fragmentação manual ou retry. Entradas IPv4 com MF ou offset são descartadas.
Um BPF `udp` pode ocultar fragmentos não iniciais; a métrica conta somente os
fragmentos efetivamente observados. O decoder valida estrutura e comprimentos;
não usa checksums de entrada como condição de aceitação, pois offload pode
afetar o que libpcap observa. As réplicas têm checksum calculado em software.

Firewalls, antispoofing, `rp_filter`, NAT/SNAT, VRFs, rotas e tráfego assimétrico
podem impedir entrega ou mudar a origem observada. Não há ajuste automático
dessas políticas. Capture no destino para confirmar a transparência real.
Captura ingress evita recapturar a própria saída na interface monitorada;
loops que atravessam e retornam por equipamentos externos devem ser evitados
pela topologia e BPF. O programa não adiciona identificador ao payload.

## Operação e métricas

```sh
curl -f http://127.0.0.1:9109/healthz
curl http://127.0.0.1:9109/metrics
sudo tcpdump -ni eth0 -Q in 'ip and udp and dst port 162' -vvv -XX
# No receptor adicional, usando a interface real:
sudo tcpdump -ni eth0 'ip and udp and dst port 162' -vvv -XX
```

`/healthz` retorna 200 depois da inicialização completa; captura/servidor
fatal encerram o serviço. Erro remoto isolado não torna healthz negativo.
Bind HTTP inválido/ocupado impede inicialização. Sem autenticação/TLS; mantenha
o bind local ou forneça proteção externa ao expor métricas.

| Métrica (prefixo `n_udptee_`) | Labels / significado |
|---|---|
| `capture_packets_total`, `capture_bytes_total` | `interface`; frames e bytes capturados |
| `packets_matched_total` | `rule`; datagramas da primeira regra correspondente |
| `packets_dropped_total` | `reason`; rejeição/supressão/descarte no shutdown |
| `replicas_enqueued_total` | `rule,target`; jobs aceitos |
| `replicas_send_success_total` | `rule,target`; syscall aceita, não entrega |
| `replicas_send_errors_total` | `rule,target,reason`; envio falhou sem retry |
| `replicas_queue_dropped_total` | `rule,target`; fila cheia naquele destino |
| `target_queue_depth` | `target`; jobs esperando, exclui envio ativo |
| `pcap_kernel_drops_total` | `interface`; deltas reais de `pcap_stats.ps_drop` |

Motivos de decode: `malformed`, `fragment`, `non_ipv4`, `non_udp`, `truncated`;
outros descartes: `unmatched`, `original_destination`, `shutdown`. Erros de envio:
`mtu`, `unreachable`, `permission`, `backpressure`, `send`. Não há labels derivados
de payload/endereço capturado. Séries aparecem quando inicializadas/usadas.
Estatísticas libpcap são consultadas periodicamente; indisponibilidade é logada
sem inventar contadores. `ps_drop` não inclui necessariamente perdas anteriores
à captura ou drops da interface. Métricas Go/processo também são expostas.

Logs aceitam `json|text` e `debug|info|warn|error`; não registram payload nem cada
pacote. Erros de envio repetidos são limitados a uma linha por segundo por target,
enquanto todos os erros incrementam contadores. SIGINT/SIGTERM param novas
entradas e drenam filas por até cinco segundos, cancelando envios restantes.

## systemd

Revise `deploy/systemd/n-udptee.service` e adapte caminhos/configuração. Instalação
explícita pelo operador:

```sh
sudo install -m 0755 build/n-udptee /usr/local/bin/n-udptee
sudo install -d /etc/n-udptee
sudo install -m 0644 configs/example.yaml /etc/n-udptee/config.yaml
# Edite /etc/n-udptee/config.yaml para a rede real antes de iniciar.
sudo install -m 0644 deploy/systemd/n-udptee.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now n-udptee
journalctl -u n-udptee -f
```

O unit usa usuário dinâmico e CAP_NET_RAW; não isola a rede, pois precisa observar
a interface real. Timeout de parada de sete segundos acomoda o drain de cinco.

## Testes e benchmark

```sh
make fmt-check vet test race check
make fuzz
make integration
make bench
make benchmark
```

A suíte comum informa explicitamente que integração privilegiada está desabilitada.
`make integration` habilita-a; falta de ferramenta/permissão resulta em falha,
sem mascarar o bloqueio. O runner usa user, mount e network namespaces, monta
um `/run/netns` privado e cria cinco namespaces: emissor, replicador/original,
A, B e bridge. Não modifica interfaces, rotas ou sysctls de rede do host.

Se user namespaces forem bloqueados pela distribuição, execute `sudo -E make
integration` em uma máquina Linux de laboratório; as alterações de rede continuam
isoladas. São necessários `unshare`, `mount`, `ip`, `sysctl`, Python 3 e tcpdump,
com CAP_NET_ADMIN/CAP_NET_RAW disponíveis **dentro** do laboratório. Um sandbox
que bloqueie criação de namespaces precisa de um runner apropriado.

Para guardar evidências:

```sh
N_UDPTEE_LAB_OUTPUT="$PWD/build/reports/integration" make integration
```

São verificadas cópias únicas, origem e payload, saída pela mesma interface de
captura sem loops, tráfego sem match, falha de A com B funcionando, erro de rota,
MTU raw, bursts, memória e SIGTERM. PCAP/tcpdump, logs e payloads recebidos ficam
no diretório de evidências. Unitários usam serialização independente do gopacket
para conferir checksums e simulam determinísticamente backpressure/shutdown.

`make bench` mede decoder/fan-out em memória (o sender do microbenchmark descarta
os jobs); não representa throughput de rede nem entrega. `make benchmark` injeta
20000 datagramas de 256 bytes em raw com dois targets, medindo pps capturados e
enviados, CPU, RSS e drops em `build/benchmark/benchmark.json`. Inclui custos do
laboratório/gerador Python e espera de drenagem: compare apenas ambientes e
métodos equivalentes. Resultados medidos nesta entrega estão em
`docs/IMPLEMENTATION-REPORT.md`; não são promessa de capacidade.

A CI compila e testa nativamente em Linux amd64 e arm64 com CGO/libpcap, executa
race/fuzz e o laboratório. Não presume cross-compilation CGO trivial.

## Releases automáticas

Envie uma tag SemVer estável para disparar `.github/workflows/release.yaml`:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

O workflow exige exatamente `vX.Y.Z`, sem zeros iniciais, sufixos ou build metadata.
Ele executa a CI completa nas duas arquiteturas, compila nativamente Linux amd64
e arm64 e publica uma release com notas automáticas, dois arquivos `.tar.gz`
e `SHA256SUMS`. Cada pacote inclui binário, README nos dois idiomas, YAML e unit systemd. A versão
do binário vem da tag, com commit e horário de build.

Os binários usam CGO e dependem de libpcap compartilhada (`libpcap.so.0.8`) e de
runtime compatível com Ubuntu 24.04/glibc 2.39 ou posterior. Para distribuições
mais antigas, compile a partir do código usando a libpcap local.

A publicação usa draft até todos os arquivos estarem enviados. Se testes, build
ou publicação falharem, a limpeza não é executada. Após publicar, ficam somente
as **cinco releases estáveis mais recentes pela data de publicação**; as anteriores
e seus assets são excluídos. Tags Git, drafts, prereleases e releases com nomes
fora de `vX.Y.Z` são preservados. Uma nova publicação, mesmo de versão numericamente
menor, conta como mais recente. O fluxo usa `GITHUB_TOKEN` com escrita apenas no
job de publicação, sem PAT adicional. Criar a tag apenas localmente não dispara
o workflow; é necessário enviá-la ao GitHub.

## Troubleshooting e limites da v0.1.0

| Sintoma | Verificação |
|---|---|
| Erro `pcap.h` ou `-lpcap` | Instale `libpcap-dev` e mantenha CGO habilitado |
| Abertura pcap/raw negada | Capabilities, políticas do ambiente e interface |
| Não inicia após configurar ingress | Driver/libpcap precisa aceitar `PCAP_D_IN` |
| Não captura | Interface, VLAN, direção, BPF e fluxo chegando realmente ao host |
| Captura sem match | CIDRs/porta, ordem das regras e destino original |
| Apenas um target perde | Drops daquela fila, erro de envio, rota/firewall remoto |
| `mtu` nos erros | MTU da rota menor que IPv4+UDP+payload; não há fragmentação |
| Origem muda ou nada chega em raw | NAT, antispoofing, rp_filter e roteamento |
| Original duplicado | Remova-o dos targets e verifique caminhos externos de retorno |
| HTTP não abre | Endereço ocupado, listen inválido ou `metrics.enabled: false` |

IPv4/UDP e Ethernet/VLAN somente; até duas tags VLAN. Sem TCP, IPv6,
reassemblagem, parsing SNMP, reload, disco, eleição de líder ou administração
remota. Uma interface por processo. Nenhuma garantia de entrega UDP.

A compilação offline usa diretamente `pcap_open_dead`/`pcap_compile`/`pcap_close`
para evitar uma falha de `Handle.Close` em handles mortos do gopacket v1.7.4 com
libpcap 1.10.1. A captura em execução usa `github.com/gopacket/gopacket/pcap`.

Licença ainda não escolhida pelo autor; nenhum arquivo de licença foi presumido.
A especificação original está em `docs/N-UDPTEE-SPEC.md`.
