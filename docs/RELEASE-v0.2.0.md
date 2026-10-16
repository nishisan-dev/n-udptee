# n-udptee v0.2.0 — implementação e validação

Data: 16/10/2026, America/Sao_Paulo. Extensão aprovada na seção 16 da especificação.

## Entrega

- Remontagem IPv4/UDP opcional antes do matcher/fan-out, isolada por interface,
  VLAN, IPs e ID; ordem arbitrária e duplicatas exatas aceitas.
- Rejeição de overlaps, duplicatas conflitantes, DF+fragmentos, comprimentos
  incoerentes, desalinhamento e UDP inválido. Nunca emitir dados parciais.
- Orçamentos de memória, contextos e fragmentos, timeout monotônico não renovável,
  limpeza ociosa e no shutdown. Tombstones limitados suprimem duplicatas tardias.
- Fragmentação raw opcional por MTU real da rota de cada target; IP/porta de origem
  preservados, checksum UDP completo e IPv4 individual, offsets/MF/ID corretos.
- Pool de 65535 IDs, sem reutilização por 60 s, com descarte/backpressure sem espera.
- Relay opcionalmente habilita fragmentação do kernel; origem permanece a do relay.
- Métricas de remontagem, recursos retidos, tentativas raw e fragmentos aceitos.
  Sucesso lógico exige todos os fragmentos aceitos; erro interrompe só aquele target.
- Defaults da v0.1.0 preservados; `version: 1` aceita configuração antiga sem campos
  novos. Exemplo completo opt-in em `configs/fragments.yaml`, documentação bilíngue
  e pacote de release incluindo os dois YAMLs.

SNMP permanece opaco. A trap SNMPv2c BER é gerada somente no transmissor de teste;
nenhum parser/transformador SNMP foi adicionado ao produto. O original continua
independente, e UDP permanece best effort.

## Testes locais reais

Linux amd64, Go 1.27.2 e libpcap 1.10.1. Headers extraídos em pasta temporária,
sem instalar serviços ou modificar configurações de rede do host. Rede de teste
isolada em user/mount/network namespaces com veth e bridge.

```sh
export CGO_CFLAGS=-I/tmp/n-udptee-deps/root/usr/include
export CGO_LDFLAGS=-L/tmp/n-udptee-deps/root/usr/lib/x86_64-linux-gnu
make fmt-check vet test race check
make fuzz
N_UDPTEE_LAB_OUTPUT="$PWD/build/reports/v0.2.0-integration" make integration
```

Todos passaram. `check` validou exemplos padrão e opt-in como usuário sem root.
O lint dos dois workflows também passou (`actionlint`). Os 13 testes de publicação
e retenção continuaram passando.

| Verificação | Resultado |
|---|---|
| Decoder fuzz (10 s, 2 workers) | 1105829 execuções; passou |
| Remontagem fuzz (10 s, 2 workers) | 4951 execuções; passou |
| Integração final | 22,008 s; passou |
| fmt-check, vet, unitários, race | Passaram |

A integração preserva todos os cenários anteriores e acrescenta:

- Trap SNMPv2c de aproximadamente 5 KiB, payload binário e payload máximo 65507 bytes.
- Original e dois extras com cópia única e payload idêntico; origem `10.10.0.2:40000`
  observada nos dois extras em raw, origem do relay em UDP socket.
- Rotas de saída com MTUs 1200 e 1400; PCAPs nos dois receptores conferidos por
  verificador independente em Python para checksum IPv4 e UDP, MF, offsets, IDs,
  comprimentos, origem e payload reconstruído.
- Ordem reversa, duplicata exata, falta de fragmento, overlap conflitante, porta sem
  match, esgotamento de contextos/bytes, expiração ociosa, RSS e falha isolada de rota.
- Remontagem e fragmentação habilitadas separadamente, caminho pequeno com auto,
  opção padrão desabilitada e SIGTERM com contexto incompleto.

Unitários incluem isolamento VLAN/interface, opções IPv4/limite de comprimento,
limite de fragmentos, timestamp não renovado por duplicatas, posse dos buffers,
ID concorrente/esgotamento/expiração, checksums contra gopacket e erro parcial
interrompendo os fragmentos restantes sem retry. Contadores de tentativa parcial
não são confundidos com sucesso de datagrama.

Uma rodada intermediária falhou no cenário de overlap: o gerador de teste havia
produzido um fragmento desalinhado, corretamente rejeitado como `invalid`. O
transmissor foi corrigido para emitir overlap alinhado; a suíte final passou.

Evidências: [checks](validation/v0.2.0/checks.log),
[fuzz](validation/v0.2.0/fuzz.log), [integração](validation/v0.2.0/integration.log).
PCAPs, dumps e logs raw/relay em `docs/validation/v0.2.0/`.

## Benchmark medido nesta versão

O laboratório injetou 20000 datagramas de 256 bytes com dois targets raw, filas de
128 posições e snaplen 262144 nesta rodada. Remontagem/fragmentação estavam
desabilitadas. A janela de 1.191769 s inclui 1,1 s para drain/coleta
libpcap e o gerador Python; não representa throughput instantâneo garantido.

- Capturados: 19524; envios aceitos: 16433.
- Média na janela: 16382.37 capturas/s e 13788.74 envios/s.
- CPU do daemon: 0.13 s (10.91% de um núcleo); RSS: 93609984 bytes.
- Drops libpcap: 480; réplicas descartadas por fila cheia: 22615.
- Microbenchmarks: decoder 292,1 ns/op, 384 B/op, 2 allocs/op; fan-out 306,4 ns/op,
  0 allocs/op. O sender do microbenchmark descarta jobs e pode haver queue drops.

Os contadores libpcap são os da plataforma e não uma prova de conservação de
pacotes/entrega remota. O burst excedeu a capacidade das filas nesta execução;
resultados variam com agendamento, snaplen e ambiente. Não comparar diretamente
com a rodada v0.1.0 de snaplen diferente nem inferir capacidade de fragmentação.
Saídas: [bench](validation/v0.2.0/bench.log), [benchmark](validation/v0.2.0/benchmark.json).

## Operação e limites

Ative somente após adaptar interface, endereços e regras do exemplo:

```yaml
capture:
  bpf: "ip proto 17 and dst host 192.0.2.10"
  snaplen: 262144
reassembly:
  enabled: true
replication:
  fragmentation: auto
```

- BPF por porta pode ocultar fragmentos seguintes; o filtro do operador nunca é
  ampliado silenciosamente. Use protocolo/endereço e deixe a porta para as regras.
- `max_datagrams` inclui tombstones até o timeout; defaults 1024 contextos e 30 s
  equivalem a aproximadamente 34 novos IDs fragmentados/s sustentados. Ajuste esse
  orçamento ao tráfego; tráfego não fragmentado não usa o cache. Reutilização legítima
  da mesma chave/ID dentro da janela também é suprimida.
- O limite de bytes mede payload retido, não RSS total: estruturas, cópias, filas,
  buffers do kernel e GC precisam de memória adicional.
- A reserva global de IDs raw limita tentativas fragmentadas sustentadas a cerca
  de 1092/s somando targets. Esgotamento é visível como backpressure e não afeta
  datagramas que cabem na MTU. IDs de outros processos/emissores não são coordenados.
- Em relay, `auto` define `IP_PMTUDISC_DONT`; `drop` mantém a política padrão anterior
  do kernel, em vez de prometer mudar o comportamento de sockets existentes.
- Não há entrega garantida: perda de qualquer fragmento pode invalidar o datagrama.
  MTU pode mudar durante uma tentativa. Firewalls, NAT e antispoofing continuam
  limitações operacionais, sem ajustes automáticos no host.
- A validação local foi amd64; o workflow da tag testa e compila nativamente amd64
  e arm64 antes de publicar. O unit systemd não foi instalado no host.

## Publicação

A tag solicitada é **v0.2.0**. O workflow existente publica somente após testes
e pacotes de ambas as arquiteturas passarem, e mantém cinco releases estáveis.
A execução remota e os arquivos publicados podem ser consultados em
[Actions](https://github.com/nishisan-dev/n-udptee/actions/workflows/release.yaml)
e na [release v0.2.0](https://github.com/nishisan-dev/n-udptee/releases/tag/v0.2.0).
