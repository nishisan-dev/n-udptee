# n-udptee — Especificação técnica de implementação

**Status:** proposta para implementação pelo Codex  
**Versão da especificação:** 1.0  
**Plataforma inicial:** Linux  
**Linguagem:** Go  
**Escopo de protocolo:** UDP sobre IPv4, exclusivamente no MVP

## 1. Objetivo

Implementar o **n-udptee**, uma ferramenta leve de captura passiva e replicação **1:N de datagramas UDP**, sem balanceamento de carga e sem alterar o datagrama original.

A ferramenta deve observar pacotes UDP que chegam a uma interface Linux, selecionar os pacotes de interesse e gerar **uma cópia independente por destino configurado**, permitindo preservar o IP e a porta UDP de origem quando utilizado o modo transparente.

O uso inicial é duplicar traps SNMP/UDP 162 para dois ou mais receptores de Fault Management, mas **o produto não deve entender SNMP**. Deve funcionar com qualquer payload UDP, incluindo Syslog e NetFlow, dentro das limitações documentadas.

### Invariantes obrigatórios

1. **Não interceptar, consumir, bloquear, substituir ou modificar o pacote original.** O receptor original continua recebendo normalmente pela pilha de rede do Linux.
2. **Não dividir tráfego.** Para cada datagrama que corresponda a uma regra, tentar transmitir exatamente uma réplica para **cada** destino daquela regra.
3. **Payload idêntico byte a byte** ao payload UDP capturado; nada de decode/encode de SNMP, alteração de conteúdo ou truncamento.
4. No modo transparente, preservar **endereço IPv4 de origem e porta UDP de origem** no pacote replicado; reescrever endereço e, se configurada, porta de destino.
5. **Não prometer entrega garantida.** O modelo é *best-effort/at-most-one send attempt por destino*, com métricas para capturas, enfileiramento, envios, erros e descartes. UDP não oferece confirmação de entrega.
6. Nunca gerar loops de replicação pelo próprio tráfego transmitido localmente.

## 2. Escopo do MVP (v0.1.0)

### Obrigatório

- Linux amd64 e arm64.
- Captura passiva via **libpcap** usando `github.com/gopacket/gopacket/pcap`.
- Filtro BPF configurável aplicado no kernel/libpcap.
- Seleção explícita de interface física ou VLAN; **não aceitar `any` no MVP**.
- Captura de entrada (`PCAP_D_IN`), sem modo promíscuo por padrão. Falhar com erro claro se a direção ingress não puder ser garantida.
- Decodificação segura de Ethernet e VLAN 802.1Q quando suportadas pelo link type; IPv4 e UDP.
- Suporte a múltiplas regras com match por CIDR de origem, CIDR de destino e porta UDP de destino.
- Seleção determinística: **primeira regra correspondente vence**; nenhuma duplicação acidental entre regras.
- Múltiplos destinos por regra, com eliminação de destinos idênticos `(IP, porta)` dentro da regra na validação (rejeitar duplicados com mensagem clara).
- Dois modos de envio: `raw_ipv4` (transparente) e `udp_socket` (relay).
- Filas limitadas **independentes por destino**, para que um destino lento não bloqueie os demais.
- Logs estruturados, métricas Prometheus, `/healthz`, desligamento gracioso e validação estrita de configuração YAML.
- Testes unitários e de integração, CLI, README, exemplo de configuração, Makefile e unit systemd.

### Explicitamente fora do MVP

- TCP, SCTP, ICMP ou protocolos não UDP.
- IPv6; planejar interfaces para extensão futura, sem implementar parcialmente.
- Reassemblagem de fragmentos IPv4: **descartar datagramas fragmentados**, documentando que um filtro BPF `udp` pode não observar fragmentos subsequentes.
- SNMP parsing, BER/ASN.1, enriquecimento, correlação ou transformação de payload.
- Reescrita de IP/porta **de origem**; a preservação é fixa no modo transparente.
- Retransmissão com confirmação, spool em disco, semântica exactly-once ou checkpoint de entrega.
- Hot reload, cluster, eleição de líder, API de administração e regras dinâmicas.
- AF_XDP, XDP/eBPF, DPDK, PF_RING, TPACKET_V3; reservar abstrações, sem construir backends prematuramente.
- Bridging L2 ou replicação de VLAN tagging/MAC de origem; o objetivo é um **novo pacote IP**, não um clone Ethernet bit a bit.

## 3. Modos de operação

### 3.1 `raw_ipv4` — modo padrão

Para cada datagrama UDP aprovado:

1. Extrair IP de origem, porta UDP de origem e payload original.
2. Para cada destino, gerar um novo pacote IPv4/UDP contendo o mesmo payload.
3. Preencher o **IP de origem** com o IP original capturado.
4. Preencher a **porta UDP de origem** com a porta original capturada.
5. Definir o novo IP de destino e a porta do destino configurado.
6. Definir TTL configurável (padrão `64`) e recalcular corretamente o checksum UDP (incluindo pseudo-header IPv4) e cabeçalho IPv4.
7. Enviar por socket IPv4 raw com `IP_HDRINCL` e `CAP_NET_RAW`, usando o roteamento do Linux.

A integridade prometida é do **payload UDP** e dos campos de origem especificados, **não de todos os bytes do cabeçalho IP original**. ID, TTL, flags, opções IP e checksum de IP podem diferir. Documentar que o sistema operacional pode preencher alguns campos do IP header no envio com `IP_HDRINCL`.

**Cuidados mandatórios:**

- Envio raw pode falhar em `EMSGSIZE` quando exceder a MTU da rota. **Não truncar, não fragmentar manualmente e não tentar reenviar infinitamente**: contar descarte e registrar erro com limitação de taxa.
- Roteadores, firewalls, antispoofing e políticas `rp_filter` podem bloquear pacotes com IP de origem que não pertence ao emissor. Tratar como limitação operacional, não como defeito ocultado.
- A configuração local de NAT/SNAT e a topologia podem alterar a transparência efetivamente observada no destino. Confirmar origem real via `tcpdump` nos testes.
- Não sobrescrever DSCP/ECN do pacote original se optar por copiá-los; no MVP é aceitável padronizar o TOS em `0`, desde que documentado.
- O IPv4 e UDP devem ser serializados corretamente sem depender de checksum offload; pacote emitido deve passar em verificadores padrão.

### 3.2 `udp_socket` — modo relay

Receber payload por captura libpcap e enviá-lo por sockets UDP normais (`net.UDPConn`) para cada destino, utilizando IP/porta de origem escolhidos pelo sistema operacional.

- Preservar apenas o **payload**, não prometer origem IP/porta originais.
- Usar o mesmo motor de regras, filas, métricas e CLI.
- Oferecer como alternativa quando `CAP_NET_RAW` não for aceitável ou quando a rede bloquear spoofing.

### 3.3 Semântica de entrega e do original

- `n-udptee` é **passivo na entrada**. Não utiliza DNAT, não remove pacotes da pilha original, não executa `iptables`/`nftables` e não precisa ocupar UDP/162.
- Os destinos configurados recebem **réplicas adicionais**; o destino original continuará recebendo a transmissão original se já for alcançável pela pilha.
- Não incluir o destino original na lista de réplicas se isso causar duplicação indesejada no mesmo receptor.
- Falha em um destino não impede que os outros recebam sua tentativa de envio.
- Não há verificação de que o datagrama chegou ao aplicativo remoto.

## 4. Exemplo completo de configuração

Criar `configs/example.yaml`:

```yaml
version: 1

capture:
  interface: "eth0"
  bpf: "ip and udp and dst port 162"
  direction: "in"
  promiscuous: false
  snaplen: 65535
  buffer_size_bytes: 33554432

replication:
  mode: "raw_ipv4"
  ttl: 64
  queue_size_per_target: 4096
  on_queue_full: "drop_newest"

rules:
  - name: "snmp-traps"
    match:
      source_cidrs:
        - "0.0.0.0/0"
      destination_cidrs:
        - "192.0.2.10/32"
      destination_ports:
        - 162
    targets:
      - name: "fm-primary"
        ip: "198.51.100.20"
        port: 162
      - name: "fm-secondary"
        ip: "198.51.100.21"
        port: 162

metrics:
  enabled: true
  listen: "127.0.0.1:9109"

logging:
  level: "info"
  format: "json"
```

Os IPs `192.0.2.0/24` e `198.51.100.0/24` são **endereços reservados para documentação**; o exemplo deverá ser adaptado à rede real.

### Validação da configuração

- Rejeitar YAML desconhecido, campos faltantes, BPF inválido, portas fora de `1..65535`, IPv6, endereços multicast/broadcast/unspecified como destino, regras sem targets e IDs/nomes duplicados.
- `capture.direction` suporta apenas `in` no MVP; exigir confirmação efetiva de `pcap.SetDirection(pcap.DirectionIn)` no runtime.
- `capture.interface` deve existir e ter um link type suportado.
- Validar coerência de filtros: a configuração recomendada deve restringir BPF por protocolo e porta; explicar que regras de match **não substituem** a necessidade de BPF eficiente.
- Rejeitar `target` idêntico ao IP de destino original quando isso inevitavelmente entregar duas cópias ao mesmo receptor, ou ao menos emitir aviso explícito e exigir opção de override — escolher rejeição no MVP.
- Todas as filas têm tamanho estritamente positivo e limitado por parâmetro razoável.
- A configuração `on_queue_full` aceita apenas `drop_newest` no MVP.

## 5. CLI

Implementar executável `n-udptee` com comandos:

```bash
n-udptee check --config configs/example.yaml
n-udptee run --config configs/example.yaml
n-udptee version
n-udptee --help
```

Requisitos:

- `check`: validar arquivo YAML, CIDRs, portas e sintaxe BPF por compilação offline com um link type suportado (por exemplo, Ethernet), **sem exigir privilégios nem abrir interface de captura**; retornar exit code `0` ou não zero. Confirmar o filtro com o link type efetivo novamente no `run`.
- `run`: validar configuração, abrir recursos, iniciar captura/replicação/servidor de métricas e processar até receber `SIGINT`/`SIGTERM`.
- `version`: imprimir versão, commit e informações de build quando fornecidas por `-ldflags`.
- Flags `--config` e `-c` equivalentes; erros em `stderr` com exit code não zero.
- Encerrar com aviso claro quando faltar permissão para abrir pcap/raw socket.

## 6. Arquitetura

```text
                Interface de entrada (UDP/IPv4)
                              |
                    libpcap + filtro BPF
                              |
                       Packet Decoder
                              |
                    Validator + Rule Matcher
                              |
                         UDP Datagram
                              |
                        Fan-out Engine
                         /    |    \
                        /     |     \
                 Queue A   Queue B   Queue N
                    |         |         |
                 Sender A  Sender B  Sender N
                    \         |         /
                      Raw IPv4 / UDP socket
                              |
                      Roteamento Linux
                              |
                       Receptores remotos

     [Captura original segue para a pilha local normalmente]
```

Interfaces Go propostas (ajustar nomes conforme o design idiomático):

- `CaptureSource`: abre captura, entrega frames e estatísticas, encerra recursos.
- `PacketDecoder`: valida Ethernet/VLAN/IPv4/UDP e converte para `Datagram` imutável.
- `RuleMatcher`: recebe `Datagram` e seleciona a **primeira** regra aplicável.
- `Replicator`: monta jobs por destino e os envia às filas correspondentes sem bloquear a captura.
- `Sender`: envia uma réplica para um endpoint, com implementações `RawIPv4Sender` e `UDPSocketSender`.
- `Metrics` e `ConfigLoader`: camadas independentes do core.

`Datagram` deverá carregar, no mínimo: `SourceIPv4`, `DestinationIPv4`, `SourcePort`, `DestinationPort`, `Payload`, `IngressInterface` e `CaptureTimestamp`. O payload não deve ser alterado depois de enfileirado; se o backend de captura reutilizar buffers, copiar os bytes necessários antes do fan-out.

### Fluxo de execução

1. Abrir pcap na interface informada, sem promisc por padrão.
2. Aplicar BPF e `DirectionIn`; se falhar, **não** continuar em modo `inout` silenciosamente.
3. Ler os frames em loop sem chamar envio de rede diretamente na goroutine de captura.
4. Decodificar, validar tamanhos e ignorar outros protocolos, pacotes truncados/corrompidos e datagramas fragmentados.
5. Selecionar regra por ordem do YAML e criar um job por destino.
6. Enfileirar de forma não bloqueante; se uma fila estiver cheia, descartar **somente aquela réplica** e incrementar métrica.
7. Worker por destino envia os jobs com o `Sender` do modo escolhido e registra sucesso de *send syscall* ou erro.
8. Atualizar métricas, lidar com erros transitórios sem derrubar outros destinos, e liberar memória rapidamente.
9. Em `SIGINT`/`SIGTERM`, parar captura e aceite de jobs, drenar filas até timeout configurado internamente (padrão 5 s), fechar sockets e servidor HTTP.

### Concorrência

- Um leitor por interface configurada (uma interface no MVP).
- Um worker por destino, com fila própria. Sem goroutine por pacote.
- Dados do pacote **imutáveis** e compartilháveis de maneira segura entre réplicas.
- Captura jamais aguarda ACK, conectividade ou velocidade de um receptor UDP.
- Contadores atômicos ou mecanismos de métricas eficientes; evitar alocações e logs no hot path.
- Sem retries automáticos no MVP; falha de envio é contada e encerrada para aquela réplica.

## 7. Parsing, checksum, filtragem e rede

- Verificar comprimento capturado versus comprimento esperado de IPv4 e UDP; nunca tentar acessar fatias fora do buffer.
- Confirmar `IPv4.Protocol == UDP`, `IHL`, `TotalLength`, `UDP.Length` e consistência de offsets.
- Validar datagramas incompletos e descartar pacotes com erro de decode.
- Ignorar fragmentação IPv4: `MF=1` ou `fragment offset != 0`; deixar métrica específica para fragmentos **observados**.
- Não assumir que `bpf = udp ...` capture os fragmentos não iniciais. Registrar a limitação no README.
- Recalcular o checksum UDP para cada destino, porque o pseudo-header inclui o IP de destino; suportar payload UDP vazio.
- Se o cálculo de checksum UDP resultar em zero no IPv4, serializar `0xffff` quando aplicável para representar um checksum calculado zero; não tratar equivocadamente como ausência de checksum.
- Não expor `IP_HDRINCL` ao mundo externo por abstrações mal definidas; isolar syscall em `internal/send/rawipv4`.
- Usar roteamento normal do kernel; não implementar ARP, Ethernet crafting ou seleção manual de MAC no MVP.
- Rejeitar envio de pacote maior que a MTU efetiva reportado por `EMSGSIZE`; não prometer fragmentação pelo kernel com `IP_HDRINCL`.
- Não garantir que pacotes com origem preservada atravessem filtros de antispoofing/`rp_filter`, NAT, VRFs ou redes externas; explicar requisitos de implantação.
- A configuração de BPF é confiável no plano de controle, mas o **conteúdo capturado é não confiável** e deve ser tratado como entrada potencialmente malformada.

## 8. Observabilidade e operações

### HTTP

- `GET /metrics` no endereço configurado, no formato Prometheus.
- `GET /healthz`: HTTP 200 apenas enquanto captura e serviço principal estiverem saudáveis; uma falha isolada de envio para destino remoto não derruba healthz.
- Bind padrão em `127.0.0.1`; não abrir porta HTTP na rede externa por padrão.

### Métricas obrigatórias

```text
n_udptee_capture_packets_total{interface}
n_udptee_capture_bytes_total{interface}
n_udptee_packets_matched_total{rule}
n_udptee_packets_dropped_total{reason}
n_udptee_replicas_enqueued_total{rule,target}
n_udptee_replicas_send_success_total{rule,target}
n_udptee_replicas_send_errors_total{rule,target,reason}
n_udptee_replicas_queue_dropped_total{rule,target}
n_udptee_target_queue_depth{target}
n_udptee_pcap_kernel_drops_total{interface}
```

- *Send success* significa aceitação pela syscall de envio, não entrega confirmada.
- Métrica de perdas libpcap deve refletir contadores fornecidos pela plataforma; se indisponíveis, documentar e não inventar valores.
- Os labels `rule`, `target` e `reason` são derivados de configuração e enums, não de IPs arbitrários capturados. Evitar cardinalidade alta.

### Logs

- `JSON` ou `text`, nível `debug|info|warn|error`.
- Logar inicialização, configuração efetiva sem segredos, interface/BPF, erros de abertura, mudanças de estado e resumo de desligamento.
- **Não logar payload UDP por padrão**, nem uma linha para cada pacote.
- Limitar taxa de logs repetitivos de erro de envio/MTU, sem perder contadores.

## 9. Segurança

- Documentar necessidade de `CAP_NET_RAW` e permissões da captura, que podem exigir capabilities adicionais dependendo do ambiente.
- Não exigir root como política permanente se capabilities suficientes funcionarem; não tentar ajustar sysctl, nftables ou iptables automaticamente.
- Documentar que spoofing do IP de origem deve ocorrer **somente em redes sob administração/autorização do operador** e pode ser bloqueado por políticas de rede.
- Exigir lista estática de destinos por configuração para evitar transformar o serviço em amplificador aberto; não aceitar destinos fornecidos por pacotes recebidos.
- Limitar filas e memória para sobreviver a storms de traps sem crescimento não controlado.
- Manter dependências atualizadas, inclusive decodificador de pacotes; usar versão segura e suportada de `github.com/gopacket/gopacket`.
- Encerrar com erro claro caso o bind de `/metrics` ou a abertura da interface falhe na inicialização, evitando falsa saúde operacional.

## 10. Estrutura esperada do repositório

```text
n-udptee/
├── cmd/
│   └── n-udptee/
│       └── main.go
├── internal/
│   ├── capture/
│   ├── config/
│   ├── decode/
│   ├── engine/
│   ├── match/
│   ├── metrics/
│   ├── model/
│   └── send/
│       ├── rawipv4/
│       └── udpsocket/
├── configs/
│   └── example.yaml
├── deploy/
│   └── systemd/
│       └── n-udptee.service
├── tests/
│   ├── integration/
│   └── fixtures/
├── .github/
│   └── workflows/
│       └── ci.yaml
├── .gitignore
├── AGENTS.md
├── LICENSE                       # quando já existente ou explicitamente escolhida
├── Makefile
├── README.md
├── go.mod
└── go.sum
```

- A árvore é uma diretriz. Refatorações pequenas são permitidas se melhorarem a clareza.
- Usar o caminho de módulo Go conforme o repositório GitHub **efetivamente criado**; não assumir organização ou usuário sem inspecionar `git remote`.
- `AGENTS.md` deve instruir agentes a executar testes, não degradar semântica de replicação e manter a spec como fonte dos critérios de aceite.
- Licença a ser escolhida de forma explícita no repositório; se ausente, **não presumir** autorização para criar uma licença em nome do autor. O Codex pode deixar a seleção indicada no planejamento.

## 11. Testes e critérios de aceite

### Testes unitários obrigatórios

1. Validar YAML (campos obrigatórios, desconhecidos e valores inválidos).
2. Match de IP por CIDR, porta, ordem e primeira regra vencedora.
3. Conservar payload byte a byte em todos os destinos, inclusive payload vazio e binário arbitrário.
4. Em `raw_ipv4`, preservar IP de origem e porta UDP de origem, reescrever destino e validar checksums IPv4/UDP contra implementação independente.
5. Em `udp_socket`, enviar mesmo payload sem afirmar preservação da origem.
6. Descartar IPv4 fragmentado, não UDP, IPv6 e pacotes truncados/malformados sem panic.
7. Fila A cheia não bloquear fila B; métricas de descarte por destino corretas.
8. `SIGTERM` interromper leitura e encerrar workers sem goroutine leaks; timeout de shutdown deve ser respeitado.
9. `n-udptee check` ser funcional sem root.
10. Fuzz tests do decoder para frames inválidos, comprimentos conflitantes e checksums.

### Testes de integração Linux (namespaces + veth)

Montar topologia com namespace de origem, namespace do replicador e dois namespaces receptores. Injetar datagramas UDP na interface de captura, aplicar rotas e observar resultado com sockets UDP e tcpdump.

**Aceite funcional obrigatório:**

- Um datagrama enviado ao IP original gera **uma réplica no receptor A e uma no receptor B**; comparar byte a byte o payload.
- O receptor original, se houver listener, continua recebendo o mesmo datagrama uma vez.
- No modo `raw_ipv4`, os dois receptores veem o **mesmo IPv4 de origem e a mesma porta UDP de origem do emissor original**. A porta de destino pode ser diferente se configurada.
- No modo `udp_socket`, ambos recebem o payload e podem observar IP de origem do replicador.
- O replicador não processa o seu próprio tráfego de saída como nova entrada, comprovado por contagem de replicas estável.
- Tráfego TCP e UDP que não corresponda à regra não produz cópias.
- Derrubar ou bloquear receptor A não impede tentativas de envio ao receptor B; observar que uma syscall UDP bem-sucedida **não garante** que A recebeu algo.
- Destino não roteável ou erro de envio incrementa métrica; daemon continua vivo quando erro é isolado.
- Tráfego acima da MTU gera rejeição/contagem apropriada e nunca payload truncado.
- Envio em lote e bursts sustentados não causam crescimento de memória ilimitado.
- Confirmar tratamento de `rp_filter`/roteamento dos namespaces no teste (configuração de laboratório apenas), sem alterar sysctls do host de produção.

Testes que exigem privilégios devem poder ser pulados explicitamente em ambientes sem `CAP_NET_ADMIN`/`CAP_NET_RAW`; **não mascarar falhas quando os testes forem executados com as permissões adequadas**.

### Qualidade

- `go test ./...` verde; `go vet ./...` verde.
- `go test -race ./...` verde para os pacotes testáveis no ambiente.
- `go fmt`/`gofmt` sem diferenças.
- CI executar testes unitários, validação e build Linux amd64 e arm64, respeitando dependência de CGO/libpcap. Cross-compilation CGO não deve ser suposta trivial: usar runner/toolchain apropriados.
- Incluir benchmark documentado de captura e fan-out com datagramas de 256 bytes e dois destinos, medindo pps, CPU, RSS e drops; **reportar resultados medidos, não inventar throughput garantido**.

## 12. README e documentação de operação

O README deve conter:

- O que é e o que **não** é o `n-udptee`.
- Diagrama de captura passiva + fan-out 1:N.
- Comparação transparente (`raw_ipv4`) versus relay (`udp_socket`).
- Instalação em Ubuntu/Debian com dependência `libpcap-dev`, compilação CGO e execução Linux.
- Exemplos completos de configuração e comandos `check`, `run`, `version`.
- Permissões/capabilities, como verificar entrada/saída com `tcpdump` e como interpretar as métricas.
- Atenção a MTU, IPv4 fragmentado, antispoofing/`rp_filter`, NAT, rotas, tráfego assimétrico e possível duplicação no listener original.
- Definição clara de **best effort**, sem garantia de entrega UDP.
- Troubleshooting (BPF errado, ingress direction não disponível, interface errada, MTU, permissões, firewall e IP spoof bloqueado).
- Arquivos de exemplo para systemd e uma seção de limitações da v0.1.0.

## 13. Plano de implementação para o Codex

Executar em etapas entregando código compilável e testes progressivos:

1. **Bootstrap:** módulo Go com path do repo real, CLI, configuração YAML estrita, validação, documentação inicial e testes de config.
2. **Captura/decoder:** pcap ingress+BPF, decoder UDP/IPv4 seguro, modelo imutável, fixtures e fuzz tests.
3. **Core de fan-out:** matcher, filas isoladas por destino, lifecycle, testes concorrentes e de backpressure.
4. **Senders:** `udp_socket` e `raw_ipv4`, serialização e checksums, testes unitários.
5. **Observabilidade:** Prometheus, healthz, logs e shutdown gracioso.
6. **Integração:** namespaces/veth, payload idêntico, preservação da origem, testes de erros, sem loops.
7. **Empacotamento:** Makefile, systemd, GitHub Actions, README completo, benchmark e relatório final.

### Instruções mandatórias ao Codex

- Implementar a aplicação inteira, não apenas um protótipo ou pseudocódigo.
- Não criar funções vazias, TODOs bloqueantes, classes/arquivos falsos ou exemplos incompletos.
- Antes de cada etapa, inspecionar o código presente e manter o build funcional.
- Priorizar comportamento correto e testes determinísticos antes de otimizações.
- Não introduzir parsing de SNMP, TCP ou IPv6 no MVP.
- Não modificar firewall, roteamento, sysctls, serviços ou interfaces do host automaticamente.
- Se uma função requer privilégios e o ambiente de CI não os possui, implementar o teste e documentar precisamente como executá-lo em Linux com privilégios.
- Ao finalizar, informar arquivos criados, comandos de teste executados, resultados reais, limitações remanescentes e quaisquer diferenças explícitas em relação a esta especificação.

## 14. Definição de pronto da v0.1.0

A entrega só é considerada completa quando:

- `n-udptee check` valida corretamente a configuração.
- `n-udptee run` captura datagramas UDP IPv4 sem ocupar a porta UDP monitorada.
- Um pacote compatível com a regra é replicado aos dois destinos configurados **sem alternância nem divisão de tráfego**.
- O payload original é idêntico nas réplicas.
- O modo `raw_ipv4` preserva efetivamente IP de origem e porta de origem observados nos receptores do teste de integração.
- O pacote original continua seu processamento normal no Linux.
- Dois destinos com níveis diferentes de falha/carga não bloqueiam um ao outro.
- Checksums são válidos, loops locais não ocorrem, limites de memória são respeitados e erros de MTU são visíveis.
- Métricas, logs e README permitem operar e diagnosticar a aplicação.
- Os testes automatizados aplicáveis passam e qualquer teste não executado por falta de permissão é declarado.

## 15. Referências técnicas

- Linux raw sockets, `IP_HDRINCL`, capabilities e MTU: https://man7.org/linux/man-pages/man7/raw.7.html
- `pcap_setdirection` e captura somente de entrada: https://linuxman7.org/linux/man-pages/man3/pcap_setdirection.3pcap.html
- gopacket mantido pela comunidade (usar release atual com correções de segurança): https://github.com/gopacket/gopacket
- API de captura `gopacket/pcap`: https://pkg.go.dev/github.com/gopacket/gopacket/pcap
- Serialização de camadas e validação UDP/IPv4: https://pkg.go.dev/github.com/gopacket/gopacket/layers
