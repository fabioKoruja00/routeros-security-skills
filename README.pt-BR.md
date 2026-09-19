# routeros-security-skills

Skills de auditoria de segurança **somente leitura** para MikroTik RouterOS (v6/v7), empacotadas
para agentes de IA (Claude Code, ChatGPT Skills e carregadores compatíveis). Uma pasta por domínio (21 skills). As skills de domínio compartilham duas dependências-base: `routeros-audit-method` e `routeros-factory-defaults`. A documentação das skills é em inglês.

[Read in English](README.md)

## O que tem aqui

| Skill | Domínio |
|---|---|
| [`routeros-audit-method`](routeros-audit-method/) | Como rodar a auditoria: regras invioláveis, o que ler antes de julgar, ordem de coleta, escala de severidade, formato de saída, armadilhas de campo, procedimento em incidente. **Ler primeiro.** |
| [`routeros-factory-defaults`](routeros-factory-defaults/) | Valores de fábrica de `/ip settings`, `/ipv6 settings`, connection tracking, device-mode, firewall padrão por chain, listas oficiais de bogon e os serviços que o fabricante manda desligar. |
| [`routeros-audit-access`](routeros-audit-access/) | Acesso administrativo: serviços e restrição de origem, SSH, usuários/grupos/chaves, RouterBOOT, device-mode, grupo default do AAA, botão físico, supout, gráficos, versão. |
| [`routeros-audit-services`](routeros-audit-services/) | Serviços auxiliares: mac-server, MNDP, bandwidth test, cache DNS, DoH, proxy, SOCKS, UPnP, cloud/DDNS, RoMON. |
| [`routeros-audit-firewall`](routeros-audit-firewall/) | Política das chains filter/NAT/mangle: input/forward, bogons, anti-spoof, flags TCP, zonas, contadores, fasttrack, NAT, ALG, listas por FQDN, log de drop. |
| [`routeros-audit-flood-defense`](routeros-audit-flood-defense/) | Tabela RAW, SYN flood, detecção de DDoS, amplificação, port scan, blacklist de força bruta, exaustão de conntrack, ICMP por tipo. |
| [`routeros-audit-layer2`](routeros-audit-layer2/) | MNDP, tabela de vizinhos, DHCP snooping, RA Guard, horizon, BPDU guard, STP, filtro de bridge e hardware offload, VLAN filtering, PVID, limite de MAC. |
| [`routeros-audit-dhcp`](routeros-audit-dhcp/) | Alertas do servidor DHCP, esgotamento de pool, lease estático, add-arp, lease script, confiança do cliente DHCP. |
| [`routeros-audit-ip-settings`](routeros-audit-ip-settings/) | Valores de `/ip settings` que só aparecem no print: rp-filter, redirects, source route, forwarding, limite de ARP, taxa de ICMP. |
| [`routeros-audit-vpn`](routeros-audit-vpn/) | PPTP, L2TP/IPsec, PPP, PPPoE, Quick Set e Back To Home, SSTP, OVPN, IPsec, WireGuard, VXLAN, ZeroTier, EoIP, port knocking. |
| [`routeros-audit-qos`](routeros-audit-qos/) | Filas com efeito de segurança: prioridade da gerência, garantias, PCQ, fila morta, filas dinâmicas, bufferbloat. |
| [`routeros-audit-ipv6`](routeros-audit-ipv6/) | Pilha IPv6, RA/ND, firewall IPv6, DHCPv6/PD, roteamento IPv6, transição, endereçamento, cabeçalhos de extensão. |
| [`routeros-audit-ospf`](routeros-audit-ospf/) | Vizinhança OSPF, tipos de rede, áreas, redistribuição, enxurrada de /32 do PPPoE, mapa de menus v6↔v7. |
| [`routeros-audit-bgp`](routeros-audit-bgp/) | Sessões BGP, filtros, atributos, vazamentos, reflexão, confederação, RPKI, armadilhas silenciosas v6↔v7. |
| [`routeros-audit-mpls`](routeros-audit-mpls/) | LDP, VPLS, isolamento de L3VPN, traffic engineering, plano de controle sob saturação. |
| [`routeros-audit-wireless`](routeros-audit-wireless/) | Interfaces wireless (legado e wifi-qcom): cifras, exposição da PSK, admissão de cliente, modos, regulatório, registration table. |
| [`routeros-audit-capsman`](routeros-audit-capsman/) | CAPsMAN: confiança CAP–controlador, descoberta, provisionamento, datapaths, versões, CA automático. |
| [`routeros-audit-scripts-storage`](routeros-audit-scripts-storage/) | Scripts, scheduler, fetch, arquivos e backups no disco, SMB, discos, containers. |
| [`routeros-audit-logging`](routeros-audit-logging/) | Log, NTP, e-mail, Netwatch, SNMP. |
| [`routeros-audit-aaa`](routeros-audit-aaa/) | RADIUS, CoA, grupo default do AAA, segredos PPP, User Manager. |
| [`routeros-audit-certificates`](routeros-audit-certificates/) | Armazém de certificados e seu uso pelos serviços. |

Cada checagem é uma linha de tabela com: **comando de leitura**, **o que caracteriza falha** e
**severidade sugerida** (CRITICAL / HIGH / MEDIUM / LOW). Todo arquivo termina com a nuance que
gera falso positivo — o que *parece* achado e não é.

## Princípios

- **Fluxo somente leitura.** `print`, `get`, `export`, `monitor`. Nunca `set`, `add`, `remove`, `enable`, `disable`, `reboot`. Use uma conta dedicada de auditoria com menor privilégio; não trate o grupo padrão `read` do RouterOS como estritamente somente leitura.
- **Ler a versão e o default de fábrica antes de julgar.** Menu de v6 e v7 diferem; comando no
  menu errado volta vazio, e vazio parece "não configurado". Valor igual ao de fábrica não é
  escolha insegura de alguém.
- **Ler o papel do equipamento.** Borda, concentrador, switch, AP e CORE multihomed não aceitam a
  mesma lista.
- **Segredo não entra na coleta normal assistida por IA.** Use `proplist` segura nas áreas que guardam credencial. Checagem de força de segredo exige revisão sensível separadamente autorizada; nunca inclua o valor no relatório. Nunca use `show-sensitive` na coleta normal.
- **Na dúvida entre duas severidades, a menor.** Severidade inflada vira ruído.
- **Ausência de regra não é falha automática.** Conferir `disabled`, ordem na chain, lista de
  interface e contador antes.
- **A própria auditoria pode derrubar o alvo.** `scan`/`snooper` de wireless sem
  `background=yes`, Torch e `profile` em CPU saturada. Ler estado, não provocar.

## Dependências-base

Instale `routeros-audit-method` e `routeros-factory-defaults` junto com qualquer skill de domínio. O método define coleta, severidade e saída; factory-defaults evita falsos positivos causados por comparar todo equipamento ao baseline de um roteador doméstico.

## Instalar

Copie as pastas que quiser para o diretório de skills do seu agente:

```bash
git clone https://github.com/fabioKoruja00/routeros-security-skills
cp -r routeros-security-skills/routeros-* ~/.claude/skills/
```

Ou por projeto: `<repo>/.claude/skills/`.

## O que as skills produzem

Um documento por equipamento **com achado**. Cada achado: o que está errado, o comando de
leitura que comprova, o que está em jogo, e as formas possíveis de resolver com o risco de cada
uma — inclusive o de perder acesso ao equipamento. Caminho, não receita pronta para colar.

## Escopo e aviso

Material independente, baseado na documentação pública do RouterOS e em experiência de campo.
Sem vínculo, endosso ou certificação da MikroTik. Comandos, menus e defaults mudam entre versões
do RouterOS — confirmar na versão instalada antes de agir sobre qualquer achado.

## Licença

MIT — ver [LICENSE](LICENSE).
