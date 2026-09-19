# routeros-security-skills

Skills de auditoria de segurança **somente leitura** para MikroTik RouterOS (v6/v7), empacotadas
para agentes de IA (Claude Code e carregadores de skill compatíveis). Uma pasta por tema; cada
skill é autocontida e instalável sozinha. A documentação das skills é em inglês.

[Read in English](README.md)

## O que tem aqui

| Skill | Cobre |
|---|---|
| [`routeros-factory-defaults`](routeros-factory-defaults/) | Valor de fábrica de `/ip settings`, `/ipv6 settings`, connection tracking, device-mode, firewall padrão (defconf) por chain, listas de bogon do guia oficial de firewall avançado e os serviços que o fabricante manda desligar. Ler antes de abrir qualquer achado. |
| [`routeros-audit-core`](routeros-audit-core/) | Acesso administrativo e serviços expostos, serviços auxiliares, política das chains do firewall, RAW e defesa de flood, ICMP por tipo, camada 2 / MNDP / bridge / VLAN, DHCP, pilha IP, túneis e cifras, QoS com efeito de segurança, sequência de coleta em bloco. |
| [`routeros-audit-ipv6`](routeros-audit-ipv6/) | Estado da pilha, RA/ND, firewall IPv6, DHCPv6 e delegação de prefixo, roteamento IPv6, mecanismos de transição, plano de endereçamento, cabeçalhos de extensão. |
| [`routeros-audit-routing`](routeros-audit-routing/) | OSPF, BGP (sessão, filtros, atributos, vazamento, reflexão), RPKI, MPLS/LDP, isolamento de VPLS e L3VPN, traffic engineering, plano de controle sob saturação, mapa de menus v6↔v7 e armadilhas silenciosas de sintaxe. |
| [`routeros-audit-wireless`](routeros-audit-wireless/) | Driver legado × `wifi-qcom`, autenticação e cifras, quem lê a PSK, admissão de cliente, modos de operação, CAPsMAN (confiança, segmentação, versões), regulatório e RF, evidência pela registration table. |
| [`routeros-audit-automation`](routeros-audit-automation/) | Script, scheduler e fetch, arquivos e backups no disco, container, log e NTP, SNMP, AAA/RADIUS, certificados, procedimento seguro durante incidente. |

Cada checagem é uma linha de tabela com: **comando de leitura**, **o que caracteriza falha** e
**severidade sugerida** (CRITICAL / HIGH / MEDIUM / LOW). Todo arquivo termina com a nuance que
gera falso positivo — o que *parece* achado e não é.

## Princípios

- **Somente leitura.** `print`, `get`, `export`, `monitor`. Nunca `set`, `add`, `remove`,
  `enable`, `disable`, `reboot`. Auditoria que mexe no equipamento é incidente.
- **Ler a versão e o default de fábrica antes de julgar.** Menu de v6 e v7 diferem; comando no
  menu errado volta vazio, e vazio parece "não configurado". Valor igual ao de fábrica não é
  escolha insegura de alguém.
- **Ler o papel do equipamento.** Borda, concentrador, switch, AP e CORE multihomed não aceitam a
  mesma lista.
- **Segredo não entra no relatório.** `proplist` nas áreas que guardam credencial. O achado é
  "senha fraca em X", não o valor.
- **Na dúvida entre duas severidades, a menor.** Severidade inflada vira ruído.
- **Ausência de regra não é falha automática.** Conferir `disabled`, ordem na chain, lista de
  interface e contador antes.
- **A própria auditoria pode derrubar o alvo.** `scan`/`snooper` de wireless sem
  `background=yes`, Torch e `profile` em CPU saturada. Ler estado, não provocar.

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
