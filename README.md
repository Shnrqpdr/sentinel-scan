# sentinel-scan

> Diagnóstico rápido de segurança para quem roda projetos com Docker numa VPS.
> Diz **o que está exposto**, **o que já foi comprometido** e **por quê**, com o comando para corrigir.

*Nome provisório. Candidatos: `sentinel-scan`, `vps-watcher`, `sentinel`. "Sentinel" sozinho colide com Microsoft Sentinel, HashiCorp Sentinel e SentinelOne.*

## Por que existe

Este projeto nasceu de um [incidente real](docs/case-study-2026-11-metabase-xmrig.md): durante meses, uma VPS pessoal recebeu alertas de malware do provedor. O antivírus matava o minerador, ele voltava, e ninguém sabia o porquê.

| Ferramenta | Por que não achou a causa |
|---|---|
| Antivírus do provedor | Mata o binário, mas não aponta a origem |
| rkhunter / chkrootkit / Lynis | Olham o **host**, e o malware estava **dentro de um container** |
| Trivy / docker-bench | Olham imagens e configuração, não um container já invadido |
| `ufw status` | O Docker publica portas **por cima** do ufw |

A causa era um **Metabase exposto na internet, conectado ao Postgres como superusuário**. O atacante executava comandos pelo banco (`COPY ... FROM PROGRAM`) e deixou backdoors no **volume de dados**, que sobrevivem à recriação do container. O sentinel-scan transforma essa investigação em verificações automáticas.

## Uso (protótipo)

```bash
# na própria VPS
sudo bash playbook/quick-diagnosis.sh

# de fora, sem instalar nada no servidor
ssh usuario@servidor 'sudo bash -s' < playbook/quick-diagnosis.sh
```

- **Somente leitura.** Não altera, apaga, executa nem envia nada para lugar nenhum.
- Sem root, roda as verificações de Docker (grupo `docker`) e pula as do host.
- Códigos de saída: `0` ok · `1` achados altos · `2` achados críticos (dá para usar em cron ou CI).

Exemplo, num ambiente com a infecção do caso reproduzida (`tests/fake-infected.sh`):

```
[HIGH    ] EXP-001  sentinel-test-pg (postgres:16-alpine) publicado na internet: portas 55432
[CRITICAL] CTR-002  sentinel-test-pg: binário/arquivo de minerador na camada do container
[HIGH    ] CTR-001  sentinel-test-pg: 7 arquivo(s) oculto(s) em diretório temporário
[CRITICAL] DB-001   sentinel-test-pg: superuser inesperado no Postgres
[CRITICAL] DB-002   sentinel-test-pg: pg_hba.conf fora do padrão da imagem oficial
[HIGH    ] DB-003   sentinel-test-pg: arquivos ocultos no PGDATA (persistência que sobrevive a recriar o container)
[CRITICAL] HOST-005 Processo se passando por thread do kernel
```

## O que verifica

Especificação completa em [`docs/checks-spec.md`](docs/checks-spec.md).

| Área | Exemplos |
|---|---|
| **Exposição** | portas de container em `0.0.0.0` (o Docker ignora o ufw), bancos e painéis de admin públicos |
| **Containers** | arquivos ocultos ou executáveis em `/tmp` via `docker diff`, binários de minerador, containers privilegiados |
| **Bancos** | superusers inesperados, `pg_hba.conf` alterado, arquivos ocultos no PGDATA, apps conectados como superuser |
| **Apps** | imagens `:latest` antigas; admins e chaves de API do Metabase e n8n (planejado) |
| **Host** | config **efetiva** do SSH (`sshd -T`), UID 0 extra, `ld.so.preload`, processo fingindo ser `kworker`, conexões com pools de mineração |

## Estrutura

```
playbook/quick-diagnosis.sh   protótipo funcional (bash, só leitura)
docs/checks-spec.md           especificação de cada verificação (ID, gravidade, detecção, correção)
docs/case-study-*.md          incidentes reais anonimizados que originaram as verificações
docs/remediation-playbook.md  o que fazer quando algo é encontrado
docs/decisions/               decisões de arquitetura (ADR)
iocs/*.yml                    indicadores de ataque como dados
tests/fake-infected.sh        reproduz uma infecção falsa (sem binários reais) para testar
private/                      relatórios com dados reais (fora do git)
```

## Princípios

1. **Somente leitura por padrão.** Correções, se um dia existirem, só com `--fix` explícito e confirmação a cada passo.
2. **Nada sai da máquina.** Sem telemetria e sem "phone home". O único tráfego de rede futuro (sondar painéis) será opt-in.
3. **Explicar, não só apontar.** Cada achado diz por que é perigoso e como corrigir.
4. **Pouco ruído.** Cada verificação documenta seus falsos positivos.
5. **Nascido de incidentes reais.** Cada verificação nova vem de um caso documentado.

## Roadmap

- [x] Protótipo bash com as verificações do primeiro incidente
- [x] Ambiente de teste com infecção falsa
- [ ] Decidir a linguagem da v0.1 ([ADR 0001](docs/decisions/0001-linguagem.md): Go recomendado)
- [ ] Saída JSON e Markdown
- [ ] Regras e IOCs carregados de YAML (`iocs/`)
- [ ] Verificações de apps: admins do Metabase, n8n, Grafana e Portainer
- [ ] CTR-004 (privilegiado / docker.sock), DB-005 (Mongo/Redis sem auth), HOST-007 (`dpkg --verify`)
- [ ] Modo remoto: `sentinel-scan ssh user@host`
- [ ] Releases com binários assinados

## Licença

A definir (sugestão: Apache-2.0).
