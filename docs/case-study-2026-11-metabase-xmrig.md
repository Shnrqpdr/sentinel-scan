# Estudo de caso: minerador escondido no container do Postgres, entrando pelo Metabase

> Incidente real numa VPS pessoal (Ubuntu 24.04, Docker, vários projetos), novembro de 2026.
> IPs, hostnames e contas da vítima foram anonimizados. Os indicadores do **atacante** estão em [`../iocs/2026-11-metabase-xmrig.yml`](../iocs/2026-11-metabase-xmrig.yml).

## Resumo

Durante meses o provedor mandou e-mails dizendo que havia malware na VPS. O antivírus do provedor (Monarx) matava o processo, mas ele sempre voltava, e ninguém sabia o porquê. O host estava limpo. O minerador vivia **dentro de um container de Postgres**, e quem abriu a porta foi um **Metabase exposto na internet e conectado ao banco com um usuário superusuário**.

## A cadeia do ataque

```
Internet ──► Metabase (0.0.0.0:3000, imagem :latest de 9 meses atrás)
                │  atacante vira admin (método não confirmado:
                │  senha fraca ou falha do Metabase)
                ▼
             SQL nativo pela conexão "Tech Finance" ──► role SUPERUSER
                │
                ▼
             COPY ... FROM PROGRAM '...'   ← execução de comandos como uid 70 (postgres)
                │
                ├─► reconhecimento: id, uname, saída via DNS/HTTP (smartdnslog)
                ├─► download do xmrig (proxies do GitHub) → /tmp/.sysd/kworker
                ├─► persistência: role _svmaint + pg_hba 0.0.0.0/0 + scripts no volume PGDATA
                └─► roubo de credenciais dos outros bancos cadastrados no Metabase
```

## Por que ninguém achava

| Ferramenta ou abordagem | Por que não resolveu |
|---|---|
| Antivírus do provedor | Detecta e mata o binário, mas não explica a origem. O backdoor continuava lá e o minerador voltava. |
| `ps` / `top` no host | Entre um kill e outro não havia nada rodando. E quando rodava, aparecia como `kworker`, nome de thread do kernel. |
| Scanners de host (rkhunter, chkrootkit, Lynis) | O host estava limpo. O malware estava na camada gravável do container. |
| ufw ativo | O Docker publica portas por cima do ufw (regras próprias no iptables). O `ufw status` não mostrava a 3000, mas ela estava aberta. |
| Recriar o container | Limpa o `/tmp`, mas o role, o `pg_hba` e o `.pgcache/` ficam no **volume de dados**. |

## Como foi detectado

1. A carga do servidor estava sempre alta (~4.5 em 2 vCPU), sem um processo culpado no host.
2. **`docker diff <container>`** em todos os containers. Esse foi o comando decisivo: ele mostra os arquivos adicionados na camada gravável. No container do Postgres apareceram ~40 arquivos ocultos em `/tmp`, incluindo `xmrig-6.21.3/` e o binário renomeado.
3. Os nomes dos arquivos de saída do atacante tinham o IP da vítima e a porta `3000`. Isso apontou o Metabase como porta de entrada.
4. Dentro do Postgres: `SELECT rolname, rolsuper FROM pg_roles` mostrou um superuser desconhecido. O `pg_hba.conf` tinha uma linha nova liberando esse role de qualquer IP.
5. `ls -la $PGDATA` mostrou arquivos ocultos no volume de dados.
6. No banco interno do Metabase (`core_user`, `api_key`): três admins e três chaves de API que o dono não criou, o primeiro de dois dias antes do primeiro sinal no Postgres.

## Correção

Detalhada em [`remediation-playbook.md`](remediation-playbook.md). Em resumo:

1. Backup só de dados (`pg_dump --no-owner --no-privileges`), para não levar o role malicioso junto.
2. Destruir a stack comprometida **incluindo os volumes**.
3. Auditar o resto: `docker diff` nos outros containers, roles dos outros bancos e, no host, UID 0, `ld.so.preload`, crons, `dpkg --verify`.
4. Revisar a superfície exposta: o que está publicado em `0.0.0.0` e o que fica público pelo proxy reverso.
5. **SSH:** a config efetiva aceitava senha **e** login de root, porque um arquivo do cloud-init sobrescrevia o `sshd_config`. Só o `sshd -T` mostrou isso.
6. Atualizar o que fica público (n8n estava 10 meses atrasado) e fixar versões.
7. Trocar todos os segredos que estavam acessíveis no ambiente comprometido.

## Lições, que viraram verificações do sentinel-scan

1. **Olhe dentro dos containers**, não só o host → `docker diff`.
2. **Docker ignora o ufw** → listar portas publicadas em `0.0.0.0` e `::`.
3. **Ferramenta de BI conectada como superusuário = execução remota de comandos** → `COPY FROM PROGRAM`.
4. **A persistência mora no volume** → arquivos ocultos em `PGDATA`, roles e `pg_hba` fora do padrão.
5. **Leia a configuração efetiva, não o arquivo** → `sshd -T`.
6. **`:latest` baixado uma vez nunca é atualizado** → idade das imagens.
7. **Nome de thread do kernel fora do kernel** → processo `kworker` cujo pai não é o PID 2.
8. **Contas de admin com e-mail estranho** (`svc-backup-*@local.dev`, `*@forensics.local`) → listar os admins dos apps conhecidos.

Especificação completa: [`checks-spec.md`](checks-spec.md).
