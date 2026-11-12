# Especificação das verificações

Cada verificação tem: **ID**, **gravidade**, **o que detecta**, **como detecta**, **falsos positivos conhecidos** e **correção sugerida**.
Todas são **somente leitura**. Status: ✅ no protótipo bash (`playbook/quick-diagnosis.sh`) · 🔜 planejada.

Gravidades: `CRITICAL` (comprometimento provável) · `HIGH` (porta de entrada aberta) · `MEDIUM` (risco relevante) · `INFO`.

Origem: as verificações marcadas com 📌 vêm direto do [estudo de caso](case-study-2026-11-metabase-xmrig.md).

---

## Exposição (EXP)

### EXP-001 · Porta de container publicada em todas as interfaces 📌 ✅
- **Gravidade:** HIGH se a imagem for banco ou painel de admin (lista abaixo); MEDIUM nos outros casos; INFO para proxy reverso nas portas 80/443.
- **Detecta:** `docker ps --format '{{.Ports}}'` contendo `0.0.0.0:` ou `[::]:`.
- **Por que importa:** o Docker insere regras próprias no iptables e **ignora o ufw**. O `ufw status` não mostra essas portas.
- **Imagens sensíveis:** postgres, mysql, mariadb, mongo, redis, memcached, elasticsearch, opensearch, couchdb, rabbitmq, minio, metabase, superset, redash, grafana, kibana, adminer, phpmyadmin, pgadmin, portainer, jupyter, n8n, nodered, code-server.
- **Correção:** `"127.0.0.1:PORTA:PORTA"` no compose, ou só pelo proxy reverso com autenticação.

### EXP-002 · Serviço do host escutando fora do loopback 🔜
- **Gravidade:** MEDIUM (fora das portas 22, 80 e 443).
- **Detecta:** `ss -tlnpH`, excluindo `127.0.0.0/8`, `::1` e as portas que são do docker-proxy.

### EXP-003 · Regras de firewall órfãs 🔜
- **Gravidade:** INFO.
- **Detecta:** regra `ufw allow` para uma porta em que nada escuta (o caso da 25565 do Minecraft).

### EXP-004 · Painel público sem autenticação 🔜
- **Gravidade:** HIGH.
- **Detecta:** a partir do host, `curl` nas rotas públicas do traefik/nginx/caddy; resposta 200 em rotas de admin conhecidas.
- **Cuidado:** é a única verificação que gera tráfego de rede. Precisa ser opt-in (`--probe`).

---

## Comprometimento em containers (CTR)

### CTR-001 · Arquivos ocultos em diretórios temporários do container 📌 ✅
- **Gravidade:** CRITICAL se houver nome de minerador ou executável; HIGH para dotfile em `/tmp` fora da lista de exceções.
- **Detecta:** `docker diff <c>` → linhas `A /tmp/.x`, `A /var/tmp/.x`, `A /dev/shm/.x`.
- **Exceções:** `.X11-unix`, `.ICE-unix`, `.XIM-unix`, `.font-unix`, `.s.PGSQL.*`, `.java_pid*`, `hsperfdata_*`.
- **Desempenho:** `docker diff` pode demorar em containers com muita escrita. Usar timeout por container (20 s).

### CTR-002 · Binário de minerador na camada gravável 📌 ✅
- **Gravidade:** CRITICAL.
- **Detecta:** `docker diff` com caminho contendo `xmrig`, `kworker`, `kdevtmpfsi`, `kinsing`, `.khw`, `minerd`, `cpuminer`.

### CTR-003 · Processo suspeito dentro de container 🔜
- **Gravidade:** CRITICAL.
- **Detecta:** `docker top` com argumentos `--donate-level`, `stratum+tcp`, `-o pool`, `--coin`, `rx/0`; ou um shell (`sh`, `bash`) filho do processo principal de um banco de dados.

### CTR-004 · Container privilegiado ou com socket do Docker 🔜
- **Gravidade:** HIGH (MEDIUM para traefik/portainer montando `docker.sock:ro`).
- **Detecta:** `HostConfig.Privileged`, `CapAdd` contendo `SYS_ADMIN`, montagem de `/`, `/var/run/docker.sock`, `PidMode=host`.
- **Por que importa:** quem compromete esse container vira root no host.

---

## Bancos de dados (DB)

### DB-001 · Role superuser inesperado no Postgres 📌 ✅
- **Gravidade:** CRITICAL.
- **Detecta:** `SELECT rolname FROM pg_roles WHERE rolsuper AND rolname NOT IN ('postgres', $POSTGRES_USER)`.
- **Falso positivo:** superusers criados de propósito pelo dono (o relatório lista para conferência).

### DB-002 · `pg_hba.conf` fora do padrão 📌 ✅
- **Gravidade:** CRITICAL se houver `trust` fora do loopback ou usuário específico com `0.0.0.0/0`; MEDIUM para outras linhas não padrão.
- **Padrão da imagem oficial:** `local`/`127.0.0.1`/`::1` com trust, mais `host all all all scram-sha-256`.

### DB-003 · Arquivos ocultos no PGDATA 📌 ✅
- **Gravidade:** HIGH.
- **Detecta:** `ls -A $PGDATA` com nomes começando por `.`.
- **Por que importa:** é persistência que **sobrevive à recriação do container**.

### DB-004 · App conectado como superuser 📌 🔜
- **Gravidade:** HIGH (CRITICAL se o app em questão estiver publicamente exposto, ver EXP-001).
- **Detecta:** `pg_stat_activity` agrupado por `usename` e `client_addr` → relacionar o IP com o container (via `docker network inspect`) → se o role for superuser, alertar.
- **Por que importa:** superuser executa `COPY ... FROM PROGRAM`, ou seja, comandos no sistema operacional. Foi o vetor do incidente.

### DB-005 · Mongo, Redis, CouchDB ou Elasticsearch sem autenticação 🔜
- **Gravidade:** HIGH (CRITICAL se exposto).
- **Detecta:** Mongo sem `--auth`; Redis sem `requirepass` ou `protected-mode no`; CouchDB sem `require_valid_user`; Elasticsearch com `xpack.security.enabled=false`.

---

## Aplicações (APP)

### APP-001 · Admins e chaves de API no Metabase 📌 🔜
- **Gravidade:** INFO (lista para revisão); HIGH se o e-mail bater com os padrões de IOC.
- **Detecta:** no banco de aplicação do Metabase, `core_user WHERE is_superuser` e `api_key`, com `date_joined`.

### APP-002 · Contas e chaves de API no n8n 🔜
- **Detecta:** tabelas `user` e `user_api_keys` do SQLite ou Postgres do n8n (ler uma cópia, nunca o arquivo em uso).

### APP-003 · Imagem `:latest` ou sem tag, antiga 📌 ✅
- **Gravidade:** MEDIUM se a imagem tiver mais de 90 dias, HIGH se também estiver exposta.
- **Detecta:** `Config.Image` sem tag ou com tag `latest`, e `.Created` da imagem.

---

## Host (HOST): requer root

### HOST-001 · Configuração efetiva do SSH 📌 ✅
- **Gravidade:** CRITICAL se `passwordauthentication yes` e `permitrootlogin yes` juntos; HIGH para cada um isolado.
- **Detecta:** `sshd -T` (**não** ler os arquivos, porque o `sshd_config.d/50-cloud-init.conf` sobrescreve o principal).

### HOST-002 · Usuário com UID 0 além do root ✅
- **Gravidade:** CRITICAL.

### HOST-003 · `/etc/ld.so.preload` existe ✅
- **Gravidade:** CRITICAL (técnica clássica de rootkit em espaço de usuário).

### HOST-004 · Executáveis em diretórios temporários do host ✅
- **Gravidade:** HIGH. Diretórios: `/tmp`, `/var/tmp`, `/dev/shm`.

### HOST-005 · Processo com nome de thread do kernel fora do kernel 📌 ✅
- **Gravidade:** CRITICAL.
- **Detecta:** `comm` começando por `kworker`, `kthreadd`, `ksoftirqd` ou `migration`, com **PPID ≠ 2** e PID ≠ 2.

### HOST-006 · Conexões com portas típicas de pool de mineração 📌 ✅
- **Gravidade:** HIGH.
- **Detecta:** `ss -tnH state established` com porta remota em {3333, 4444, 5555, 6666, 7777, 9999, 14433, 14444, 45700}, ou destino na lista de IOCs.

### HOST-007 · Binários do sistema alterados 🔜
- **Gravidade:** CRITICAL.
- **Detecta:** `dpkg --verify` (Debian/Ubuntu) ou `rpm -Va` (RHEL), ignorando arquivos de configuração (`c`).

### HOST-008 · Persistência: cron, systemd, chaves SSH 🔜
- **Gravidade:** INFO (lista para revisão) ou HIGH para padrões como `curl|sh`, `wget -O- |`, base64 decodificado e executado.
- **Detecta:** crontabs de todos os usuários, `/etc/cron.*`, units em `/etc/systemd/system` que não pertencem a pacotes, `authorized_keys` de todos os usuários (com comentário e data).

### HOST-009 · Contas padrão do provedor com sudo NOPASSWD 📌 🔜
- **Gravidade:** MEDIUM.
- **Detecta:** usuários em `/etc/sudoers.d/*` com `NOPASSWD`, senha não bloqueada (`passwd -S`) e sem uso recente.
