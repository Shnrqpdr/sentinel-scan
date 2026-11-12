#!/usr/bin/env bash
# sentinel-scan, protótipo: diagnóstico rápido de VPS com Docker.
# SOMENTE LEITURA: não altera, apaga, executa ou envia nada para fora.
#
# Uso:  sudo bash quick-diagnosis.sh          (completo)
#       bash quick-diagnosis.sh               (sem root: pula as verificações do host que precisam de root)
#       ssh user@host 'sudo bash -s' < quick-diagnosis.sh
#
# Verificações: docs/checks-spec.md

set -u
export LC_ALL=C

# ---------- saída ----------
if [ -t 1 ]; then
  R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[34m'; G=$'\e[32m'; D=$'\e[2m'; BOLD=$'\e[1m'; N=$'\e[0m'
else R=; Y=; B=; G=; D=; BOLD=; N=; fi

CRIT=0; HIGHC=0; MED=0; INFOC=0
finding() { # finding <SEV> <ID> <título> [detalhe] [correção]
  local sev=$1 id=$2 title=$3 detail=${4:-} fix=${5:-} c
  case $sev in
    CRITICAL) c=$R; CRIT=$((CRIT+1));;
    HIGH)     c=$R; HIGHC=$((HIGHC+1));;
    MEDIUM)   c=$Y; MED=$((MED+1));;
    *)        c=$B; INFOC=$((INFOC+1));;
  esac
  printf '%s[%-8s]%s %s%s%s  %s\n' "$c" "$sev" "$N" "$BOLD" "$id" "$N" "$title"
  [ -n "$detail" ] && printf '%s\n' "$detail" | sed "s/^/             ${D}│${N} /"
  [ -n "$fix" ]    && printf '             %s↳ correção:%s %s\n' "$G" "$N" "$fix"
}
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$N"; }
have() { command -v "$1" >/dev/null 2>&1; }

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
DOCKER=0; have docker && docker info >/dev/null 2>&1 && DOCKER=1

MINER_RE='xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|/kworker$|/\.khw$|/\.kw$|udev-notify'
SENSITIVE_RE='postgres|mysql|mariadb|mongo|redis|memcached|elasticsearch|opensearch|couchdb|rabbitmq|minio|metabase|superset|redash|grafana|kibana|adminer|phpmyadmin|pgadmin|portainer|jupyter|n8n|node-red|nodered|code-server'
PROXY_RE='traefik|nginx|caddy|haproxy|envoy'
POOL_PORTS=' 3333 4444 5555 6666 7777 9999 14433 14444 45700 '

printf '%ssentinel-scan (protótipo)%s · %s · %s · root=%s docker=%s\n' "$BOLD" "$N" \
  "$(hostname)" "$(date -u +%FT%TZ)" "$IS_ROOT" "$DOCKER"
printf '%sCarga: %s · CPUs: %s%s\n' "$D" "$(cut -d' ' -f1-3 /proc/loadavg)" "$(nproc)" "$N"

# =====================================================================
section "Exposição"
# =====================================================================
if [ $DOCKER -eq 1 ]; then
  while IFS=$'\t' read -r name image ports; do
    [ -z "$ports" ] && continue
    pub=$(printf '%s' "$ports" | tr ',' '\n' | grep -E '0\.0\.0\.0:|\[::\]:|:::' | sed 's/^ *//' | sort -u)
    [ -z "$pub" ] && continue
    hostports=$(printf '%s\n' "$pub" | sed -E 's/.*:([0-9]+)->.*/\1/' | sort -u | tr '\n' ' ')
    if printf '%s' "$image" | grep -qiE "$SENSITIVE_RE"; then
      finding HIGH EXP-001 "$name ($image) publicado na internet: portas $hostports" \
        "Banco/painel de admin acessível de fora. O Docker ignora o ufw.
$pub" "trocar para \"127.0.0.1:PORTA:PORTA\" no compose, ou publicar só pelo proxy reverso com autenticação"
    elif printf '%s' "$image" | grep -qiE "$PROXY_RE" && [ -z "$(printf '%s\n' $hostports | grep -vxE '80|443')" ]; then
      finding INFO EXP-001 "$name ($image) é o proxy reverso público (80/443)"
    else
      finding MEDIUM EXP-001 "$name ($image) publicado na internet: portas $hostports" \
        "O Docker ignora o ufw: essas portas ficam abertas mesmo com o firewall ativo." \
        "se não precisa ser público, usar \"127.0.0.1:PORTA:PORTA\""
    fi
  done < <(docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}')
else
  finding INFO EXP-001 "Docker indisponível ou sem permissão: verificações de container puladas" "" \
    "rodar com sudo ou com um usuário do grupo docker"
fi

# =====================================================================
section "Containers"
# =====================================================================
if [ $DOCKER -eq 1 ]; then
  for c in $(docker ps -aq); do
    name=$(docker inspect -f '{{.Name}}' "$c" | sed 's#^/##')
    diff=$(timeout 20 docker diff "$c" 2>/dev/null) || {
      [ $? -eq 124 ] && finding INFO CTR-001 "$name: docker diff passou de 20 s, pulado"; continue; }
    added=$(printf '%s\n' "$diff" | awk '$1=="A"{print $2}')
    miner=$(printf '%s\n' "$added" | grep -E "$MINER_RE" | head -8)
    if [ -n "$miner" ]; then
      finding CRITICAL CTR-002 "$name: binário/arquivo de minerador na camada do container" "$miner" \
        "NÃO apague ainda: leia os scripts (head) para achar o vetor de entrada; veja docs/remediation-playbook.md"
    fi
    hidden=$(printf '%s\n' "$added" \
      | grep -E '^/(tmp|var/tmp|dev/shm)/\.' \
      | grep -vE '^/(tmp|var/tmp|dev/shm)/\.(X11-unix|ICE-unix|XIM-unix|font-unix|s\.PGSQL|java_pid)' )
    if [ -n "$hidden" ]; then
      n=$(printf '%s\n' "$hidden" | wc -l)
      finding HIGH CTR-001 "$name: $n arquivo(s) oculto(s) em diretório temporário" \
        "$(printf '%s\n' "$hidden" | head -10)$([ "$n" -gt 10 ] && printf '\n… e mais %s' $((n-10)))" \
        "inspecionar com: docker exec $name ls -la /tmp"
    fi
  done

  # imagens :latest / sem tag e antigas (APP-003)
  now=$(date +%s)
  while IFS=$'\t' read -r name image; do
    tag=${image##*:}; [ "$tag" = "$image" ] && tag=""
    case "$image" in *@sha256:*) continue;; esac
    if [ -z "$tag" ] || [ "$tag" = latest ] || printf '%s' "$tag" | grep -q '/'; then
      # imagem compilada localmente (sem RepoDigests) não vem de registry: ignorar
      [ -z "$(docker image inspect -f '{{join .RepoDigests ""}}' "$image" 2>/dev/null)" ] && continue
      created=$(docker image inspect -f '{{.Created}}' "$image" 2>/dev/null | cut -c1-19)
      [ -z "$created" ] && continue
      age=$(( (now - $(date -d "$created" +%s 2>/dev/null || echo "$now")) / 86400 ))
      [ "$age" -ge 90 ] && finding MEDIUM APP-003 "$name usa $image sem versão fixa, imagem com $age dias" \
        "Uma imagem :latest baixada uma vez nunca é atualizada sozinha." \
        "fixar a versão (ex.: imagem:1.2.3), atualizar e acompanhar as releases"
    fi
  done < <(docker ps --format '{{.Names}}\t{{.Image}}')
fi

# =====================================================================
section "Bancos de dados"
# =====================================================================
if [ $DOCKER -eq 1 ]; then
  for c in $(docker ps -q); do
    name=$(docker inspect -f '{{.Name}}' "$c" | sed 's#^/##')
    docker exec "$c" sh -c 'command -v psql >/dev/null && [ -n "${PGDATA:-}" ]' 2>/dev/null || continue

    q() { docker exec "$c" sh -c 'psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-${POSTGRES_USER:-postgres}}" -XAtc "$1"' _ "$1" 2>/dev/null; }
    pguser=$(docker exec "$c" sh -c 'echo "${POSTGRES_USER:-postgres}"')

    supers=$(q "select rolname from pg_roles where rolsuper and rolname not in ('postgres','$pguser')")
    [ -n "$supers" ] && finding CRITICAL DB-001 "$name: superuser inesperado no Postgres" "$supers" \
      "se você não criou: DROP ROLE <nome>; e revise o pg_hba.conf e o PGDATA"

    hba=$(docker exec "$c" sh -c 'grep -vE "^\s*(#|$)" "$PGDATA/pg_hba.conf"' 2>/dev/null \
      | grep -vE '^local\s+(all|replication)\s+all\s+trust\s*$' \
      | grep -vE '^host\s+(all|replication)\s+all\s+(127\.0\.0\.1/32|::1/128)\s+trust\s*$' \
      | grep -vE '^host\s+all\s+all\s+all\s+scram-sha-256\s*$')
    if [ -n "$hba" ]; then
      if printf '%s\n' "$hba" | grep -qE 'trust|0\.0\.0\.0/0|::/0'; then sev=CRITICAL; else sev=MEDIUM; fi
      finding "$sev" DB-002 "$name: pg_hba.conf fora do padrão da imagem oficial" "$hba" \
        "remover linhas que você não adicionou e rodar: SELECT pg_reload_conf();"
    fi

    dot=$(docker exec "$c" sh -c 'ls -A "$PGDATA" | grep "^\."' 2>/dev/null)
    [ -n "$dot" ] && finding HIGH DB-003 "$name: arquivos ocultos no PGDATA (persistência que sobrevive a recriar o container)" \
      "$dot" "inspecionar: docker exec $name ls -la \$PGDATA"

    # app conectado como superuser (DB-004, versão simples)
    conns=$(q "select distinct a.usename||' ← '||coalesce(host(a.client_addr),'local') from pg_stat_activity a join pg_roles r on r.rolname=a.usename where r.rolsuper and a.client_addr is not null and a.pid<>pg_backend_pid()")
    [ -n "$conns" ] && finding MEDIUM DB-004 "$name: aplicações conectadas como SUPERUSER" "$conns
Superuser pode executar comandos no SO (COPY ... FROM PROGRAM). Se o app for invadido, o banco vira shell." \
      "criar um role sem superuser só com os GRANTs necessários (somente leitura para BI)"
  done
fi

# =====================================================================
section "Host"
# =====================================================================
# HOST-005: nome de thread do kernel fora do kernel
fake=$(ps -eo pid=,ppid=,comm= | awk '$1!=2 && $2!=2 && $3 ~ /^(kworker|kthreadd|ksoftirqd|migration|rcu_)/')
[ -n "$fake" ] && finding CRITICAL HOST-005 "Processo se passando por thread do kernel" "PID PPID NOME
$fake" "ver: ls -l /proc/<PID>/exe ; cat /proc/<PID>/cmdline | tr '\\0' ' '"

# argumentos típicos de minerador (o colchete evita casar com o próprio processo do grep/ps)
margs=$(ps -eo pid=,args= | grep -E -- '[-]-donate-level|[s]tratum\+tcp|[-]-randomx|[x]mrig' | grep -v quick-diagnosis)
[ -n "$margs" ] && finding CRITICAL CTR-003 "Processo com argumentos de minerador" "$margs"

# HOST-006: conexões com portas de pool
if have ss; then
  pools=$(ss -tnH state established 2>/dev/null | awk '{print $4}' | while read -r peer; do
    p=${peer##*:}; case "$POOL_PORTS" in *" $p "*) echo "$peer";; esac; done | sort -u)
  [ -n "$pools" ] && finding HIGH HOST-006 "Conexões abertas para portas típicas de pool de mineração" "$pools" \
    "identificar o processo: ss -tnp | grep <ip>"
fi

# HOST-004: executáveis em tmp
ex=$(find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | head -10)
[ -n "$ex" ] && finding HIGH HOST-004 "Executáveis em diretórios temporários do host" "$ex"

# HOST-002 / HOST-003
uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
[ -n "$uid0" ] && finding CRITICAL HOST-002 "Usuário com UID 0 além do root" "$uid0"
[ -e /etc/ld.so.preload ] && finding CRITICAL HOST-003 "/etc/ld.so.preload existe (técnica de rootkit)" \
  "$(cat /etc/ld.so.preload 2>/dev/null || echo '(sem permissão para ler)')"

# HOST-001: SSH efetivo (precisa de root)
if [ $IS_ROOT -eq 1 ] && have sshd; then
  eff=$(sshd -T 2>/dev/null)
  pa=$(printf '%s\n' "$eff" | awk '$1=="passwordauthentication"{print $2}')
  pr=$(printf '%s\n' "$eff" | awk '$1=="permitrootlogin"{print $2}')
  fixssh='criar /etc/ssh/sshd_config.d/00-hardening.conf com "PasswordAuthentication no" e "PermitRootLogin prohibit-password"; sshd -t && systemctl reload ssh (teste numa 2ª sessão)'
  src=$(grep -lis '^\s*PasswordAuthentication\s\+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr '\n' ' ')
  if [ "$pa" = yes ] && [ "$pr" = yes ]; then
    finding CRITICAL HOST-001 "SSH aceita senha E login de root" "Configuração efetiva (sshd -T). 'yes' vem de: ${src:-?}" "$fixssh"
  else
    [ "$pa" = yes ] && finding HIGH HOST-001 "SSH aceita login por senha" "Definido em: ${src:-?}" "$fixssh"
    [ "$pr" = yes ] && finding HIGH HOST-001 "SSH permite login de root com senha" "" "$fixssh"
  fi
elif [ $IS_ROOT -eq 0 ]; then
  finding INFO HOST-001 "Sem root: config efetiva do SSH, crons e binários não verificados" "" "rodar com sudo"
fi

# =====================================================================
printf '\n%sResumo:%s %s%d crítico(s)%s · %s%d alto(s)%s · %s%d médio(s)%s · %d info\n' \
  "$BOLD" "$N" "$R" "$CRIT" "$N" "$R" "$HIGHC" "$N" "$Y" "$MED" "$N" "$INFOC"
[ $((CRIT+HIGHC)) -eq 0 ] && printf '%sNada crítico ou alto encontrado.%s Isso não prova que a máquina está limpa; veja docs/remediation-playbook.md.\n' "$G" "$N"
[ $CRIT -gt 0 ] && exit 2
[ $HIGHC -gt 0 ] && exit 1
exit 0
