#!/usr/bin/env bash
# Cria um ambiente "infectado" DE MENTIRA para validar o scanner.
# Nenhum binário real de minerador é usado: só arquivos de texto com os mesmos nomes
# e um `sleep` renomeado para "kworker".
#
#   bash tests/fake-infected.sh up      # sobe
#   bash playbook/quick-diagnosis.sh    # deve acusar CTR-001/002, DB-001/002/003, EXP-001, HOST-005
#   bash tests/fake-infected.sh down    # remove tudo
set -euo pipefail
NAME=sentinel-test-pg
case "${1:-}" in
  up)
    docker run -d --name $NAME -e POSTGRES_PASSWORD=test -e POSTGRES_USER=app \
      -p 0.0.0.0:55432:5432 postgres:16-alpine >/dev/null
    until docker exec $NAME pg_isready -U app >/dev/null 2>&1; do sleep 1; done; sleep 2
    # artefatos do incidente (texto inofensivo)
    docker exec -u postgres $NAME sh -c '
      mkdir -p /tmp/.sysd/xmrig-6.21.3 /tmp/.xr
      echo FAKE > /tmp/.sysd/xmrig-6.21.3/config.json
      echo FAKE > /tmp/.g2.sh; echo FAKE > /tmp/.w2_10-0-0-1-3000
      cp /bin/sleep /tmp/.sysd/kworker
      mkdir -p "$PGDATA/.pgcache"; echo FAKE > "$PGDATA/.pgcache/re.sh"
      echo "host all _svmaint 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"'
    docker exec $NAME psql -U app -d app -c "CREATE ROLE _svmaint SUPERUSER LOGIN PASSWORD 'x';" >/dev/null
    # processo que se renomeia para "kworker" (como o malware faz) para testar HOST-005.
    # O "; :" no final impede o shell de fazer exec no sleep e perder o nome.
    docker exec -d -u postgres $NAME sh -c 'printf kworker > /proc/$$/comm; sleep 600; :'
    echo "ambiente falso no ar: container $NAME"
    ;;
  down) docker rm -f $NAME >/dev/null && echo removido ;;
  *) echo "uso: $0 up|down"; exit 1 ;;
esac
