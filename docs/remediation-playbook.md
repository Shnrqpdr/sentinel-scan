# Playbook: VPS com Docker possivelmente comprometida

O que fazer, em ordem, quando aparece um alerta de malware ou uma carga de CPU sem explicação. Generalizado a partir do [estudo de caso](case-study-2026-11-metabase-xmrig.md).

> **Regra de ouro:** primeiro só leitura. Entenda **como** entraram antes de apagar qualquer coisa; senão o atacante volta pelo mesmo caminho.

## 1. Triagem (5 min, só leitura)

```bash
uptime; nproc                                   # carga alta x número de CPUs
ps -eo pid,ppid,user,%cpu,etime,cmd --sort=-%cpu | head -20
ss -tunp | grep ESTAB                           # conexões de saída estranhas
ss -tulnp | grep -v 127.0.0                     # o que escuta para fora
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
```

Sinais de alerta:
- carga alta e constante sem um processo culpado;
- processo chamado `kworker`, `kthreadd`, `systemd-*` ou `[algo]` cujo **PPID não é 2**;
- conexão para portas 3333, 4444, 5555, 7777 ou 14444 (pools de mineração).

## 2. Procurar dentro dos containers

```bash
for c in $(docker ps -aq); do
  n=$(docker inspect -f '{{.Name}}' "$c")
  out=$(timeout 30 docker diff "$c" | grep -E '^A /(tmp|var/tmp|dev/shm)/\.' | head)
  [ -n "$out" ] && printf '### %s\n%s\n' "$n" "$out"
done
for c in $(docker ps -q); do docker top "$c" -eo pid,user,pcpu,args; done
```

Achou algo? **Não apague ainda.** Leia os scripts (`head`, nunca execute) para entender o vetor: nomes de arquivo com IP e porta da vítima costumam dizer por onde entraram.

## 3. Bancos de dados

**Postgres:**
```sql
SELECT rolname, rolsuper, rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_';
```
```bash
docker exec <db> sh -c 'grep -v "^#" "$PGDATA/pg_hba.conf" | grep -v "^$"; ls -la "$PGDATA" | grep " \."'
```

- Superuser além do `POSTGRES_USER` → backdoor quase certo.
- Linha no `pg_hba` com usuário específico e `0.0.0.0/0` → backdoor.
- Arquivos ocultos em `PGDATA` → persistência que sobrevive à recriação do container.

**Outros:** Mongo sem `--auth`, Redis sem senha, CouchDB sem `require_valid_user`.

## 4. Apps com painel de admin (Metabase, n8n, Grafana, Portainer…)

- Liste os usuários admin e as chaves de API, com data de criação. Desconfie de e-mails como `svc-*`, `backup*`, `*@local.dev`, `*@forensics.local` e de contas que você não criou.
- Veja quais conexões de banco o app usa e **com qual role**.

## 5. Host (precisa de root)

```bash
awk -F: '$3==0' /etc/passwd                     # só root
cat /etc/ld.so.preload                          # não deve existir
ls -la /var/spool/cron/crontabs /etc/cron.d
find /tmp /var/tmp /dev/shm -type f -perm -u+x
dpkg --verify openssh-server sudo coreutils procps util-linux systemd bash
for u in /root /home/*; do cat "$u/.ssh/authorized_keys" 2>/dev/null; done
sshd -T | grep -E '^(passwordauthentication|permitrootlogin) '
```

## 6. Conter e erradicar

1. **Backup só de dados**, sem roles: `pg_dump --no-owner --no-privileges -d <db> | gzip > backup.sql.gz`.
2. Derrube a stack **com os volumes**: `docker compose down -v --rmi all --remove-orphans`.
   - Se precisar manter o volume: `DROP ROLE <backdoor>`, limpar o `pg_hba.conf`, apagar os arquivos ocultos de `PGDATA` e recriar o container.
3. Feche a porta de entrada **antes** de subir de novo:
   - portas como `127.0.0.1:PORTA:PORTA`, ou só pelo proxy reverso com autenticação;
   - o app de BI conecta com um **role somente leitura, sem superuser**;
   - imagem com versão fixa e atualizada.
4. Troque **todos** os segredos que o container comprometido podia ler: as variáveis de ambiente do container e as credenciais guardadas no app.

## 7. Endurecer o resto

```conf
# /etc/ssh/sshd_config.d/00-hardening.conf
# o prefixo 00 é de propósito: no sshd vale o primeiro valor lido,
# e ele precisa vir antes do 50-cloud-init.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
PermitEmptyPasswords no
X11Forwarding no
```
```bash
sshd -t && systemctl reload ssh
# teste numa SEGUNDA sessão antes de fechar a atual
```

- Bloqueie contas não usadas: `passwd -l ubuntu`.
- Remova regras de firewall de serviços que não existem mais.
- Atualize o que fica público e fixe as versões das imagens.
- Peça ao provedor um novo scan.
