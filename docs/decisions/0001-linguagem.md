# ADR 0001: Linguagem da implementação

**Status:** em aberto (o protótipo é em bash).

## Contexto

A ferramenta roda como root em servidores de terceiros, possivelmente comprometidos, e o público-alvo quer "baixar e rodar". As verificações são, na maioria, chamadas ao Docker e leitura de `/proc`, `/etc` e da saída de comandos.

## Opções

### Go
- ✅ Binário estático único: `curl -L .../sentinel-scan -o s && sudo ./s scan`.
- ✅ Não depende do interpretador nem das bibliotecas da máquina, o que é importante quando a máquina pode estar comprometida.
- ✅ SDK oficial do Docker é em Go. Compilação cruzada amd64/arm64 trivial.
- ❌ Escrever é mais lento, e há menos contribuidores casuais.

### Python
- ✅ Rápido de escrever; muita gente de DevOps e segurança sabe contribuir; o dono já usa.
- ❌ Depende do `python3` do host (versão variável; containers alpine nem têm).
- ❌ Ubuntu 24.04 bloqueia `pip install` global (PEP 668), o que obriga a usar pipx ou venv.
- ⚠️ Dá para empacotar (PyInstaller/shiv), mas é frágil entre distros.

### Bash, mantido como protótipo
- ✅ Já existe e roda em qualquer lugar.
- ❌ Fica ilegível passando de ~500 linhas, sem testes decentes nem JSON confiável.

## Recomendação

Go para a v0.1. As verificações ficam como dados (YAML de IOCs e regras), para que a comunidade contribua com regras sem precisar saber Go. Se a velocidade de desenvolvimento pesar mais, Python serve, e a interface de regras em YAML continua a mesma.
