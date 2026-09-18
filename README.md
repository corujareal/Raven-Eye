# RavenEye v6.6.6 — I see you

## Execução

### Instalação sem root (com `sudo raven` já pronto ao final)

Em Linux e Termux, a instalação em espaço do usuário cria o comando `raven`,
sem alterar o Python do sistema e sem exigir `venv`:

```bash
./installer/install.sh
raven --help
```

Esse único comando instala **o pacote completo** (crawler, scanner, todos os
protocolos de bruteforce assíncrono — SSH, RDP, SMB, FTP, MySQL, PostgreSQL,
MongoDB, LDAP, SMTP..., relatórios TXT/JSON/HTML/CSV/Markdown/PDF, Playwright,
uvloop) e, em seguida, **encadeia automaticamente um `sudo`** para configurar
o wrapper global — ao final da mesma execução, tanto `raven` quanto
`sudo raven` já funcionam. Isso resolve de fábrica o erro clássico
`sudo: raven: comando não encontrado`, causado pelo `secure_path` do `sudo`
não incluir `~/.local/bin`.

Sem argumentos, `raven` abre o menu interativo — como o `nmap`, basta digitar
o comando e navegar pelos módulos. Para uso direto/scriptável, passe um
comando: `raven scanner <URL>`, `raven crawler <URL>`, `raven full <URL>`, etc.

O instalador detecta Termux por `PREFIX`; em outros Linux usa `~/.local/bin`.
Se necessário, ele informa o ajuste de `PATH` em vez de modificá-lo silenciosamente.
No Termux não existe `sudo`, então essa etapa é pulada automaticamente; se o
sistema não tiver `sudo` instalado, também é pulada — sem qualquer flag para
decidir isso, é tudo automático conforme o ambiente.

Não há modos ou flags separados para escolher: `./installer/install.sh` sem
argumentos sempre instala o pacote completo e sempre tenta configurar
`sudo raven` na mesma execução. As dependências já são instaladas como o
usuário atual antes dessa etapa, então o passo com `sudo` só copia o wrapper
para `/usr/local/bin` — nenhum comando privilegiado baixa ou instala pacotes.
Se esse passo falhar (por exemplo, sem senha de sudo disponível num
terminal não interativo), basta rodar o instalador de novo para tentar outra
vez; `raven` (sem sudo) já funciona normalmente enquanto isso.

Os comandos `scanner`, `crawler` e `full` funcionam sem root para alvos
explicitamente autorizados; use `sudo raven` apenas quando uma função
específica realmente exigir privilégio elevado.

Todas as dependências ficam embutidas no próprio `installer/install.sh` (sem
`requirements*.txt` para manter sincronizado) e são instaladas em `_vendor`
dentro da instalação — isso mantém `raven` e `sudo raven` no mesmo ambiente
sem exigir ativação de shell. Se a rede estiver indisponível, o instalador
falha de forma explícita; `RAVENEYE_SKIP_DEPS=1` pode ser usado somente para
diagnóstico offline (`--help` e inspeções locais).

### Desinstalação

```bash
sh installer/uninstall.sh              # remove a instalação de usuário
sudo sh installer/uninstall.sh --system-wrapper  # remove o wrapper global
sh installer/uninstall.sh --all -y     # ambos, sem confirmação (funciona
                                        # mesmo rodado só com sudo: o script
                                        # resolve o home do usuário real via
                                        # SUDO_USER, não usa o $HOME de root)
```

O desinstalador só remove o que o instalador criou (`raven` e a cópia em
`~/.local/share/raveneye` ou equivalentes no Termux). Arquivos gerados durante
o uso — `raven_eye_config.json`, `data/raveneye.db`, `output/`, `reports/`,
`raveneye.log` — ficam na pasta de onde você roda `raven`, não na instalação,
e não são tocados; apague-os manualmente se quiser.

### venv (uso manual/desenvolvimento)

Sem o installer, é possível rodar a partir do próprio `pyproject.toml`
(backend `poetry-core`, sem precisar de `requirements.txt`):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
python3 RavenEye.py -h
python3 RavenEye.py
```

### Termux (manual, sem o installer)

```bash
pkg update
pkg install python
python -m venv .venv
. .venv/bin/activate
pip install .
python3 RavenEye.py -h
python3 RavenEye.py
```

O launcher é `RavenEye.py` e deve ser executado a partir da pasta do projeto;
não é necessário informar caminho absoluto. O caminho recomendado continua
sendo `./installer/install.sh` (ver acima), que já resolve o perfil correto
para Termux automaticamente.

## Dependências

Não há mais `requirements*.txt`: as listas de dependências vivem em um único
lugar, `installer/install.sh` (blocos `CORE_DEPS`, `FULL_DEPS`, `PROTOCOL_DEPS`,
`TEST_DEPS`), que é o que o instalador de fato executa. `pyproject.toml`
continua sendo a declaração canônica para quem instala via `pip install .`.

## API / integrações
- Shodan: https://developer.shodan.io/api
- VirusTotal: https://docs.virustotal.com/reference/overview
- Google Programmable Search / Custom Search JSON API: https://developers.google.com/custom-search/v1/overview
- NVD: https://nvd.nist.gov/developers/vulnerabilities
- crt.sh: https://crt.sh/
- Internet Archive CDX: https://github.com/internetarchive/wayback/tree/master/webservices
- Exploit-DB/SearchSploit: https://www.exploit-db.com/

## Scanner de vulnerabilidades
O scanner é um módulo independente do crawler e do NUKE/C4. Ele usa evidência, baseline, confidence e deduplicação. Indícios não confirmados permanecem como candidatos e não são apresentados como exploração comprovada.

### Correlação local de CVEs

O scanner correlaciona CVEs apenas quando identifica a tecnologia e a versão exata
na resposta e há correspondência em uma base local. Isso evita inferir que uma
versão "próxima" é vulnerável. Configure `RAVENEYE_CVE_RECORDS_PATH` com um JSON
normalizado (`product`, `version`, `cve`) ou uma exportação JSON do NVD; o RavenEye
não baixa feeds nem executa exploits automaticamente.

## Banco
O SQLite é inicializado automaticamente. Ele armazena cache, fingerprints, CVEs, scans e findings; segredos não são persistidos em claro.

## Relatórios
Os relatórios de scan contêm somente resultados, evidências redigidas, impacto, severidade, confiança e remediação. Notas de desenvolvimento ficam consolidadas em `docs/DEVELOPMENT_HISTORY.md` e não são misturadas aos relatórios.

## Identidade
Versão: **6.6.6**

Lema: **I see you**


## CLI unificada

A entrada recomendada, uma vez instalado, é `raven` — um único comando, no
estilo `nmap`: sem argumentos abre o menu interativo, com um comando/URL roda
direto.

```bash
raven                              # menu interativo
raven -h
raven scanner -h
raven crawler -h
raven full -h
raven nuke -h
raven report -h
raven database -h
raven logs -h
raven doctor -h
```

Exemplos:

```bash
raven scanner https://alvo-autorizado.example
raven crawler https://alvo-autorizado.example -p 100 -n -s   # páginas, Nmap e Shodan
raven full https://alvo-autorizado.example -o saida          # fluxo completo
raven report -f pdf -o relatorio
raven database -i
raven logs -w raveneye.log
raven doctor -j
```

Use `raven <comando> -h` para a referência completa de cada módulo. Os nomes
longos (`--pages`, `--nmap`, `--shodan`, `--output` etc.) continuam aceitos.

Sem o installer (execução manual em venv), o mesmo CLI é acessado via
`python3 RavenEye.py [comando] [opções]` — é o mesmo programa; `raven` é só o
wrapper instalado que já resolve o ambiente/dependências.

Ciclo de manutenção: **verificar → forçar em ambiente controlado → encontrar erro → corrigir → testar novamente → aumentar a segurança**.

## Loop de QA e manutenção

Toda evolução deve seguir: **verificar → forçar em ambiente controlado → encontrar erro → corrigir → testar novamente → aumentar a segurança → repetir**.

O release não considera uma heurística como vulnerabilidade confirmada sem evidência suficiente; candidatos recebem confidence apropriado e permanecem no histórico do banco para comparação entre scans.

## Diagnóstico local

Use o comando `doctor` para verificar o ambiente sem fazer requisições de rede:

```bash
raven doctor
raven doctor --json
```

Ele verifica Python, venv/Termux, dependências core, integrações opcionais, permissões locais e a presença do cache do Playwright.

## Exportação de relatórios

O RavenEye 6.6.6 suporta relatórios TXT, JSON, HTML, Markdown, CSV e **PDF**. O PDF é gerado localmente, sem CDN ou serviço externo, usando a paleta preto/roxo/vermelho. Quando o resultado do scan contém caminhos locais em `screenshots`, `images`, `evidence_images` ou imagens anexadas a findings, elas são incorporadas ao PDF.

No Leitor de Logs, `export` informa os formatos disponíveis: **CSV | JSONL | PDF**. Exemplo: `export <arquivo> <categoria> <saida.pdf>`.

Dependência PDF: `reportlab` e `Pillow` — fazem parte do grupo `FULL_DEPS` do instalador, sempre instalado junto com o resto em qualquer plataforma.

## Exportação do Leitor de Logs

Ao digitar `export` no leitor de logs, o RavenEye apresenta os formatos disponíveis:

- CSV (`.csv`)
- JSONL (`.jsonl`)
- PDF (`.pdf`)

O PDF é validado após a geração e a extensão correta é adicionada automaticamente quando o nome de saída não possui extensão.


## Termux / Python 3.14

O `installer/install.sh` já detecta o Termux (`PREFIX`) e sempre instala o
pacote completo, igual em qualquer outra plataforma (sem `sudo`, que não
existe no Termux). Se algum pacote nativo — lxml, pydantic, SQLAlchemy,
reportlab, Pillow — não compilar no seu dispositivo específico, instale as
ferramentas de build do Termux antes e rode o instalador de novo:

```bash
pkg install clang make rust
./installer/install.sh
```

Para diagnosticar localmente sem depender da rede (só `--help` e inspeções
locais), use `RAVENEYE_SKIP_DEPS=1 sh installer/install.sh`. Use
`raven doctor --json` para inspecionar as capacidades opcionais disponíveis.

## Termux smoke test

Depois de instalar, rode `python3 scripts/termux_smoke.py`. Ele faz apenas
checagens locais de import e não realiza nenhuma requisição de rede.

## Arquitetura durante a transição

`raveneye/` contém os módulos novos e assíncronos. `raveneye_pkg/` é mantido temporariamente como camada legada para backward compatibility. A presença de APIs síncronas nessa camada legada não significa que elas sejam usadas pelos módulos novos; a migração é incremental e cada remoção exige regressão verde.


---

## Estrutura organizada

```text
RavenEye.py                 # launcher principal (também é o que 'raven' executa)
installer/
  install.sh                 # instalador único: deps embutidas, sempre
                              # instala o pacote completo e configura
                              # 'sudo raven' automaticamente na mesma execução
  uninstall.sh                # desinstalador simétrico
  raven                       # template do wrapper instalado como comando `raven`
raveneye/                   # engine modular/assíncrona
raveneye_pkg/                # camada legada para backward compatibility
tests/                       # testes organizados por domínio
scripts/                     # build (build_release.py), auditoria e smoke tests
examples/                    # exemplos de relatórios
reports/PDF/                # PDFs gerados em runtime
docs/DEVELOPMENT_HISTORY.md # histórico consolidado
MIGRATION.md                 # guia de migração
README.md                    # documentação principal
pyproject.toml               # metadados/deps para `pip install .` e config de testes
```

O diretório `reports/PDF/` é criado/preservado para acesso rápido aos PDFs gerados; nenhum PDF de runtime é empacotado no release.
