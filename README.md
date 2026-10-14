# RavenEye v6.6.6 — I see you

## Execução

### Instalação completa em Linux (com `sudo raven` já pronto ao final)

Em Linux/Unix, a instalação em espaço do usuário cria o
comando `raven`, sem alterar o Python do sistema e sem exigir `venv`:

```bash
./installer/install.sh
raven --help
```

Esse comando instala o crawler, o scanner e os formatos de relatório disponíveis
no pacote. A auditoria de autenticação ativa nesta versão é HTTP(S), serial,
com confirmação do alvo, listas classificadas, limites locais e checkpoints
redigidos. O instalador instala as dependências Python e tenta preparar
Chromium para renderização headless. Firefox e WebKit são opcionais. Em Linux,
o instalador prefere Chromium do gerenciador nativo conhecido; em Debian/Ubuntu
e derivados apt, tenta também as dependências do Playwright. Outras distros
recebem apenas o browser, sem executar o instalador de dependências `apt`.
Depois, valida a combinação com um fixture HTML local. Se nenhum browser
funcionar, a instalação do runtime base continua sem ativar arquivos de browser
defeituosos; o crawler estático e os outros módulos seguem disponíveis, e
`raven doctor` reporta a capacidade headless. A documentação do Playwright lista
oficialmente Debian 12/13, Ubuntu 22.04/24.04/26.04, macOS 14+ e Windows 11+;
em outras distros/Unix o smoke test verifica a combinação disponível, sem
transformar plataformas não listadas em sistemas oficialmente suportados.
Android/Termux instala em modo estático e pula o browser headless.
Em Linux/Unix com `sudo`, o instalador tenta configurar o wrapper global
`sudo raven` ao final. O caminho de instalação fica em um arquivo lateral,
sem interpolar valores de diretório customizados em código shell.

Sem argumentos, `raven` abre o menu interativo — como o `nmap`, basta digitar
o comando e navegar pelos módulos. Para uso direto/scriptável, passe um
comando: `raven scanner <URL>`, `raven crawler <URL>`, `raven full <URL>`, etc.

O instalador mostra a distro/Termux, o nível root/sem-root e o gerenciador de
pacotes detectado. Ele detecta Termux por `PREFIX`; em outros Linux usa `~/.local/bin`.
Se necessário, ele informa o ajuste de `PATH` em vez de modificá-lo silenciosamente.
O instalador exige `sudo` no Linux quando precisa instalar bibliotecas do
sistema para os navegadores. A configuração do wrapper global continua sendo
automática quando `sudo` está disponível.

`./installer/install.sh --dry-run` mostra destinos, dependências e se tentaria
configurar o wrapper sem criar arquivos, instalar pacotes ou chamar `sudo`.
Sem `--dry-run`, o script instala o pacote completo e tenta configurar
`sudo raven` na mesma execução quando `sudo` existe e o ambiente não é Termux.
Os pacotes Python e os navegadores ficam na instalação do usuário; `sudo` é
usado para bibliotecas de sistema e, se habilitado, para copiar o wrapper a
`/usr/local/bin`.
Se esse passo falhar (por exemplo, sem senha de sudo disponível num
terminal não interativo), basta rodar o instalador de novo para tentar outra
vez; `raven` (sem sudo) já funciona normalmente enquanto isso. Uma falha do
browser não invalida o runtime: o modo estático permanece disponível.

Os comandos `scanner`, `crawler` e `full` funcionam sem root para alvos
explicitamente autorizados; use `sudo raven` apenas quando uma função
específica realmente exigir privilégio elevado.

Todas as dependências ficam embutidas no próprio `installer/install.sh` (sem
`requirements*.txt` para manter sincronizado) e são instaladas em `_vendor`
dentro da instalação — isso mantém `raven` e `sudo raven` no mesmo ambiente
sem exigir ativação de shell. O instalador sempre instala o conjunto completo;
falha ao obter dependências Python interrompe a atualização e preserva a versão
ativa. Falha no browser é reportada, mas mantém o runtime em modo estático.

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
e não são tocados; apague-os manualmente se quiser. O `--dry-run` lista os
arquivos que seriam removidos. O desinstalador recusa caminhos protegidos,
links simbólicos e destinos que não identifica como instalação RavenEye.

### venv (uso manual/desenvolvimento)

Sem o installer, é possível rodar a partir do próprio `pyproject.toml`
(backend `poetry-core`, sem precisar de `requirements.txt`):

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
python -m playwright install chromium
python3 RavenEye.py -h
python3 RavenEye.py
```

### Termux / Android

O instalador tenta instalar o runtime estático no Termux. Como o Playwright
não oferece suporte oficial ao driver/browser Android, ele prepara as
dependências de compilação do Termux e remove `uvloop` (incompatível com esse
ambiente) e pula a instalação headless. O modo crawler estático, scanner e
outros módulos dependem da compilação local das extensões Python; se ela falhar,
o instalador mostra a dependência que não pôde ser construída e preserva a
instalação anterior.

## Dependências

Não há mais `requirements*.txt`. `pyproject.toml` declara as dependências para
`pip install .`; o instalador autônomo mantém as listas `CORE_DEPS`,
`FULL_DEPS`, `PROTOCOL_DEPS` e `TEST_DEPS`, pois precisa funcionar sem Poetry.
Os testes de installer comparam os dois manifestos e falham se uma dependência
de runtime ou de desenvolvimento faltar no pacote completo. O mesmo contrato
exige que `doctor` conheça o módulo importável correspondente a cada pacote de
runtime (por exemplo, `Pillow` → `PIL`). Assim, uma dependência nova precisa ser
declarada, instalada, verificada e diagnosticada antes de entrar no projeto.

## API / integrações
- Shodan: https://developer.shodan.io/api
- VirusTotal: https://docs.virustotal.com/reference/overview
- Google Programmable Search / Custom Search JSON API: https://developers.google.com/custom-search/v1/overview
- Censys Platform API: https://docs.censys.com/reference/get-started
- Netlas API: https://docs.netlas.io/api-reference/
- LeakIX API client: https://github.com/LeakIX/LeakIXClient-Python
- Censys Platform v3, Netlas e LeakIX: enriquecimento passivo é executado somente quando a chave correspondente está configurada. `CENSYS_ORGANIZATION_ID` é opcional para a consulta de host e pode ser definido quando fornecido pela conta.
- NVD: https://nvd.nist.gov/developers/vulnerabilities
- crt.sh: https://crt.sh/
- Internet Archive CDX: https://github.com/internetarchive/wayback/tree/master/webservices
- Exploit-DB/SearchSploit: https://www.exploit-db.com/

Configure `CENSYS_API_KEY` with a Censys Personal Access Token and, optionally,
`CENSYS_ORGANIZATION_ID` with the organization ID supplied by the account;
Netlas and LeakIX use `NETLAS_API_KEY` and `LEAKIX_API_KEY`. Provider calls run
only for configured keys. Reports retain compact asset metadata and explicit
provider status, never raw banners, leak bodies, or credentials.
The CLI loads the nearest `.env` from its working directory or a parent folder;
already exported environment variables take precedence.

## Scanner de vulnerabilidades
O scanner é um módulo independente do crawler e do NUKE/C4. Ele usa evidência, baseline, confidence e deduplicação. Indícios não confirmados permanecem como candidatos e não são apresentados como exploração comprovada.

Antes de cada execução, a interface pede confirmação explícita para o Scanner;
recusar cancela a operação antes das requisições. Em um NUKE/C4 com Scanner, há
uma confirmação específica para essa etapa. Sem `--scope`, o alvo informado
define o limite do scanner; escopos adicionais precisam ser configurados
explicitamente.

### Correlação local de CVEs

O scanner correlaciona CVEs apenas quando identifica a tecnologia e a versão exata
na resposta e há correspondência em uma base local. Isso evita inferir que uma
versão "próxima" é vulnerável. Configure `RAVENEYE_CVE_RECORDS_PATH` com um JSON
normalizado (`product`, `version`, `cve`) ou uma exportação JSON do NVD; o RavenEye
não baixa feeds nem executa exploits automaticamente.

## Banco
O SQLite é inicializado automaticamente. Ele armazena cache, fingerprints, CVEs, scans e findings. Chaves API configuradas pelo menu são ofuscadas em Base64 no arquivo JSON, não criptografadas; prefira variáveis de ambiente e proteja o arquivo de configuração.

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
raven crawler https://alvo-autorizado.example -p 100 -n -s   # legado, páginas, Nmap e Shodan
raven crawler https://alvo-autorizado.example --engine async -p 100  # JSONL streaming
raven crawler https://alvo-autorizado.example --engine async --headless # SPA + XHR/fetch sob escopo
raven full https://alvo-autorizado.example -o saida          # fluxo completo
raven report -f pdf -o relatorio
raven database -i
raven logs -w raveneye.log
raven doctor -j
```

Use `raven <comando> -h` para a referência completa de cada módulo. `--engine async` ativa o crawler assíncrono com fila limitada, escopo restrito ao host inicial por padrão e saída JSONL versionada; `--engine legacy` mantém os relatórios, proxy e enriquecimentos atuais e segue como padrão até passar pelos gates de equivalência. Os nomes
longos (`--pages`, `--nmap`, `--shodan`, `--output` etc.) continuam aceitos. O modo `--headless` é opcional e só se aplica ao engine assíncrono; é desativado por padrão, limita cada origem, permite apenas GET/HEAD no browser, não submete formulários e não encaminha mensagens WebSocket. Como alguns sites implementam ações com GET, execute-o apenas contra alvos autorizados; o crawler não clica em controles nem segue links sem descobri-los e checá-los contra o escopo.

Sem o installer (execução manual em venv), o mesmo CLI é acessado via
`python3 RavenEye.py [comando] [opções]` — é o mesmo programa; `raven` é só o
wrapper instalado que já resolve o ambiente/dependências.

Ciclo de manutenção: **verificar → forçar em ambiente controlado → encontrar erro → corrigir → testar novamente → aumentar a segurança**.

## Diagnóstico local

Use o comando `doctor` para verificar o ambiente sem fazer requisições de rede:

```bash
raven doctor
raven doctor --json
```

Ele verifica Python, dependências de runtime, permissões locais e se o Chromium
headless consegue iniciar. O headless é opcional para o modo estático; se
`headless_rendering` estiver ativado, sua ausência torna o diagnóstico incompleto.
Firefox e WebKit aparecem como engines opcionais.

## Exportação de relatórios

O RavenEye 6.6.6 suporta relatórios TXT, JSON, HTML, Markdown, CSV e **PDF**. O PDF é gerado localmente, sem CDN ou serviço externo, com uma identidade visual de túnel VPN em azul-marinho e ciano. O resumo separa findings `CONFIRMED`, `PROBABLE` e `POSSIBLE`, e pode incluir as respostas filtradas do SearXNG e o estado das integrações de API. Imagens locais já anexadas ao resultado também podem ser incorporadas.

Cada execução integrada gera `<base>_events.jsonl`, um log estruturado versionado com métricas do crawler, URLs de JavaScript e endpoints com valores de query removidos, estado de APIs, respostas automatizadas em escopo e findings classificados. Correspondências antigas por nome de caminho aparecem como indícios não verificados, fora da contagem de vulnerabilidades. Padrões de segredo em JavaScript registram tipo e arquivo; o valor detectado é ocultado em TXT, CSV, JSON e PDF. O arquivo é escrito atomicamente antes dos exportadores e recebe permissão privada quando o sistema oferece modos POSIX. Consultas de dorks, corpos de resposta e credenciais não são gravados; evidências do scanner ficam limitadas a hashes e metadados HTTP. O arquivo fica disponível no Leitor de Logs em “Eventos do scan — JSONL”. Veja [docs/scan-event-log-v1.md](docs/scan-event-log-v1.md).

O comparador local do crawler mede cobertura, velocidade, memória, repetição de requisições e endpoints JavaScript contra Katana em uma fixture isolada: [método, baseline e limitações](docs/katana-comparison.md).

No Leitor de Logs, `export` informa os formatos disponíveis: **CSV | JSONL | PDF**. Exemplo: `export <arquivo> <categoria> <saida.pdf>`.

Dependências PDF: `reportlab` e `Pillow` — instaladas como parte obrigatória do runtime completo.

## Exportação do Leitor de Logs

Ao digitar `export` no leitor de logs, o RavenEye apresenta os formatos disponíveis:

- CSV (`.csv`)
- JSONL (`.jsonl`)
- PDF (`.pdf`)

O PDF é validado após a geração e a extensão correta é adicionada automaticamente quando o nome de saída não possui extensão.


## Compatibilidade Android

Android/Termux não está entre os sistemas oficialmente suportados pelo
Playwright Python. O instalador pula o browser e tenta preparar o runtime base;
em Linux/Unix sem browser compatível, o modo estático também continua disponível.

Para diagnosticar localmente sem depender da rede, use `raven doctor --json`.
O instalador termina com erro se não puder instalar o runtime Python. Se o
Chromium headless não iniciar, ele informa a limitação e mantém o modo estático.

## Linux com pacman (Archcraft/Arch Linux)

Em distribuições Arch, o instalador instala o Chromium com `pacman` (que resolve
suas dependências nativas), sem usar o fallback `apt-get` do Playwright. O crawler
aponta Playwright para o Chromium nativo; assim evita os ABIs Ubuntu exigidos
por Firefox/WebKit, engines que RavenEye não usa. Se o lançamento falhar, o
instalador mostra o diagnóstico local e mantém o crawler estático disponível.

## Verificação local do runtime

Rode `python3 scripts/termux_smoke.py` para conferir dependências e capacidades.
O comando faz apenas checagens locais e não realiza requisições de rede.

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
docs/katana-comparison.md  # baseline reproduzível contra Katana
MIGRATION.md                 # guia de migração
README.md                    # documentação principal
pyproject.toml               # metadados/deps para `pip install .` e config de testes
```

O diretório `reports/PDF/` é criado/preservado para acesso rápido aos PDFs gerados; nenhum PDF de runtime é empacotado no release.
