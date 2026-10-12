# RavenEye 6.6.6 — Histórico de desenvolvimento e auditoria

Registro consolidado das revisões, correções e ciclos de QA.

## Empacotamento seguro de configurações locais (2026-10-12)

- O construtor da distribuição agora exclui `raven_eye_config.json` junto com `.env`; esses arquivos pertencem ao runtime local e não devem acompanhar o ZIP.
- `.gitignore` também protege ambos os arquivos contra inclusão acidental no controle de versão.
- A verificação de layout do release confirma que configuração local e `.env` ficam fora do ZIP.

## Continuidade da atualização — robustez do catálogo de wordlists (2026-10-12)

- A versão anexada pelo usuário não continha as opções de enumeração/configuração de wordlists de subdomínio; o pacote de atualização agora expõe ambas no menu interativo.
- Se o manifesto de listas importadas estiver corrompido, o seletor continua mostrando apenas as listas embutidas verificadas e informa a limitação. Listas importadas continuam bloqueadas até a integridade do catálogo ser recuperada.
- A importação valida o manifesto antes de gravar dados e não deixa arquivos órfãos quando o catálogo está inválido.
- Verificações de regressão exercitam menus, seleção do padrão embutido e falha forçada de manifesto corrompido.

## Notas consolidadas de implementação

This document describes the modular architecture and migration decisions. It is documentation, not a scan report.

- Version remains 6.6.6.
- Scanner findings are stored separately from crawler/recon artifacts.
- Reports contain findings and evidence, never source code or implementation notes.
- NUKE/C4 is an orchestration mode; vulnerability scanning remains a distinct module.

---

## Auditoria incremental

## Auditoria e melhoria incremental

## Correção principal

As opções 4, 5 e 6 do menu de enumeração HTTP do módulo Bruteforce estavam referenciando `enumerate_paths`, `enumerate_endpoints` e `enumerate_parameters` sem importá-las em `raveneye_pkg/menus.py`.

A correção também identificou uma segunda falha latente: o módulo de menu usava `_sleep` sem importá-lo.

## Regressão coberta

Foi adicionada uma suíte específica para:

- verificar que as três funções estão ligadas ao menu;
- executar a enumeração de endpoints com transporte simulado;
- executar a enumeração de parâmetros com transporte simulado;
- garantir que essas rotas não dependem de autenticação.

## Auditoria adicional

A etapa também repetiu:

1. compilação de todos os módulos;
2. suíte completa de testes;
3. verificação da CLI de bootstrap;
4. procura por `eval`, `exec`, `pickle`, `shell=True` e `os.system` no código principal;
5. limpeza de caches Python antes do empacotamento.

## Regra de manutenção

`verificar → forçar em ambiente controlado → encontrar erro → corrigir → testar novamente → aumentar a segurança → repetir`

---

## Auditoria incremental


## Ciclo
Verificar → Forçar → Encontrar erro → Corrigir → Testar → Aumentar a segurança → repetir.

## Alterações
- Unificada a compatibilidade de ambiente entre `requirements.txt` e `pyproject.toml` para Python 3.10+.
- Adicionadas dependências declaradas ausentes: SQLAlchemy e pydantic-settings.
- Adicionado `requirements-termux.txt` como perfil explícito de instalação core.
- Adicionado `RavenEye.py doctor` para diagnóstico local sem rede.
- `AsyncHttpClient` agora aceita subdomínios reais do escopo sem aceitar colisões de sufixo.
- Mantidos limites de timeout, escopo e SSRF.

## Validação
- pytest: passou.
- py_compile: passou.
- `python3 RavenEye.py -h`: passou.
- busca por construções proibidas no código principal: sem ocorrências novas.

---

## Auditoria incremental


- Adicionado gerador PDF local em `raveneye/reports/pdf.py`.
- Paleta visual: preto, roxo e vermelho.
- Capa, resumo executivo, tabela de severidade, risk score, findings, anexos e evidências visuais.
- Imagens locais de screenshots/evidências são incorporadas quando presentes no resultado do scan.
- `save_all_reports()` agora gera PDF junto aos demais formatos.
- CLI `scan --report pdf` disponível.
- Leitor de Logs: `export` agora aceita CSV, JSONL e PDF e informa os formatos disponíveis quando o comando é digitado sem argumentos.
- Dependências `reportlab` e `Pillow` adicionadas ao runtime.
- Testes de geração PDF, exportação PDF de logs e incorporação de imagem local adicionados.

Validação: suíte completa aprovada após a implementação.

---



## Problema corrigido
A exportação do leitor de logs podia aceitar um nome de saída sem extensão e inferir o formato de forma implícita. Isso permitia que o usuário criasse um arquivo sem `.pdf` ou, em cenários de uso incorreto, um arquivo vazio/sem o tipo esperado.

## Correção
- O exportador aceita somente CSV, JSONL e PDF.
- O formato pode ser informado explicitamente (`fmt="pdf"`).
- Se o nome não tiver extensão, a extensão correta é adicionada automaticamente.
- Se a extensão não corresponder ao formato explicitamente selecionado, ela é substituída pela extensão correta.
- PDF é validado após a geração: arquivo existente, tamanho > 0 e assinatura `%PDF`.
- O comando `export` agora apresenta uma lista explícita de formatos.
- Testes de regressão cobrem PDF sem extensão e extensão incompatível.

## Regra do looping
Verificar → Forçar → Encontrar erro → Corrigir → Testar → Aumentar segurança → repetir.

---

## Auditoria incremental

### Formulários HTTP do módulo de autenticação

- O formulário que contém os campos de usuário e senha configurados agora
  determina a ação POST, desde que permaneça na origem explicitamente aprovada.
- O token CSRF é lido desse formulário, sem misturar campos de busca ou logout.
- Formulários GET e ações em outra origem são bloqueados antes do envio de
  credenciais. Respostas de erro podem fornecer a próxima ação/token CSRF.
- Fixtures forçaram e cobriram ações relativas, formulário CSRF irrelevante,
  método incorreto e ação externa. A primeira rodada encontrou um `NameError`
  por import ausente de `urljoin`; correção aplicada e 19 testes focados passaram.
- Comparador Hydra ampliado com casos positivos/negativos de token CSRF de uso
  único. A integração RavenEye passou no fixture HTTP local; a comparação Hydra
  dessa nova modalidade aguarda reconstruir o binário temporário.


Cross-cutting hardening pass.

- Log `watch` now detects truncation and inode rotation instead of silently stopping at the old offset.
- Log `watch` rejects non-positive polling intervals.
- Log `delete` rejects directories and symlinks, requires exact `SIM`, and uses collision-resistant UTC timestamps.
- Release hygiene is verified after test execution so generated caches are not shipped.
- PDF export remains extension-safe and validates the `%PDF` signature after generation.

## Crawler scope boundary correction

- Forced the path-scope boundary case: `/api` previously accepted `/apiary` in
  both `Scope` and `ScopeGuard` because they used raw string-prefix matching.
- Added shared slash-segment matching. Exact paths and descendants remain
  included; sibling names are rejected consistently by crawler, renderer, and
  request guard.
- Regression fixtures cover `/api`, `/api/`, `/api/v1/items`, `/apiary`,
  `/api-v2`, and `/apix/child`.
- Frontier normalization previously sorted query keys, potentially merging
  application routes whose query order or repeated-key order is significant.
  Query strings are now retained verbatim while safe authority normalization
  and fragment removal remain. Fixtures force both reordered and repeated-key
  variants through deduplication.
- `doctor` previously treated any Playwright version directory as an installed
  browser. It now asks the installed Playwright runtime for each expected
  executable path and requires an executable file, so interrupted downloads
  cannot produce a false `OK`. A fixture covers valid executables and an absent
  browser binary alongside leftover version directories.
- API enrichment previously converted HTTP 204 into an empty summary while
  labeling it HTTP 200. It now reports `no_content` with the real status and
  omits fabricated metadata; a provider-response fixture covers this path.

---



## Verification
- Full pytest suite executed before packaging.
- Release archive is built by `scripts/build_release.py`.
- Runtime SQLite databases are excluded from releases.
- Python bytecode and test/cache directories are excluded.

## Finding
auditoria anterior still contained `data/raveneye.db` despite the release manifest stating that runtime databases were excluded.

## Fix
The runtime database was removed from the source snapshot and the release builder now enforces exclusion of runtime/cache artifacts. A regression test was added.

## Rule
Verify -> Force -> Find -> Fix -> Test -> Harden -> Clean -> Package -> Verify again.

---

## Auditoria incremental


- XML-aware crawler parsing for sitemap/RSS/Atom documents.
- Termux core requirements split from native-heavy optional requirements.
- Minimal config fallback when Pydantic is absent.
- YAML template loading is optional in the minimal profile.
- Poetry Python constraint aligned to Python 3.14 compatibility target.

---


## Auditoria e melhoria incremental

## Auditoria geral

Ciclo aplicado: verificar → forçar em ambiente controlado → encontrar falha → corrigir → testar → endurecer → empacotar → validar o artefato.

### Correções desta etapa

- `RavenEye.py doctor` pode executar no bootstrap antes das dependências da camada legada (ex.: `colorama`).
- Parser de sitemap/XML mantém processamento XML sem `XMLParsedAsHTMLWarning`.
- `AsyncSession` ganhou resolver DNS pinado, atualizado por hostname após validação SSRF, reduzindo risco de DNS rebinding entre validação e conexão.
- Compatibilidade da sessão: referência fechada permanece disponível para inspeção via `.closed`.
- CLI `scan --report` agora oferece TXT, JSON, HTML, CSV, Markdown e PDF.
- Regressões de exportação e release hygiene ganharam cobertura automatizada.
- Release builder continua excluindo banco runtime, caches e bytecode.

### Verificações

- Suíte pytest: PASS.
- `compileall`: PASS.
- CLI bootstrap `-h`: PASS.
- `doctor --json`: executável e retorna status de dependências.
- Ajuda dos subcomandos: PASS.
- PDF de exemplo: assinatura `%PDF` válida.
- Relatório de exemplo: sem código-fonte ou texto do prompt.
- ZIP final: íntegro e sem `raveneye.db`, `__pycache__`, `.pytest_cache`, `.pyc` ou `.pyo`.

### Observação sobre Termux

O perfil `requirements-termux.txt` permanece deliberadamente leve e evita dependências nativas/Rust pesadas. Recursos como PDF/Pydantic/XML parser C são opcionais no perfil `requirements-termux-extras.txt` e devem ser instalados somente quando existir pacote/wheel compatível no ambiente Termux específico.

---

## Auditoria incremental

## Auditoria e melhoria incremental

## Objetivo
Auditoria transversal da auditoria transversal: estrutura de release, compatibilidade legada, CLI, Termux, módulos async, relatórios e higiene do artefato.

## Resultado
- O projeto é empacotado na raiz do ZIP; não há diretório wrapper `diretório wrapper anterior`.
- `raveneye/` é a arquitetura nova; `raveneye_pkg/` permanece como camada legada para backward compatibility.
- Dependências síncronas encontradas em `raveneye_pkg/` são tratadas como legado e não são declaradas como parte da camada async nova.
- O perfil Termux core mantém `requests` por compatibilidade com o legado; dependências nativas/Rust pesadas permanecem no perfil opcional.
- A suíte existente foi executada antes do empacotamento.
- O artefato final é validado depois da limpeza de caches/bytecode.

## Regra de release
O conteúdo do projeto deve aparecer diretamente na raiz do ZIP, com `RavenEye.py`, `pyproject.toml`, `installer/`, `raveneye/`, `raveneye_pkg/` e `tests/` no primeiro nível.

## Observação
A remoção da camada `raveneye_pkg/` não é feita nesta etapa porque quebraria funcionalidades legadas. A migração deve ocorrer módulo por módulo, com testes de regressão.

---

## Auditoria incremental

## Auditoria e melhoria incremental

## Auditoria transversal
- Corrigido o release builder para colocar o projeto diretamente na raiz do ZIP.
- Removido uso desnecessário de `__import__` no banco legado; `hashlib` é importado explicitamente.
- Atualizado RELEASE_MANIFEST para refletir a auditoria de release.
- Adicionado teste de regressão do layout do ZIP e da higiene do artefato.
- Mantida a camada `raveneye_pkg/` por backward compatibility; migração segue módulo a módulo.

## Loop
Verificar -> Forçar -> Encontrar falha -> Corrigir -> Testar -> Endurecer -> Empacotar -> Validar artefato -> repetir.

---

## AUDIT AUDITORIA DE CAPACIDADES

## Auditoria e melhoria incremental

## Loop

Verificar → Forçar → Encontrar falha → Corrigir → Testar → Endurecer → repetir.

## Achado desta rodada

A auditoria estrutural encontrou adaptadores de protocolo no módulo de bruteforce
que eram apenas `NotImplementedError`, embora a árvore do projeto pudesse fazê-los
parecer implementações completas.

Nesta stage eles passam a declarar explicitamente a capacidade como indisponível,
em vez de fingir que existe uma implementação funcional. Isso evita falsos
positivos de capacidade e falhas silenciosas no menu.

Não foi adicionada lógica de tentativa de credenciais ou de evasão. Recursos de
segurança ofensiva devem permanecer sujeitos a autorização e controles de escopo.

## Verificações

- suíte pytest: executada após a correção
- compileall: executado
- release hygiene: executado no ZIP final
- código novo: sem eval/exec/pickle/shell=True/os.system
- módulos novos de rede: sem requests/threading

---

## AUDIT AUDITORIA DE ESCOPO

## Auditoria e melhoria incremental

## Loop executed
Verify → Force → Find failure → Fix → Retest → Harden → package → inspect final artifact.

## Findings fixed
- Scanner scope exclusions now consume `ScopeConfig.exclude`; the previous `exclude_patterns` lookup could silently skip configured exclusions.
- ScopeGuard path exclusions now support glob patterns such as `/private*` while keeping explicit domain wildcards.
- Passive cookie analysis can inspect multiple `Set-Cookie` values when the response mapping provides `getall()`.
- Added malformed-input stress checks for passive scanner parsing and bounded URL parameter extraction.
- Termux instructions in README now consistently point to `requirements-termux.txt` for the core profile.
- Release manifest synchronized to auditoria de escopo.

## Validation
- Full pytest suite: PASS.
- compileall: PASS.
- Release ZIP integrity: PASS.
- Runtime database / bytecode / cache artifacts in ZIP: none.

## Limpeza de instalador e branding TandaiSec

- Selo de créditos trocado de ROKUHARASEC para o logo TandaiSec (ASCII), com
  checagem de integridade (`raveneye_pkg/credits.py`) chamada na inicialização
  de `main()` e a cada iteração do menu principal.
- Removido `raveneye.py` (shim de uma linha que só encaminhava para
  `RavenEye.py`); `RavenEye.py` continua sendo o launcher canônico e não foi
  alterado em comportamento — apenas o texto de ajuda (`prog`, exemplos,
  mensagens de erro) foi atualizado de `python3 RavenEye.py` para `raven`.
  Nenhum subcomando, alias, flag ou lógica de despacho foi removido/alterado.
- Removidos `requirements.txt`, `requirements-extras.txt`,
  `requirements-termux.txt`, `requirements-termux-extras.txt` e
  `RELEASE_MANIFEST.txt`. As listas de dependências agora vivem só em
  `installer/install.sh` (`CORE_DEPS`, `FULL_DEPS`, `PROTOCOL_DEPS`,
  `TEST_DEPS`), com o mesmo split que existia entre os quatro arquivos.
  `pyproject.toml` segue como manifesto para quem instala via `pip install .`.
- `installer/install.sh` ganhou `--with-extras` (grupo PROTOCOLS + FULL no
  Termux) e `-h/--help`; removida a criação do symlink `RavenEye` no bin dir
  (agora só existe o comando `raven`, no estilo nmap: um único binário).
- Novo `installer/uninstall.sh`, simétrico ao installer (modo usuário,
  `--system-wrapper`, `--all`, `-y`).
- Removido `scripts/bootstrap_termux.sh` (script órfão, não referenciado por
  nada, que duplicava — de forma desatualizada e via venv — o que
  `installer/install.sh` já faz melhor e sem venv para o Termux).
- Testes atualizados para a nova estrutura: `test_release_layout.py`,
  `test_regression_baseline.py`, `test_termux_compatibility.py` e
  `test_core.py` (ver `tests/`); nenhum teste foi removido, apenas repontado
  para os novos arquivos/local das mesmas garantias.

## Correção: sudo raven e pacote completo por padrão

- `sudo raven` falhava com "comando não encontrado" logo após uma instalação
  nova, porque o wrapper global (`/usr/local/bin/raven`) exigia um segundo
  comando manual (`--system-wrapper`) que não era executado automaticamente.
  Corrigido: `installer/install.sh`, por padrão, encadeia um `sudo` ao final
  da própria execução para configurar esse wrapper — uma única chamada de
  `./installer/install.sh` deixa `raven` e `sudo raven` funcionando. Pode ser
  pulado com `--no-sudo-wrapper`; no Termux (sem `sudo`) é pulado sozinho.
- Removido o modelo opt-in `--with-extras`: o instalador agora traz o pacote
  completo (CORE + FULL + PROTOCOLS + TEST) por padrão, em qualquer
  plataforma, incluindo Termux. `--with-extras` continua aceito como no-op
  (não quebra scripts antigos). Quem precisar de uma instalação reduzida por
  limitação real de compilação nativa usa `--minimal` (opt-out explícito, não
  o padrão).

## Correção: permissão de root no installer/uninstaller e simplificação do install.sh

- Corrigido bug de permissão no reparo `--system-wrapper` (existente até
  então): o arquivo temporário de requirements era criado por root (modo
  `600`) e lido pelo usuário original via `runuser`/`su`, gerando
  "Permission denied" silencioso e quebrando o encadeamento automático de
  `sudo raven`.
- Corrigido `installer/uninstall.sh`: sob `sudo`, `$HOME` é resetado para o
  home de root por padrão, então `remove_user_install()` procurava em
  `/root/.local` em vez do home real de quem instalou, reportando "nenhuma
  instalação encontrada" sem remover nada. Agora resolve o home real via
  `SUDO_USER` + `getent passwd`, igual ao que o instalador já fazia.
- `installer/install.sh` foi simplificado para uma execução única, sem
  modos/flags: removidos `--minimal`, `--no-sudo-wrapper`, `--system-wrapper`
  e `--with-extras` (este último já era no-op). Agora `./installer/install.sh`
  sem argumentos sempre instala o pacote completo (CORE + FULL + PROTOCOLS +
  TEST) em modo usuário e, na mesma execução, configura `sudo raven`
  automaticamente sempre que `sudo` existir e não for Termux — sem exigir uma
  segunda chamada manual com flag. Como as dependências já foram instaladas
  como o usuário atual antes dessa etapa, o passo com `sudo` só copia o
  wrapper para `/usr/local/bin`; nenhum comando privilegiado roda `pip`, o
  que também elimina a classe de bug de permissão descrita acima. Mensagens
internas (`raveneye_pkg/menus.py`) e testes (`tests/compatibility/test_sudo_wrapper.py`)
atualizados para não referenciar mais `--system-wrapper` como algo que o
usuário precisa rodar manualmente. `README.md` atualizado de acordo.

## Auditoria contínua — CSRF e formulários

- A auditoria HTTP escolhe o formulário que contém os campos configurados,
  resolve a ação relativa na origem aprovada e envia somente os tokens CSRF
  daquele formulário. Ação externa e método GET são bloqueados antes do POST.
- A regressão forçada encontrou `urljoin` sem import; correção aplicada. Fixtures
  cobrem ação relativa, token de formulário não relacionado, formulário GET e
  ação cross-origin. Uma fixture HTTP efêmera em loopback também passou com CSRF
  de uso único rotativo.
- O scanner de CSRF reconhece `_token`, `__RequestVerificationToken` e meta
  tokens preenchidos. Ausência de marcador caiu para `BAIXO` / `LOW` / `POSSIBLE`,
  pois não prova ausência de outras defesas.
- 93 testes focados do scanner passaram. O comparador Hydra ganhou casos
  positivos e negativos com token rotativo, mas ainda requer reconstrução do
  binário temporário para publicar métricas desses casos.
- O crawler JavaScript deixou de procurar rotas com regex sobre o texto bruto:
  agora classifica literais do tokenizador e ignora expressões regulares,
  evitando tratar exemplos dentro de strings, comentários e padrões como
  chamadas reais. Regressão coberta com exemplos de `fetch`, URLs e WebSockets.

## Compatibilidade Termux — estado atual

Embora etapas antigas tenham registrado instalação completa no Termux, o estado
atual do instalador recusa essa plataforma porque o runtime exige Chromium,
Firefox e WebKit funcionais. O Playwright lista Windows, macOS e Linux Debian/
Ubuntu entre os sistemas suportados; Android/Termux não aparece nessa lista.
Proot-Distro oferece um userland Linux no Android, mas não oferece isolamento de
namespace/seccomp; RavenEye exige o sandbox do Chromium. Não removemos essa
proteção nem registramos suporte Termux sem uma validação real de todos os
navegadores com sandbox habilitado.

## Crawler — redirecionamentos de robots.txt

- A revisão contra a seção 2.3.1.2 do RFC 9309 encontrou que o crawler tratava
  qualquer resposta 3xx de `robots.txt` como bloqueio permanente do host.
  Agora segue até cinco redirecionamentos manualmente, mantendo as regras
  associadas à autoridade original, como exige o RFC.
- Cada salto precisa continuar dentro do escopo atual e passa pela validação
  SSRF/DNS do cliente HTTP. Redirecionamento externo, fora do escopo de caminho
  ou acima do limite mantém o bloqueio seguro e registra a razão sem requisitar
  o destino recusado.
- Fixtures locais verificam redirecionamento permitido, destino fora do escopo
  e limite de cinco saltos. `tests/crawler/test_robots_sitemap_jsonl.py` e
  `tests/crawler/test_js_module_crawl.py` passaram.

## Crawler — captura de JavaScript inline e rotas dinâmicas

- A auditoria do parser encontrou que a extração do HTML procurava `fetch()`
  por regex no documento inteiro e não aplicava o tokenizador mais preciso ao
  JavaScript inline. Agora scripts inline executáveis passam pelo mesmo parser
  limitado a 1 MB e até 256 resultados por bloco; blocos JSON e scripts dentro
  de `<template>` ficam fora da análise.
- Literais dinâmicos em `fetch`, axios, XHR e campos de URL geram
  `js_route_templates`, com placeholders e apenas o caminho. Eles não entram
  na fila do crawler, não são enviados ao alvo e não conservam query strings.
  Assim se recupera evidência de rotas como `/api/users/{param}` sem inventar
  valores de parâmetros nem causar requisições com placeholders.
- A auditoria do caminho padrão encontrou que o menu ainda executa o crawler
  legado. A captura de templates agora também é acumulada nesse fluxo e aparece
  nos eventos JSONL e no anexo do PDF. Source maps analisam `sourcesContent`
  para rotas e imports literais, sem tratá-los como texto HTML nem enviar
  templates ao alvo.
- As fixtures forçam exemplos falsos dentro de strings, script JSON,
  `<template>`, query com valores, bundle externo e source map. Apenas os
  templates executáveis aparecem no campo próprio e nenhum URL com placeholder
  é requisitado.
