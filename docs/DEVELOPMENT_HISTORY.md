# RavenEye 6.6.6 — Histórico de desenvolvimento e auditoria

Registro consolidado das revisões, correções e ciclos de QA.

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


Cross-cutting hardening pass.

- Log `watch` now detects truncation and inode rotation instead of silently stopping at the old offset.
- Log `watch` rejects non-positive polling intervals.
- Log `delete` rejects directories and symlinks, requires exact `SIM`, and uses collision-resistant UTC timestamps.
- Release hygiene is verified after test execution so generated caches are not shipped.
- PDF export remains extension-safe and validates the `%PDF` signature after generation.

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
