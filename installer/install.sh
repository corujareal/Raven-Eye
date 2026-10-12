#!/usr/bin/env sh
# RavenEye — instalador único. Uma execução faz tudo:
#   1) instala o pacote COMPLETO e tenta preparar Chromium headless,
#      nativo da distro quando disponível ou fornecido pelo Playwright;
#   2) cria o comando 'raven';
#   3) configura automaticamente o wrapper global em /usr/local/bin/raven,
#      para que 'sudo raven' já funcione ao final da mesma execução (pode
#      pedir sua senha de sudo uma vez). Termux instala o runtime estático;
#      Termux mantém o runtime sem headless, que não é suportado pelo Playwright.
#
# Todas as dependências ficam embutidas neste script: não há
# requirements*.txt separado para manter em sincronia.
set -eu

# ==================================================================
# DEPENDÊNCIAS EMBUTIDAS
# ==================================================================
# BASE: runtime obrigatorio em todas as instalacoes suportadas.
CORE_DEPS='
beautifulsoup4>=4.12,<5
colorama>=0.4.6,<1
aiohttp>=3.10,<4
httpx>=0.27,<1
aiosqlite>=0.20,<1
rich>=13.7,<15
click>=8.1,<9
python-dotenv>=1.0,<2
dnspython>=2.6,<3
python-whois>=0.9,<1
PyJWT>=2.8,<3
jsbeautifier>=1.15,<2
tqdm>=4.66,<5
requests[socks]>=2.32,<3
PySocks>=1.7,<2
shodan>=1.31,<2
'

# FULL: recursos (parsing XML rápido,
# validação de config, ORM do banco, geração de PDF).
FULL_DEPS='
lxml>=5.2,<7
PyYAML>=6.0,<7
pydantic>=2.7,<3
pydantic-settings>=2.2,<3
SQLAlchemy>=2.0,<3
reportlab>=4.0,<5
Pillow>=10,<13
'

# PROTOCOLS: adaptadores de protocolo, navegadores Playwright e loop
# de eventos de performance.
PROTOCOL_DEPS="
uvloop>=0.19,<1; sys_platform == 'linux'
playwright>=1.48,<2
asyncssh>=2.14,<3
aioftp>=0.23,<1
aiosmtplib>=3.0,<4
motor>=3.5,<4
asyncpg>=0.29,<1
aiomysql>=0.2,<1
smbprotocol>=1.14,<2
"

# TEST: tooling de desenvolvimento/teste instalado junto com o pacote.
TEST_DEPS='
pytest>=8,<9
pytest-asyncio>=0.23,<2
coverage>=7,<8
testcontainers>=4,<5
'

usage() {
  cat <<'EOF'
Uso: sh installer/install.sh [--dry-run] [-h]

Sem opções: instala o pacote COMPLETO (core + full + protocolos) em modo
usuário (~/.local) e, na mesma execução, configura automaticamente
'sudo raven' (pode pedir sua senha de sudo uma vez). O headless é opcional:
em Termux e outros Unix, o runtime estático pode ser instalado quando o
driver/browser Playwright não for compatível. Em Linux, tenta Chromium nativo
com o gerenciador detectado e valida renderização local quando disponível.

Variáveis de ambiente:
  RAVENEYE_BIN_DIR, RAVENEYE_LIB_DIR, RAVENEYE_SYSTEM_BIN_DIR
                                        Sobrescrevem os diretórios de destino.
  PYTHON                                Interpretador a usar (padrão: python3).

Opções:
  --dry-run                              Mostra ambiente e ações sem alterar arquivos,
                                        instalar pacotes ou chamar sudo.
  -h, --help                             Mostra esta ajuda.

Depois de instalado: raven --help  /  sudo raven --help
Para desinstalar:     sh installer/uninstall.sh
EOF
}

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Opção desconhecida: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_PATH=$0
case "$SCRIPT_PATH" in -*) SCRIPT_PATH=./$SCRIPT_PATH ;; esac
SCRIPT_DIR=$(CDPATH= cd -P "$(dirname "$SCRIPT_PATH")" 2>/dev/null && pwd -P) || {
  echo "Não foi possível localizar a pasta do instalador." >&2
  exit 1
}
ROOT=$(CDPATH= cd -P "$SCRIPT_DIR/.." 2>/dev/null && pwd -P) || {
  echo "Não foi possível localizar a raiz do RavenEye." >&2
  exit 1
}

# Monta um arquivo de requirements temporário a partir das listas embutidas
# acima (CORE+FULL+PROTOCOLS+TEST — sempre o pacote completo). pip -r
# continua sendo o mecanismo real de instalação; só a origem do texto mudou.
build_requirements_file() {
  out=$(mktemp "${TMPDIR:-/tmp}/raveneye-deps.XXXXXX")
  printf '%s\n' "$CORE_DEPS" >>"$out"
  printf '%s\n' "$FULL_DEPS" >>"$out"
  if is_termux_env; then
    # uvloop is Linux-only and cannot be built for Android's Bionic libc.
    printf '%s\n' "$PROTOCOL_DEPS" | sed '/^uvloop[><=~]/d' >>"$out"
  else
    printf '%s\n' "$PROTOCOL_DEPS" >>"$out"
  fi
  printf '%s\n' "$TEST_DEPS" >>"$out"
  printf '%s' "$out"
}

is_termux_env() {
  case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac
}

is_debian_apt_env() {
  [ "$(uname -s 2>/dev/null || true)" = "Linux" ] || return 1
  # Arch derivatives (including Archcraft) can carry compatibility metadata
  # or helper tools that resemble Debian. Never let Playwright call apt-get
  # when the package manager selected for this host is pacman.
  [ "$PACKAGE_MANAGER" != "pacman" ] || return 1
  case " ${DISTRO_ID:-} ${DISTRO_LIKE:-} " in
    *" arch "*) return 1 ;;
    *" debian "*|*" ubuntu "*)
      [ "$PACKAGE_MANAGER" = "apt-get" ] || [ "$PACKAGE_MANAGER" = "apt" ]
      ;;
    *) return 1 ;;
  esac
}

read_os_release_field() {
  field=$1
  release_file=${RAVENEYE_OS_RELEASE_FILE:-/etc/os-release}
  [ -r "$release_file" ] || release_file=/usr/lib/os-release
  [ -r "$release_file" ] || return 0
  value=$(sed -n "s/^${field}=//p" "$release_file" | head -n 1)
  value=${value#\"}; value=${value%\"}
  value=${value#\'}; value=${value%\'}
  printf '%s' "$value"
}

manager_available() {
  command -v "$1" >/dev/null 2>&1
}

detect_package_manager() {
  if is_termux_env && manager_available pkg; then printf 'pkg (Termux)'; return; fi

  # Prefer the manager implied by os-release. PATH order alone is unreliable
  # on derivative distros that may also ship compatibility tools.
  distro_family="${DISTRO_ID:-} ${DISTRO_LIKE:-}"
  case "$distro_family" in
    *arch*)
      if manager_available pacman; then printf 'pacman'; else printf 'não detectado'; fi
      return
      ;;
    *debian*|*ubuntu*)
      if manager_available apt-get; then printf 'apt-get'; return; fi
      if manager_available apt; then printf 'apt'; return; fi
      printf 'não detectado'; return
      ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*)
      if manager_available dnf; then printf 'dnf'; return; fi
      if manager_available yum; then printf 'yum'; return; fi
      printf 'não detectado'; return
      ;;
    *suse*) if manager_available zypper; then printf 'zypper'; else printf 'não detectado'; fi; return ;;
    *alpine*) if manager_available apk; then printf 'apk'; else printf 'não detectado'; fi; return ;;
    *void*) if manager_available xbps-install; then printf 'xbps-install'; else printf 'não detectado'; fi; return ;;
    *gentoo*) if manager_available emerge; then printf 'emerge'; else printf 'não detectado'; fi; return ;;
    *solus*) if manager_available eopkg; then printf 'eopkg'; else printf 'não detectado'; fi; return ;;
    *clearlinux*) if manager_available swupd; then printf 'swupd'; else printf 'não detectado'; fi; return ;;
  esac

  case "$(uname -s 2>/dev/null || true)" in
    Darwin) if manager_available brew; then printf 'brew'; return; fi ;;
    FreeBSD) if manager_available pkg; then printf 'pkg (FreeBSD)'; return; fi ;;
    OpenBSD) if manager_available pkg_add; then printf 'pkg_add'; return; fi ;;
    NetBSD) if manager_available pkgin; then printf 'pkgin'; return; fi ;;
  esac

  for candidate in apt-get dnf yum pacman zypper apk xbps-install emerge eopkg swupd brew pkg pkgin pkg_add; do
    if manager_available "$candidate"; then printf '%s' "$candidate"; return; fi
  done
  printf 'não detectado'
}

detect_environment() {
  if is_termux_env; then
    DISTRO=Termux
  else
    DISTRO=$(read_os_release_field PRETTY_NAME)
    if [ -z "$DISTRO" ]; then
      DISTRO=$(uname -s 2>/dev/null || printf 'Unix')
    fi
  fi
  DISTRO_ID=$(read_os_release_field ID)
  DISTRO_LIKE=$(read_os_release_field ID_LIKE)
  PACKAGE_MANAGER=$(detect_package_manager)
  if [ "$(id -u)" -eq 0 ]; then PRIVILEGE_MODE=root; else PRIVILEGE_MODE=sem-root; fi
  printf 'Ambiente: %s' "$DISTRO"
  [ -z "$DISTRO_ID" ] || printf ' (ID=%s)' "$DISTRO_ID"
  printf '\nPrivilégio: %s\nGerenciador detectado: %s\n' "$PRIVILEGE_MODE" "$PACKAGE_MANAGER"
  if command -v "${PYTHON:-python3}" >/dev/null 2>&1; then
    printf 'Python: %s\n' "$(command -v "${PYTHON:-python3}")"
  else
    printf 'Python: não encontrado\n'
  fi
}

dependency_help() {
  case "$PACKAGE_MANAGER" in
    'pkg (Termux)') echo "Instale Python/pip no Termux com: pkg install python" ;;
    apt-get) echo "Instale Python/pip com o gerenciador da distro, por exemplo: sudo apt-get install python3 python3-pip" ;;
    dnf) echo "Instale Python/pip com o gerenciador da distro, por exemplo: sudo dnf install python3 python3-pip" ;;
    yum) echo "Instale Python/pip com o gerenciador da distro, por exemplo: sudo yum install python3 python3-pip" ;;
    pacman) echo "Instale Python/pip com o gerenciador da distro, por exemplo: sudo pacman -S python python-pip" ;;
    zypper) echo "Instale Python/pip com o gerenciador da distro, por exemplo: sudo zypper install python3 python3-pip" ;;
    apk) echo "Instale Python/pip com o gerenciador da distro, por exemplo: doas apk add python3 py3-pip" ;;
    xbps-install) echo "Instale Python/pip com: sudo xbps-install -S python3 python3-pip" ;;
    emerge) echo "Instale Python/pip com emerge e os pacotes disponíveis nesta versão do Gentoo." ;;
    eopkg) echo "Instale Python/pip com eopkg e os pacotes disponíveis nesta versão do Solus." ;;
    swupd) echo "Instale Python/pip usando os bundles swupd desta versão do Clear Linux." ;;
    brew) echo "Instale Python com: brew install python" ;;
    'pkg (FreeBSD)') echo "Instale Python/pip com: sudo pkg install python3 py311-pip" ;;
    pkg_add) echo "Instale Python/pip com pkg_add e os pacotes disponíveis nesta versão do OpenBSD." ;;
    pkgin) echo "Instale Python/pip com pkgin e os pacotes disponíveis nesta versão do NetBSD." ;;
    pkg) echo "Instale Python e pip usando o gerenciador pkg desta plataforma." ;;
    *) echo "Instale Python 3.10+ e pip pelo gerenciador de pacotes desta plataforma e tente novamente." ;;
  esac
}

run_with_privilege() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  elif command -v doas >/dev/null 2>&1; then
    doas "$@"
  else
    echo "Instalar bibliotecas do Chromium exige root, sudo ou doas." >&2
    return 1
  fi
}

install_termux_build_dependencies() {
  [ "$IS_TERMUX" = "1" ] || return 0
  if ! command -v pkg >/dev/null 2>&1; then
    echo "Termux detectado, mas o comando pkg não está disponível." >&2
    return 1
  fi
  # Termux has no manylinux wheels for several native Python packages in the
  # runtime. Install its supported toolchain and library headers for pip builds.
  pkg install -y clang make pkg-config rust openssl libffi libxml2 libxslt \
    libjpeg-turbo libpng freetype libwebp littlecms
}

install_arch_browser_dependencies() {
  # Never call Playwright --with-deps on Arch: it assumes an apt-based host.
  run_with_privilege pacman -S --needed chromium
}

system_chromium_available() {
  if [ -n "${RAVENEYE_CHROMIUM_EXECUTABLE:-}" ] && [ -x "$RAVENEYE_CHROMIUM_EXECUTABLE" ]; then
    return 0
  fi
  for browser_name in chromium chromium-browser google-chrome-stable google-chrome chrome; do
    command -v "$browser_name" >/dev/null 2>&1 && return 0
  done
  return 1
}

install_browser_system_dependencies() {
  [ "$(uname -s 2>/dev/null || true)" = "Linux" ] || return 0
  if system_chromium_available; then
    echo "Chromium nativo encontrado; não será necessário instalar pacotes de navegador no sistema."
    return 0
  fi
  case "$PACKAGE_MANAGER" in
    pacman) install_arch_browser_dependencies ;;
    dnf|yum)
      run_with_privilege "$PACKAGE_MANAGER" install chromium
      ;;
    zypper)
      run_with_privilege zypper install chromium
      ;;
    apk)
      # Chromium comes from musl-native Alpine packages; gcompat is a
      # best-effort bridge for the Playwright Node driver. The local smoke
      # test decides whether this combination actually works on this release.
      run_with_privilege apk add chromium gcompat
      ;;
    xbps-install)
      run_with_privilege xbps-install -S chromium
      ;;
    emerge)
      run_with_privilege emerge --ask --oneshot www-client/chromium
      ;;
    eopkg)
      run_with_privilege eopkg install chromium
      ;;
    apt-get|apt)
      # The supported Debian/Ubuntu path is handled by Playwright --with-deps.
      return 0
      ;;
    brew)
      # macOS supplies native browser libraries; Playwright installs its binary.
      return 0
      ;;
    *)
      echo "Bibliotecas nativas não instaladas automaticamente para '$PACKAGE_MANAGER'; verificando Chromium instalado." >&2
      return 0
      ;;
  esac
}

install_playwright_chromium() {
  PYTHONPATH="$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" \
    PLAYWRIGHT_BROWSERS_PATH="$BROWSER_STAGE" \
    "$PYTHON" -m playwright install chromium
}

install_playwright_chromium_with_deps() {
  if [ "$(id -u)" -eq 0 ]; then
    PYTHONPATH="$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" \
      PLAYWRIGHT_BROWSERS_PATH="$BROWSER_STAGE" \
      "$PYTHON" -m playwright install --with-deps chromium
  elif command -v sudo >/dev/null 2>&1; then
    sudo env "PYTHONPATH=$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" \
      "PLAYWRIGHT_BROWSERS_PATH=$BROWSER_STAGE" "$PYTHON" \
      -m playwright install --with-deps chromium
  elif command -v doas >/dev/null 2>&1; then
    doas env "PYTHONPATH=$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" \
      "PLAYWRIGHT_BROWSERS_PATH=$BROWSER_STAGE" "$PYTHON" \
      -m playwright install --with-deps chromium
  else
    install_playwright_chromium
  fi
}

run_chromium_smoke_test() {
  smoke_source=$1
  smoke_vendor=$2
  smoke_browsers=$3
  PYTHONPATH="$smoke_source:$smoke_vendor${PYTHONPATH:+:$PYTHONPATH}" \
    PLAYWRIGHT_BROWSERS_PATH="$smoke_browsers" \
    "$PYTHON" -c 'import sys
from raveneye.core.browser import chromium_runtime_smoke
ok, detail = chromium_runtime_smoke()
print(detail, file=sys.stderr if not ok else sys.stdout)
raise SystemExit(0 if ok else 1)'
}

has_entries() {
  directory=$1
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    return 0
  done
  return 1
}

launcher_is_raveneye() {
  candidate=$1
  [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
  grep -F 'RAVENEYE_LAUNCHER=1' "$candidate" >/dev/null 2>&1 || grep -F 'RAVENEYE_HOME=' "$candidate" >/dev/null 2>&1
}

validate_install_paths() {
  for candidate in "$BIN_DIR" "$LIB_DIR" "${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}"; do
    case "$candidate" in
      /*) ;;
      *) echo "Caminho de instalação precisa ser absoluto: $candidate" >&2; return 1 ;;
    esac
    case "$candidate" in */../*|*/..|*/./*|*/.)
      echo "Caminho de instalação não pode conter componentes '.' ou '..': $candidate" >&2
      return 1
      ;;
    esac
    case "$candidate" in *'
'*) echo "Caminho de instalação não pode conter quebra de linha." >&2; return 1 ;; esac
  done
  case "$LIB_DIR" in
    /|"$HOME"|"$HOME/"|"${PREFIX:-/non-termux}"|"${PREFIX:-/non-termux}/")
      echo "RAVENEYE_LIB_DIR aponta para um diretório protegido; escolha uma pasta dedicada ao RavenEye." >&2
      return 1
      ;;
  esac
  case "$SYSTEM_BIN_DIR" in /|"$HOME"|"${PREFIX:-/non-termux}"|"${PREFIX:-/non-termux}/")
    echo "RAVENEYE_SYSTEM_BIN_DIR aponta para um diretório protegido: $SYSTEM_BIN_DIR" >&2
    return 1
    ;;
  esac
  [ "$BIN_DIR" != "$LIB_DIR" ] || { echo "BIN_DIR e LIB_DIR não podem ser iguais." >&2; return 1; }
  [ "$SYSTEM_BIN_DIR" != "$BIN_DIR" ] || { echo "SYSTEM_BIN_DIR e BIN_DIR não podem ser iguais." >&2; return 1; }
  [ ! -L "$LIB_DIR" ] || { echo "RAVENEYE_LIB_DIR não pode ser link simbólico." >&2; return 1; }
  [ ! -L "$BIN_DIR" ] || { echo "RAVENEYE_BIN_DIR não pode ser link simbólico." >&2; return 1; }
  case "$BIN_DIR" in /|"$HOME"|"${PREFIX:-/non-termux}"|"${PREFIX:-/non-termux}/")
    echo "RAVENEYE_BIN_DIR aponta para um diretório protegido: $BIN_DIR" >&2
    return 1
    ;;
  esac
  case "$BIN_DIR/" in "$LIB_DIR/"*) echo "BIN_DIR não pode conter LIB_DIR." >&2; return 1 ;; esac
  case "$LIB_DIR/" in "$BIN_DIR/"*) echo "LIB_DIR não pode conter BIN_DIR." >&2; return 1 ;; esac
  if { [ -e "$LIB_DIR/.raveneye-install" ] || [ -L "$LIB_DIR/.raveneye-install" ]; } &&
     { [ ! -f "$LIB_DIR/.raveneye-install" ] || [ -L "$LIB_DIR/.raveneye-install" ]; }; then
    echo "O marcador de instalação existente não é um arquivo regular confiável: $LIB_DIR/.raveneye-install" >&2
    return 1
  fi
  [ ! -L "$BIN_DIR/raven" ] || { echo "O launcher de destino é link simbólico; não será substituído." >&2; return 1; }
  [ ! -L "$BIN_DIR/raven.home" ] || { echo "O arquivo lateral do launcher é link simbólico; não será substituído." >&2; return 1; }
  if [ -e "$BIN_DIR/raven" ] && ! launcher_is_raveneye "$BIN_DIR/raven"; then
    echo "Já existe um comando 'raven' que não pertence ao RavenEye em $BIN_DIR; nada foi sobrescrito." >&2
    return 1
  fi
  if [ -d "$LIB_DIR" ] && has_entries "$LIB_DIR"; then
    marker_ok=0
    if [ -f "$LIB_DIR/.raveneye-install" ] && [ ! -L "$LIB_DIR/.raveneye-install" ] &&
       grep -F 'RavenEye' "$LIB_DIR/.raveneye-install" >/dev/null 2>&1; then marker_ok=1; fi
    legacy_ok=0
    if [ -f "$LIB_DIR/RavenEye.py" ] && [ -f "$LIB_DIR/raveneye_pkg/constants.py" ]; then legacy_ok=1; fi
    partial_empty_vendor=0
    if [ -d "$LIB_DIR/_vendor" ] && [ ! -L "$LIB_DIR/_vendor" ] && ! has_entries "$LIB_DIR/_vendor"; then
      partial_empty_vendor=1
      for existing_entry in "$LIB_DIR"/* "$LIB_DIR"/.[!.]* "$LIB_DIR"/..?*; do
        [ -e "$existing_entry" ] || [ -L "$existing_entry" ] || continue
        [ "$existing_entry" = "$LIB_DIR/_vendor" ] || { partial_empty_vendor=0; break; }
      done
    fi
    if [ "$marker_ok" != 1 ] && [ "$legacy_ok" != 1 ] && [ "$partial_empty_vendor" != 1 ]; then
      echo "O diretório de destino já contém dados que não foram identificados como RavenEye: $LIB_DIR" >&2
      return 1
    fi
  fi
  return 0
}

if [ -z "${HOME:-}" ]; then
  echo "HOME não está definido; não é possível escolher o destino da instalação." >&2
  exit 1
fi
BIN_DIR="${RAVENEYE_BIN_DIR:-$HOME/.local/bin}"
LIB_DIR="${RAVENEYE_LIB_DIR:-$HOME/.local/share/raveneye}"
SYSTEM_BIN_DIR="${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}"
IS_TERMUX=0
if is_termux_env; then
  IS_TERMUX=1
  BIN_DIR="${RAVENEYE_BIN_DIR:-$PREFIX/bin}"
  LIB_DIR="${RAVENEYE_LIB_DIR:-$PREFIX/share/raveneye}"
fi
PYTHON=${PYTHON:-python3}
detect_environment
validate_install_paths || exit 1

if [ "$DRY_RUN" = "1" ]; then
  echo "Modo dry-run: nenhuma ação foi executada."
  echo "Destino do comando: $BIN_DIR/raven"
  echo "Destino do código/dependências: $LIB_DIR"
  echo "Dependências: instalar runtime completo; usar Chromium nativo ou baixar o Chromium Playwright em diretório temporário; validar antes de ativar."
  echo "Ações: instalar dependências do navegador com o gerenciador detectado quando necessário, criar diretórios, copiar fontes e verificar 'raven --version'."
  if [ "$IS_TERMUX" = "1" ]; then
    echo "Termux: instalar toolchain para compilar dependências Python; headless é opcional e será ignorado."
    echo "Wrapper global: ignorado no Termux."
  elif command -v sudo >/dev/null 2>&1; then
    echo "Wrapper global: solicitar sudo para copiar o launcher em $SYSTEM_BIN_DIR (nenhuma chamada será feita no dry-run)."
  else
    echo "Wrapper global: ignorado porque sudo não está instalado."
  fi
  exit 0
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python não encontrado." >&2
  dependency_help >&2
  exit 1
fi
if ! "$PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
  echo "O RavenEye requer Python 3.10 ou superior." >&2
  dependency_help >&2
  exit 1
fi
if ! "$PYTHON" -c 'import pip' >/dev/null 2>&1; then
  echo "O Python selecionado não tem pip." >&2
  dependency_help >&2
  echo "Nenhum pacote do sistema será instalado automaticamente." >&2
  exit 1
fi
for required_tool in tar mktemp; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    echo "Ferramenta necessária não encontrada: $required_tool. Instale-a pelo gerenciador $PACKAGE_MANAGER e tente novamente." >&2
    exit 1
  fi
done
if ! install_termux_build_dependencies; then
  echo "Falha ao preparar o toolchain de compilação do Termux; nenhuma alteração do RavenEye foi ativada." >&2
  exit 1
fi
mkdir -p "$BIN_DIR" "$LIB_DIR"
LOCK_DIR="$LIB_DIR/.raveneye-install.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Outra instalação RavenEye está ativa ou deixou um lock em $LOCK_DIR." >&2
  echo "Depois de confirmar que não há instalador rodando, remova esse diretório e tente novamente." >&2
  exit 1
fi
LOCK_HELD=1
# Mantém uma cópia-fonte autocontida e atualizável, usando execução por módulo.
ARCHIVE=
REQ=
VENDOR_STAGE=
VENDOR_BACKUP=
BROWSER_STAGE=
BROWSER_BACKUP=
SOURCE_STAGE=
SOURCE_BACKUP=
MARKER_TMP=
MARKER_BACKUP=
LAUNCHER_TMP=
HOME_TMP=
LAUNCHER_BACKUP_DIR=
SOURCE_ACTIVATED=0
VENDOR_ACTIVATED=0
BROWSER_ACTIVATED=0
LAUNCHER_ACTIVATED=0
MARKER_ACTIVATED=0
INSTALL_COMMITTED=0
cleanup_temp() {
  [ -z "$ARCHIVE" ] || rm -f "$ARCHIVE"
  [ -z "$REQ" ] || rm -f "$REQ"
  [ -z "$MARKER_TMP" ] || rm -f "$MARKER_TMP"
  [ -z "$LAUNCHER_TMP" ] || rm -f "$LAUNCHER_TMP"
  [ -z "$HOME_TMP" ] || rm -f "$HOME_TMP"
  if [ -n "$VENDOR_STAGE" ] && [ -d "$VENDOR_STAGE" ]; then rm -rf "$VENDOR_STAGE"; fi
  if [ -n "$BROWSER_STAGE" ] && [ -d "$BROWSER_STAGE" ]; then rm -rf "$BROWSER_STAGE"; fi
  if [ "$INSTALL_COMMITTED" != "1" ]; then
    if [ "$SOURCE_ACTIVATED" = "1" ] && [ -n "$SOURCE_STAGE" ] && [ -d "$SOURCE_STAGE" ]; then
      for staged_path in "$SOURCE_STAGE"/* "$SOURCE_STAGE"/.[!.]* "$SOURCE_STAGE"/..?*; do
        [ -e "$staged_path" ] || [ -L "$staged_path" ] || continue
        source_name=${staged_path##*/}
        rm -rf "$LIB_DIR/$source_name"
        if [ -e "$SOURCE_BACKUP/$source_name" ] || [ -L "$SOURCE_BACKUP/$source_name" ]; then
          mv "$SOURCE_BACKUP/$source_name" "$LIB_DIR/$source_name" || true
        fi
      done
    fi
    if [ "$MARKER_ACTIVATED" = "1" ]; then
      rm -f "$LIB_DIR/.raveneye-install"
      if [ -e "$MARKER_BACKUP" ]; then mv "$MARKER_BACKUP" "$LIB_DIR/.raveneye-install" || true; fi
    fi
    if [ "$BROWSER_ACTIVATED" = "1" ]; then
      rm -rf "$LIB_DIR/.playwright-browsers"
      if [ -n "$BROWSER_BACKUP" ] && [ -d "$BROWSER_BACKUP" ]; then
        mv "$BROWSER_BACKUP" "$LIB_DIR/.playwright-browsers" || true
      fi
    fi
    if [ "$VENDOR_ACTIVATED" = "1" ]; then
      rm -rf "$LIB_DIR/_vendor"
      if [ -n "$VENDOR_BACKUP" ] && [ -d "$VENDOR_BACKUP" ]; then
        mv "$VENDOR_BACKUP" "$LIB_DIR/_vendor" || true
      fi
    fi
    if [ "$LAUNCHER_ACTIVATED" = "1" ]; then
      rm -f "$BIN_DIR/raven" "$BIN_DIR/raven.home"
      if [ -n "$LAUNCHER_BACKUP_DIR" ] && [ -d "$LAUNCHER_BACKUP_DIR" ]; then
        if [ -e "$LAUNCHER_BACKUP_DIR/raven" ]; then cp -p "$LAUNCHER_BACKUP_DIR/raven" "$BIN_DIR/raven" || true; fi
        if [ -e "$LAUNCHER_BACKUP_DIR/raven.home" ]; then cp -p "$LAUNCHER_BACKUP_DIR/raven.home" "$BIN_DIR/raven.home" || true; fi
      fi
    fi
  fi
  if [ -n "$SOURCE_STAGE" ] && [ -d "$SOURCE_STAGE" ]; then rm -rf "$SOURCE_STAGE"; fi
  if [ -n "$VENDOR_BACKUP" ] && [ -d "$VENDOR_BACKUP" ]; then rm -rf "$VENDOR_BACKUP"; fi
  if [ -n "$BROWSER_BACKUP" ] && [ -d "$BROWSER_BACKUP" ]; then rm -rf "$BROWSER_BACKUP"; fi
  if [ -n "$SOURCE_BACKUP" ] && [ -d "$SOURCE_BACKUP" ]; then rm -rf "$SOURCE_BACKUP"; fi
  if [ -n "$LAUNCHER_BACKUP_DIR" ] && [ -d "$LAUNCHER_BACKUP_DIR" ]; then rm -rf "$LAUNCHER_BACKUP_DIR"; fi
  if [ "$INSTALL_COMMITTED" = "1" ] && [ -n "$MARKER_BACKUP" ] && [ -e "$MARKER_BACKUP" ]; then
    rm -f "$MARKER_BACKUP"
  fi
  if [ "${LOCK_HELD:-0}" = "1" ]; then rmdir "$LOCK_DIR" 2>/dev/null || true; fi
}
trap cleanup_temp 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ARCHIVE=$(mktemp "${TMPDIR:-/tmp}/raveneye-install.XXXXXX") || {
  echo "Não foi possível criar um arquivo temporário para a instalação." >&2
  exit 1
}

SYMLINK_IN_SOURCE=$(find "$ROOT" \( -path "$ROOT/venv" -o -path "$ROOT/.venv" \) -prune -o -type l -print -quit)
if [ -n "$SYMLINK_IN_SOURCE" ]; then
  echo "A origem contém um link simbólico e não será empacotada: $SYMLINK_IN_SOURCE" >&2
  exit 1
fi
TAR_HELP=$(tar --help 2>/dev/null || true)
if case "$TAR_HELP" in *--warning*) true ;; *) false ;; esac; then
  tar --warning=no-timestamp -C "$ROOT" \
    --exclude='./venv' --exclude='./.venv' --exclude='./__pycache__' \
    --exclude='./.pytest_cache' --exclude='./output' --exclude='./data' \
    --exclude='./reports' --exclude='.env' --exclude='./raven_eye_config.json' \
    --exclude='*.log' --exclude='*.log.*' --exclude='./RavenEye_dorks_*.txt' \
    --exclude='./RavenEye_dorks_resultados_*.txt' --exclude='./raveneye_audit_log.txt' \
    --exclude='./.raveneye_trash' -cf "$ARCHIVE" . || {
      echo "Falha ao empacotar os arquivos do RavenEye." >&2
      exit 1
    }
else
  tar -C "$ROOT" \
    --exclude='./venv' --exclude='./.venv' --exclude='./__pycache__' \
    --exclude='./.pytest_cache' --exclude='./output' --exclude='./data' \
    --exclude='./reports' --exclude='.env' --exclude='./raven_eye_config.json' \
    --exclude='*.log' --exclude='*.log.*' --exclude='./RavenEye_dorks_*.txt' \
    --exclude='./RavenEye_dorks_resultados_*.txt' --exclude='./raveneye_audit_log.txt' \
    --exclude='./.raveneye_trash' -cf "$ARCHIVE" . || {
  echo "Falha ao empacotar os arquivos do RavenEye." >&2
  exit 1
}
fi
# Dependências Python ficam dentro da instalação; headless é uma capacidade
# opcional e o Chromium é validado localmente antes de ser ativado.
# Todos os artefatos são preparados separadamente; falha de download não
# substitui o código, vendor ou browsers que já estejam ativos.
VENDOR_DIR="$LIB_DIR/_vendor"
if [ -L "$VENDOR_DIR" ] || { [ -e "$VENDOR_DIR" ] && [ ! -d "$VENDOR_DIR" ]; }; then
  echo "O destino de dependências não é um diretório seguro: $VENDOR_DIR" >&2
  exit 1
fi
  REQ=$(build_requirements_file)
  VENDOR_STAGE=$(mktemp -d "$LIB_DIR/.raveneye-vendor.XXXXXX") || {
    echo "Não foi possível preparar o diretório temporário de dependências em $LIB_DIR." >&2
    exit 1
  }
  "$PYTHON" -m pip install --disable-pip-version-check --upgrade --target "$VENDOR_STAGE" -r "$REQ" || {
    echo "Não foi possível instalar as dependências em $VENDOR_DIR." >&2
    echo "Verifique a rede e o gerenciador de pacotes Python e tente novamente." >&2
    exit 1
  }
  PYTHONPATH="$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" -c 'import os, requests, colorama, aiohttp, httpx, aiosqlite, rich, click, dotenv, socks, dns, whois, jwt, jsbeautifier, tqdm, shodan, pydantic, pydantic_settings, yaml, lxml, sqlalchemy, reportlab, PIL, playwright, asyncssh, aioftp, aiosmtplib, motor, asyncpg, aiomysql, smbprotocol; import sys; __import__("uvloop") if sys.platform == "linux" and "com.termux" not in os.environ.get("PREFIX", "") else None' >/dev/null 2>&1 || {
    echo "O conjunto temporário não contém todas as dependências runtime obrigatórias; a instalação anterior foi mantida." >&2
    exit 1
  }
  BROWSER_DIR="$LIB_DIR/.playwright-browsers"
  if [ -L "$BROWSER_DIR" ] || { [ -e "$BROWSER_DIR" ] && [ ! -d "$BROWSER_DIR" ]; }; then
    echo "O diretório dos navegadores Playwright não é seguro: $BROWSER_DIR" >&2
    exit 1
  fi
  BROWSER_STAGE=$(mktemp -d "$LIB_DIR/.raveneye-browsers.XXXXXX") || {
    echo "Não foi possível preparar o diretório temporário dos navegadores." >&2
    exit 1
  }
  if [ "$IS_TERMUX" = "1" ]; then
    echo "Termux não usa o Chromium Linux do Playwright; mantendo a instalação sem headless." >&2
  elif is_debian_apt_env; then
    if ! install_playwright_chromium_with_deps; then
      echo "Playwright --with-deps falhou; tentando baixar o Chromium sem instalar dependências do sistema." >&2
      if ! install_playwright_chromium; then
        echo "Não foi possível baixar o Chromium Playwright; a renderização headless ficará indisponível se nenhum browser existente iniciar." >&2
      fi
    fi
  else
    if ! install_browser_system_dependencies; then
      echo "Não foi possível instalar Chromium nativo pelo gerenciador $PACKAGE_MANAGER; tentando o Chromium do Playwright." >&2
    fi
    if system_chromium_available; then
      echo "Usando Chromium fornecido pela distro; Playwright manterá o driver Python no runtime do RavenEye."
    elif ! install_playwright_chromium; then
      echo "Não foi possível baixar Chromium Playwright; a renderização headless ficará indisponível se nenhum browser existente iniciar." >&2
    fi
  fi

  SOURCE_STAGE=$(mktemp -d "$LIB_DIR/.raveneye-source.XXXXXX") || {
    echo "Não foi possível preparar a cópia temporária do código." >&2
    exit 1
  }
  tar -C "$SOURCE_STAGE" -xf "$ARCHIVE" || {
    echo "Falha ao validar a cópia temporária do código." >&2
    exit 1
  }
  HEADLESS_AVAILABLE=0
  if [ "$IS_TERMUX" = "1" ]; then
    rm -rf "$BROWSER_STAGE"
    BROWSER_STAGE=
  elif run_chromium_smoke_test "$SOURCE_STAGE" "$VENDOR_STAGE" "$BROWSER_STAGE"; then
    HEADLESS_AVAILABLE=1
  elif [ -d "$BROWSER_DIR" ] && run_chromium_smoke_test "$SOURCE_STAGE" "$VENDOR_STAGE" "$BROWSER_DIR"; then
    echo "O Chromium novo falhou; mantendo o browser ativo que passou no smoke test." >&2
    rm -rf "$BROWSER_STAGE"
    BROWSER_STAGE=
    HEADLESS_AVAILABLE=1
  else
    echo "Nenhum Chromium headless passou no fixture local; a instalação seguirá sem renderização JS." >&2
    echo "Crawler estático, scanner e outros módulos continuam disponíveis; 'raven doctor' mostrará essa capacidade como opcional." >&2
    rm -rf "$BROWSER_STAGE"
    BROWSER_STAGE=
  fi
  PYTHONPATH="$SOURCE_STAGE:$VENDOR_STAGE${PYTHONPATH:+:$PYTHONPATH}" PLAYWRIGHT_BROWSERS_PATH="$BROWSER_STAGE" \
    "$PYTHON" "$SOURCE_STAGE/RavenEye.py" --version >/dev/null 2>&1 || {
      echo "O código novo não passou na verificação local de inicialização; a instalação ativa foi preservada." >&2
      exit 1
    }

  VENDOR_BACKUP="$LIB_DIR/.raveneye-vendor-backup.$$"
  BROWSER_BACKUP="$LIB_DIR/.raveneye-browsers-backup.$$"
  SOURCE_BACKUP="$LIB_DIR/.raveneye-source-backup.$$"
  if [ -e "$VENDOR_BACKUP" ] || [ -L "$VENDOR_BACKUP" ] ||
     [ -e "$BROWSER_BACKUP" ] || [ -L "$BROWSER_BACKUP" ] ||
     [ -e "$SOURCE_BACKUP" ] || [ -L "$SOURCE_BACKUP" ]; then
    echo "Diretório temporário de backup já existe; instalação bloqueada." >&2
    exit 1
  fi
  mkdir "$SOURCE_BACKUP" || { echo "Não foi possível preparar backup do código atual." >&2; exit 1; }
  for staged_path in "$SOURCE_STAGE"/* "$SOURCE_STAGE"/.[!.]* "$SOURCE_STAGE"/..?*; do
    [ -e "$staged_path" ] || [ -L "$staged_path" ] || continue
    source_name=${staged_path##*/}
    if [ -e "$LIB_DIR/$source_name" ] || [ -L "$LIB_DIR/$source_name" ]; then
      cp -a "$LIB_DIR/$source_name" "$SOURCE_BACKUP/$source_name" || {
        echo "Não foi possível preservar $source_name; instalação cancelada." >&2
        exit 1
      }
    fi
  done

  # The following swaps are reversible until the final launcher smoke check.
  if [ -n "$BROWSER_STAGE" ]; then
    if [ -d "$BROWSER_DIR" ]; then
      mv "$BROWSER_DIR" "$BROWSER_BACKUP" || { echo "Não foi possível preservar os browsers ativos." >&2; exit 1; }
    fi
    if mv "$BROWSER_STAGE" "$BROWSER_DIR"; then
      BROWSER_STAGE=
      BROWSER_ACTIVATED=1
    else
      [ ! -d "$BROWSER_BACKUP" ] || mv "$BROWSER_BACKUP" "$BROWSER_DIR" || true
      echo "Não foi possível ativar os browsers novos; os atuais foram preservados." >&2
      exit 1
    fi
  fi

  if [ -e "$VENDOR_DIR" ]; then
    mv "$VENDOR_DIR" "$VENDOR_BACKUP" || { echo "Não foi possível preservar as dependências atuais." >&2; exit 1; }
  fi
  if mv "$VENDOR_STAGE" "$VENDOR_DIR"; then
    VENDOR_STAGE=
    VENDOR_ACTIVATED=1
  else
    if [ -d "$VENDOR_BACKUP" ] && [ ! -e "$VENDOR_DIR" ]; then mv "$VENDOR_BACKUP" "$VENDOR_DIR"; fi
    echo "Não foi possível ativar as dependências novas; o conjunto anterior foi restaurado." >&2
    exit 1
  fi

  SOURCE_ACTIVATED=1
  tar -C "$LIB_DIR" -xf "$ARCHIVE" || {
    echo "Falha ao ativar o código novo; o instalador restaurará a versão anterior." >&2
    exit 1
  }
  if [ -e "$LIB_DIR/.raveneye-install" ] || [ -L "$LIB_DIR/.raveneye-install" ]; then
    MARKER_BACKUP=$(mktemp "$LIB_DIR/.raveneye-marker.XXXXXX") || {
      echo "Não foi possível preservar o marcador de instalação." >&2
      exit 1
    }
    cp -p "$LIB_DIR/.raveneye-install" "$MARKER_BACKUP" || {
      echo "Não foi possível preservar o marcador de instalação." >&2
      exit 1
    }
  fi
  MARKER_TMP=$(mktemp "$LIB_DIR/.raveneye-install.XXXXXX") || {
    echo "Não foi possível criar o marcador de instalação." >&2
    exit 1
  }
  printf 'RavenEye 6.6.6\n' > "$MARKER_TMP"
  chmod 600 "$MARKER_TMP"
  mv -f "$MARKER_TMP" "$LIB_DIR/.raveneye-install"
  MARKER_TMP=
  MARKER_ACTIVATED=1
PYTHONPATH="$VENDOR_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" -c 'import bs4' >/dev/null 2>&1 || {
  echo "A instalação não tem a dependência obrigatória beautifulsoup4 (bs4)." >&2
  dependency_help >&2
  echo "Execute novamente o instalador com uma conexão disponível para instalar o pacote completo." >&2
  exit 1
}

install_launcher() {
  destination_dir=$1
  destination="$destination_dir/raven"
  destination_home="$destination.home"
  [ ! -L "$destination_home" ] || { echo "O arquivo lateral do launcher é link simbólico: $destination_home" >&2; return 1; }
  if [ -e "$destination_home" ] && ! launcher_is_raveneye "$destination"; then
    echo "O arquivo lateral já existe sem um launcher RavenEye correspondente: $destination_home" >&2
    return 1
  fi
  LAUNCHER_TMP=$(mktemp "$destination_dir/.raveneye-launcher.XXXXXX") || return 1
  HOME_TMP=$(mktemp "$destination_dir/.raveneye-home.XXXXXX") || return 1
  if [ -e "$destination" ] && ! launcher_is_raveneye "$destination"; then
    echo "Já existe um comando não RavenEye em $destination; ele não será sobrescrito." >&2
    return 1
  fi
  cp "$ROOT/installer/raven" "$LAUNCHER_TMP"
  printf '%s\n' "$LIB_DIR" > "$HOME_TMP"
  chmod 755 "$LAUNCHER_TMP"
  chmod 644 "$HOME_TMP"
  mv -f "$HOME_TMP" "$destination_home"
  HOME_TMP=
  mv -f "$LAUNCHER_TMP" "$destination"
  LAUNCHER_TMP=
}

LAUNCHER_BACKUP_DIR=$(mktemp -d "$BIN_DIR/.raveneye-launcher-backup.XXXXXX") || {
  echo "Não foi possível preservar o launcher anterior." >&2
  exit 1
}
if [ -e "$BIN_DIR/raven" ]; then cp -p "$BIN_DIR/raven" "$LAUNCHER_BACKUP_DIR/raven"; fi
if [ -e "$BIN_DIR/raven.home" ]; then cp -p "$BIN_DIR/raven.home" "$LAUNCHER_BACKUP_DIR/raven.home"; fi
LAUNCHER_ACTIVATED=1
install_launcher "$BIN_DIR" || exit 1
"$BIN_DIR/raven" --version >/dev/null 2>&1 || {
  echo "O launcher foi criado, mas não passou no teste local de inicialização." >&2
  exit 1
}
INSTALL_COMMITTED=1
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "Instalado. Adicione $BIN_DIR ao PATH para usar 'raven' em novos terminais." ;; esac
echo "RavenEye instalado em modo usuário com o pacote completo (core + full + protocolos)."
echo "Sem argumentos, 'raven' abre o menu interativo (estilo nmap)."
if [ "${HEADLESS_AVAILABLE:-0}" = "1" ]; then
  echo "Renderização headless Chromium: validada com fixture local."
else
  echo "Renderização headless não disponível neste sistema; crawler estático e os demais módulos continuam instalados."
fi

# 'sudo' normalmente usa um PATH restrito (secure_path) que não inclui
# ~/.local/bin, então sem um wrapper em /usr/local/bin 'sudo raven' falha
# com "comando não encontrado". Isto é configurado agora mesmo, sempre,
# na mesma execução — pode pedir sua senha de sudo uma vez. As dependências
# já foram instaladas acima como o usuário atual, então este passo só
# precisa copiar o wrapper para um caminho de sistema: nenhum comando
# privilegiado roda pip.
configure_sudo_wrapper() {
  [ ! -L "$SYSTEM_BIN_DIR" ] || { echo "Diretório global de comandos é link simbólico: $SYSTEM_BIN_DIR" >&2; return 1; }
  if [ -e "$SYSTEM_BIN_DIR/raven" ] && ! launcher_is_raveneye "$SYSTEM_BIN_DIR/raven"; then
    echo "Já existe um comando não RavenEye em $SYSTEM_BIN_DIR/raven; o wrapper global foi preservado." >&2
    return 1
  fi
  if [ -e "$SYSTEM_BIN_DIR/raven.home" ] && ! launcher_is_raveneye "$SYSTEM_BIN_DIR/raven"; then
    echo "O arquivo lateral global já existe sem wrapper RavenEye correspondente; ele será preservado." >&2
    return 1
  fi
  [ ! -L "$SYSTEM_BIN_DIR/raven.home" ] || { echo "Arquivo lateral global é link simbólico; wrapper preservado." >&2; return 1; }
  sudo mkdir -p "$SYSTEM_BIN_DIR" &&
    sudo cp "$BIN_DIR/raven" "$SYSTEM_BIN_DIR/raven" &&
    sudo cp "$BIN_DIR/raven.home" "$SYSTEM_BIN_DIR/raven.home" &&
    sudo chmod 755 "$SYSTEM_BIN_DIR/raven" &&
    sudo chmod 644 "$SYSTEM_BIN_DIR/raven.home"
}

if [ "$IS_TERMUX" != "1" ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "Configurando 'sudo raven' automaticamente (pode pedir sua senha)..."
    if configure_sudo_wrapper && "$SYSTEM_BIN_DIR/raven" --version >/dev/null 2>&1; then
      echo "Pronto: 'raven' e 'sudo raven' já funcionam."
    else
      echo "Não foi possível configurar 'sudo raven' agora. Rode o instalador novamente para tentar de novo, ou configure manualmente:" >&2
      echo "  Verifique permissões em $SYSTEM_BIN_DIR e rode o instalador novamente." >&2
    fi
  else
    echo "'sudo' não encontrado neste sistema; pulando o wrapper global. 'raven' (sem sudo) já funciona normalmente."
  fi
else
  echo "Termux não usa sudo; 'raven' já funciona diretamente."
fi
echo "Para desinstalar:"
echo "  sh $LIB_DIR/installer/uninstall.sh"
