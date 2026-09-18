#!/usr/bin/env sh
# RavenEye — instalador único. Uma execução faz tudo:
#   1) instala o pacote COMPLETO (core + full + protocolos de bruteforce
#      assíncrono) em modo usuário (~/.local), sem exigir venv ativado;
#   2) cria o comando 'raven';
#   3) configura automaticamente o wrapper global em /usr/local/bin/raven,
#      para que 'sudo raven' já funcione ao final da mesma execução (pode
#      pedir sua senha de sudo uma vez). No Termux essa etapa é pulada
#      (não existe sudo lá) e, se 'sudo' não existir no sistema, também é
#      pulada — sem qualquer flag para o usuário decidir.
#
# Todas as dependências ficam embutidas neste script: não há
# requirements*.txt separado para manter em sincronia.
set -eu

# ==================================================================
# DEPENDÊNCIAS EMBUTIDAS
# ==================================================================
# CORE: necessário em qualquer plataforma, incluindo Termux/Android.
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
'

# FULL: recursos que costumam exigir compilação nativa (parsing XML rápido,
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

# PROTOCOLS: bruteforce assíncrono por protocolo, browser headless e loop
# de eventos de performance.
PROTOCOL_DEPS='
uvloop>=0.19,<1
playwright>=1.45,<2
asyncssh>=2.14,<3
aioftp>=0.23,<1
aiosmtplib>=3.0,<4
motor>=3.5,<4
asyncpg>=0.29,<1
aiomysql>=0.2,<1
smbprotocol>=1.14,<2
'

# TEST: tooling de desenvolvimento/teste; faz parte do pacote completo.
TEST_DEPS='
pytest>=8,<9
pytest-asyncio>=0.23,<2
coverage>=7,<8
'

usage() {
  cat <<'EOF'
Uso: sh installer/install.sh [-h]

Sem opções: instala o pacote COMPLETO (core + full + protocolos) em modo
usuário (~/.local) e, na mesma execução, configura automaticamente
'sudo raven' (pode pedir sua senha de sudo uma vez). No Termux essa última
etapa é pulada (não existe sudo lá); se este sistema não tiver 'sudo'
instalado, também é pulada automaticamente.

Variáveis de ambiente:
  RAVENEYE_BIN_DIR, RAVENEYE_LIB_DIR, RAVENEYE_SYSTEM_BIN_DIR
                                        Sobrescrevem os diretórios de destino.
  RAVENEYE_SKIP_DEPS=1                  Pula a instalação de dependências
                                        (diagnóstico/desenvolvimento offline).
  PYTHON                                Interpretador a usar (padrão: python3).

Depois de instalado: raven --help  /  sudo raven --help
Para desinstalar:     sh installer/uninstall.sh
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    *) echo "Opção desconhecida: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Monta um arquivo de requirements temporário a partir das listas embutidas
# acima (CORE+FULL+PROTOCOLS+TEST — sempre o pacote completo). pip -r
# continua sendo o mecanismo real de instalação; só a origem do texto mudou.
build_requirements_file() {
  out=$(mktemp "${TMPDIR:-/tmp}/raveneye-deps.XXXXXX.txt")
  printf '%s\n' "$CORE_DEPS" >>"$out"
  printf '%s\n' "$FULL_DEPS" >>"$out"
  printf '%s\n' "$PROTOCOL_DEPS" >>"$out"
  printf '%s\n' "$TEST_DEPS" >>"$out"
  printf '%s' "$out"
}

is_termux_env() {
  case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac
}

BIN_DIR="${RAVENEYE_BIN_DIR:-$HOME/.local/bin}"
LIB_DIR="${RAVENEYE_LIB_DIR:-$HOME/.local/share/raveneye}"
IS_TERMUX=0
if is_termux_env; then
  IS_TERMUX=1
  BIN_DIR="${RAVENEYE_BIN_DIR:-$PREFIX/bin}"
  LIB_DIR="${RAVENEYE_LIB_DIR:-$PREFIX/share/raveneye}"
fi
PYTHON=${PYTHON:-python3}
command -v "$PYTHON" >/dev/null 2>&1 || { echo "Python 3 não encontrado. Instale Python e tente novamente." >&2; exit 1; }
"$PYTHON" -c 'import pip' >/dev/null 2>&1 || {
  echo "O Python encontrado não possui pip. Instale o pacote pip da sua distribuição e tente novamente." >&2
  exit 1
}
mkdir -p "$BIN_DIR" "$LIB_DIR"
# Mantém uma cópia-fonte autocontida e atualizável, usando execução por módulo.
TAR_WARNING=
if tar --help 2>/dev/null | grep -q -- '--warning'; then
  TAR_WARNING='--warning=no-timestamp'
fi
ARCHIVE=$(mktemp "${TMPDIR:-/tmp}/raveneye-install.XXXXXX.tar") || {
  echo "Não foi possível criar um arquivo temporário para a instalação." >&2
  exit 1
}
REQ=
cleanup_temp() { rm -f "$ARCHIVE" "$REQ"; }
trap cleanup_temp EXIT HUP INT TERM
tar $TAR_WARNING -C "$ROOT" \
  --exclude='./venv' --exclude='./.venv' --exclude='./__pycache__' \
  --exclude='./.pytest_cache' --exclude='./output' --exclude='./data' \
  --exclude='./reports' -cf "$ARCHIVE" . || {
  echo "Falha ao empacotar os arquivos do RavenEye." >&2
  exit 1
}
tar -C "$LIB_DIR" -xf "$ARCHIVE" || {
  echo "Falha ao copiar os arquivos para $LIB_DIR. Verifique permissões." >&2
  exit 1
}

# Dependências ficam dentro da instalação: nenhum gerenciador de pacotes do
# sistema, sudo ou venv ativado é necessário. Sempre instala o pacote
# completo (CORE+FULL+PROTOCOLS+TEST), em qualquer plataforma, Termux
# incluso.
VENDOR_DIR="$LIB_DIR/_vendor"
mkdir -p "$VENDOR_DIR"
if [ "${RAVENEYE_SKIP_DEPS:-0}" != "1" ]; then
  REQ=$(build_requirements_file)
  "$PYTHON" -m pip install --disable-pip-version-check --upgrade --target "$VENDOR_DIR" -r "$REQ" || {
    echo "Não foi possível instalar as dependências em $VENDOR_DIR." >&2
    echo "Verifique a rede/gerenciador de pacotes ou repita com RAVENEYE_SKIP_DEPS=1 para diagnóstico." >&2
    exit 1
  }
fi
PYTHONPATH="$VENDOR_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" -c 'import bs4' >/dev/null 2>&1 || {
  echo "A instalação terminou sem a dependência obrigatória beautifulsoup4 (bs4)." >&2
  exit 1
}
sed "s|__RAVENEYE_HOME__|$LIB_DIR|g" "$ROOT/installer/raven" > "$BIN_DIR/raven"
chmod +x "$BIN_DIR/raven"
"$BIN_DIR/raven" --version >/dev/null 2>&1 || {
  echo "O launcher foi criado, mas não passou no teste local de inicialização." >&2
  exit 1
}
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "Instalado. Adicione $BIN_DIR ao PATH para usar 'raven' em novos terminais." ;; esac
echo "RavenEye instalado em modo usuário com o pacote completo (core + full + protocolos)."
echo "Sem argumentos, 'raven' abre o menu interativo (estilo nmap)."

# 'sudo' normalmente usa um PATH restrito (secure_path) que não inclui
# ~/.local/bin, então sem um wrapper em /usr/local/bin 'sudo raven' falha
# com "comando não encontrado". Isto é configurado agora mesmo, sempre,
# na mesma execução — pode pedir sua senha de sudo uma vez. As dependências
# já foram instaladas acima como o usuário atual, então este passo só
# precisa copiar o wrapper para um caminho de sistema: nenhum comando
# privilegiado roda pip.
configure_sudo_wrapper() {
  SYSTEM_BIN_DIR=${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}
  HELPER=$(mktemp "${TMPDIR:-/tmp}/raveneye-sudo-wrapper.XXXXXX.sh") || return 1
  cat > "$HELPER" <<HELPER_EOF
set -eu
mkdir -p "$SYSTEM_BIN_DIR"
sed "s|__RAVENEYE_HOME__|$LIB_DIR|g" "$ROOT/installer/raven" > "$SYSTEM_BIN_DIR/raven"
chmod 755 "$SYSTEM_BIN_DIR/raven"
HELPER_EOF
  sudo sh "$HELPER"
  rc=$?
  rm -f "$HELPER"
  return $rc
}

if [ "$IS_TERMUX" != "1" ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "Configurando 'sudo raven' automaticamente (pode pedir sua senha)..."
    SYSTEM_BIN_DIR=${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}
    if configure_sudo_wrapper && "$SYSTEM_BIN_DIR/raven" --version >/dev/null 2>&1; then
      echo "Pronto: 'raven' e 'sudo raven' já funcionam."
    else
      echo "Não foi possível configurar 'sudo raven' agora. Rode o instalador novamente para tentar de novo, ou configure manualmente:" >&2
      echo "  sudo mkdir -p $SYSTEM_BIN_DIR" >&2
      echo "  sudo sh -c \"sed 's|__RAVENEYE_HOME__|$LIB_DIR|g' $ROOT/installer/raven > $SYSTEM_BIN_DIR/raven && chmod 755 $SYSTEM_BIN_DIR/raven\"" >&2
    fi
  else
    echo "'sudo' não encontrado neste sistema; pulando o wrapper global. 'raven' (sem sudo) já funciona normalmente."
  fi
else
  echo "Termux não usa sudo; 'raven' já funciona diretamente."
fi
echo "Para desinstalar:"
echo "  sh $LIB_DIR/installer/uninstall.sh"
