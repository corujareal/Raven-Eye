#!/usr/bin/env sh
# RavenEye — remove only an installation identified as RavenEye.
set -eu

usage() {
  cat <<'EOF'
Uso: sh installer/uninstall.sh [opções]

Opções:
  (nenhuma)          Remove a instalação de usuário identificada como RavenEye.
  --system-wrapper    Remove o wrapper RavenEye em /usr/local/bin (requer root).
  --all               Remove a instalação de usuário e, com root, o wrapper global.
  --dry-run           Mostra ações sem remover arquivos ou pedir confirmação.
  -y, --yes           Não pede confirmação.
  -h, --help          Mostra esta ajuda.

Variáveis de ambiente:
  RAVENEYE_BIN_DIR, RAVENEYE_LIB_DIR, RAVENEYE_SYSTEM_BIN_DIR
      Mesmas variáveis aceitas por install.sh, para destinos customizados.
EOF
}

MODE=user
ASSUME_YES=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --system-wrapper) MODE=system ;;
    --all) MODE=all ;;
    --dry-run) DRY_RUN=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    *) echo "Opção desconhecida: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

is_termux_env() {
  case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac
}

read_os_release_field() {
  field=$1
  release_file=/etc/os-release
  [ -r "$release_file" ] || release_file=/usr/lib/os-release
  [ -r "$release_file" ] || return 0
  value=$(sed -n "s/^${field}=//p" "$release_file" | head -n 1)
  value=${value#\"}; value=${value%\"}
  value=${value#\'}; value=${value%\'}
  printf '%s' "$value"
}

detect_environment() {
  if is_termux_env; then distro=Termux; else distro=$(read_os_release_field PRETTY_NAME); fi
  [ -n "$distro" ] || distro=$(uname -s 2>/dev/null || printf 'Unix')
  manager='não detectado'
  if is_termux_env && command -v pkg >/dev/null 2>&1; then manager='pkg (Termux)'; else
    for candidate in apt-get dnf yum pacman zypper apk brew pkg; do
      if command -v "$candidate" >/dev/null 2>&1; then manager=$candidate; break; fi
    done
  fi
  if [ "$(id -u)" -eq 0 ]; then privilege=root; else privilege=sem-root; fi
  printf 'Ambiente: %s\nPrivilégio: %s\nGerenciador detectado: %s\n' "$distro" "$privilege" "$manager"
}

validate_absolute_path() {
  label=$1
  candidate=$2
  case "$candidate" in
    /*) ;;
    *) echo "$label precisa ser absoluto: $candidate" >&2; return 1 ;;
  esac
  case "$candidate" in */../*|*/..|*/./*|*/.)
    echo "$label não pode conter componentes '.' ou '..': $candidate" >&2
    return 1
    ;;
  esac
  case "$candidate" in *'
'*) echo "$label não pode conter quebra de linha." >&2; return 1 ;; esac
}

resolve_target_home() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && ! is_termux_env; then
    resolved=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)
    if [ -z "$resolved" ] && [ -r /etc/passwd ]; then
      resolved=$(awk -F: -v name="$SUDO_USER" '$1 == name { print $6; exit }' /etc/passwd)
    fi
    printf '%s' "$resolved"
  else
    printf '%s' "${HOME:-}"
  fi
}

launcher_is_raveneye() {
  candidate=$1
  [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
  grep -F 'RAVENEYE_LAUNCHER=1' "$candidate" >/dev/null 2>&1 ||
    grep -F 'RAVENEYE_HOME=' "$candidate" >/dev/null 2>&1
}

install_is_raveneye() {
  directory=$1
  [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
  if [ -f "$directory/.raveneye-install" ] && [ ! -L "$directory/.raveneye-install" ]; then
    grep -F 'RavenEye' "$directory/.raveneye-install" >/dev/null 2>&1 && return 0
  fi
  [ -f "$directory/RavenEye.py" ] && [ -f "$directory/raveneye_pkg/constants.py" ]
}

confirm() {
  [ "$DRY_RUN" = 1 ] && return 0
  [ "$ASSUME_YES" = 1 ] && return 0
  printf '%s [y/N] ' "$1"
  read -r reply || reply=
  case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

remove_user_install() {
  TARGET_HOME=$(resolve_target_home)
  validate_absolute_path 'HOME do usuário' "$TARGET_HOME"
  BIN_DIR=${RAVENEYE_BIN_DIR:-$TARGET_HOME/.local/bin}
  LIB_DIR=${RAVENEYE_LIB_DIR:-$TARGET_HOME/.local/share/raveneye}
  if is_termux_env; then
    BIN_DIR=${RAVENEYE_BIN_DIR:-$PREFIX/bin}
    LIB_DIR=${RAVENEYE_LIB_DIR:-$PREFIX/share/raveneye}
  fi
  validate_absolute_path 'RAVENEYE_BIN_DIR' "$BIN_DIR"
  validate_absolute_path 'RAVENEYE_LIB_DIR' "$LIB_DIR"
  case "$LIB_DIR" in
    /|"$TARGET_HOME"|"$TARGET_HOME/"|"${PREFIX:-/non-termux}"|"${PREFIX:-/non-termux}/")
      echo "RAVENEYE_LIB_DIR aponta para um diretório protegido: $LIB_DIR" >&2
      return 1
      ;;
  esac
  [ ! -L "$BIN_DIR" ] || { echo "Diretório de binários é link simbólico; nada será removido: $BIN_DIR" >&2; return 1; }
  [ ! -L "$LIB_DIR" ] || { echo "Diretório de instalação é link simbólico; nada será removido: $LIB_DIR" >&2; return 1; }

  launcher="$BIN_DIR/raven"
  sidecar="$BIN_DIR/raven.home"
  remove_launcher=0
  remove_library=0
  if [ -e "$launcher" ] || [ -L "$launcher" ]; then
    if launcher_is_raveneye "$launcher"; then
      remove_launcher=1
    else
      echo "O comando existente não foi identificado como RavenEye e será preservado: $launcher" >&2
      return 1
    fi
  fi
  if [ -d "$LIB_DIR" ]; then
    install_is_raveneye "$LIB_DIR" || {
      echo "O destino existe, mas não foi identificado como instalação RavenEye; nada será removido: $LIB_DIR" >&2
      return 1
    }
    remove_library=1
  elif [ -e "$LIB_DIR" ]; then
    echo "O destino não é um diretório RavenEye seguro; nada será removido: $LIB_DIR" >&2
    return 1
  fi
  if [ -L "$sidecar" ]; then
    echo "O arquivo lateral do launcher é link simbólico; nada será removido: $sidecar" >&2
    return 1
  fi
  if [ -f "$sidecar" ] && [ "$remove_launcher" = 1 ]; then
    sidecar_home=$(sed -n '1p' "$sidecar")
    [ "$sidecar_home" = "$LIB_DIR" ] || {
      echo "O launcher aponta para outra instalação; o arquivo lateral será preservado: $sidecar" >&2
      return 1
    }
  fi
  if [ "$remove_launcher" = 0 ] && [ "$remove_library" = 0 ]; then
    echo "Nenhuma instalação RavenEye encontrada em $BIN_DIR / $LIB_DIR."
    return 0
  fi
  echo "Ações de remoção:"
  [ "$remove_launcher" = 0 ] || echo "  remover $launcher e o arquivo lateral RavenEye correspondente"
  [ "$remove_library" = 0 ] || echo "  remover $LIB_DIR (código e dependências da instalação)"
  if [ "$DRY_RUN" = 1 ]; then echo "Dry-run: nenhum arquivo foi alterado."; return 0; fi
  if ! confirm "Confirmar remoção da instalação RavenEye de usuário?"; then
    echo "Cancelado." >&2
    return 1
  fi
  if [ "$remove_launcher" = 1 ]; then
    rm -f "$launcher"
    [ ! -f "$sidecar" ] || rm -f "$sidecar"
  fi
  if [ "$remove_library" = 1 ]; then rm -rf "$LIB_DIR"; fi
  echo "Instalação de usuário removida."
}

remove_system_wrapper() {
  SYSTEM_BIN_DIR=${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}
  validate_absolute_path 'RAVENEYE_SYSTEM_BIN_DIR' "$SYSTEM_BIN_DIR"
  case "$SYSTEM_BIN_DIR" in /|"${HOME:-/non-home}"|"${PREFIX:-/non-termux}"|"${PREFIX:-/non-termux}/")
    echo "RAVENEYE_SYSTEM_BIN_DIR aponta para um diretório protegido: $SYSTEM_BIN_DIR" >&2
    return 1
    ;;
  esac
  [ ! -L "$SYSTEM_BIN_DIR" ] || { echo "Diretório global de comandos é link simbólico; nada será removido: $SYSTEM_BIN_DIR" >&2; return 1; }
  wrapper="$SYSTEM_BIN_DIR/raven"
  sidecar="$SYSTEM_BIN_DIR/raven.home"
  if [ ! -e "$wrapper" ] && [ ! -L "$wrapper" ]; then
    echo "Nenhum wrapper de sistema encontrado em $SYSTEM_BIN_DIR."
    return 0
  fi
  launcher_is_raveneye "$wrapper" || {
    echo "O comando de sistema não foi identificado como RavenEye e será preservado: $wrapper" >&2
    return 1
  }
  [ ! -L "$sidecar" ] || { echo "O arquivo lateral do wrapper é link simbólico; nada será removido: $sidecar" >&2; return 1; }
  printf 'Ações de remoção:\n  remover %s e o arquivo lateral correspondente\n' "$wrapper"
  if [ "$DRY_RUN" = 1 ]; then echo "Dry-run: nenhum arquivo foi alterado."; return 0; fi
  [ "$(id -u)" -eq 0 ] || { echo "Remoção do wrapper de sistema requer root." >&2; return 1; }
  if ! confirm "Confirmar remoção do wrapper global?"; then
    echo "Cancelado." >&2
    return 1
  fi
  rm -f "$wrapper"
  [ ! -f "$sidecar" ] || rm -f "$sidecar"
  echo "Wrapper de sistema removido."
}

detect_environment
case "$MODE" in
  user) remove_user_install ;;
  system) remove_system_wrapper ;;
  all)
    remove_user_install
    if [ "$(id -u)" -eq 0 ] || [ "$DRY_RUN" = 1 ]; then
      remove_system_wrapper
    else
      echo "Wrapper de sistema preservado: requer root para remover."
    fi
    ;;
esac
