#!/usr/bin/env sh
# RavenEye — desinstalador. Remove o que installer/install.sh criou.
#
# Importante: config/banco/relatórios de uma sessão (raven_eye_config.json,
# data/raveneye.db, output/, reports/, raveneye.log) são gerados no diretório
# de onde você executa 'raven', não dentro da instalação — este script não
# mexe neles. Apague-os manualmente se quiser.
set -eu

usage() {
  cat <<'EOF'
Uso: sh installer/uninstall.sh [opções]

Opções:
  (nenhuma)          Remove a instalação de usuário (~/.local/bin/raven e
                      ~/.local/share/raveneye, ou os equivalentes no Termux).
  --system-wrapper    Requer root (sudo). Remove apenas o wrapper global
                      que 'install.sh' cria automaticamente em
                      /usr/local/bin/raven.
  --all               Remove instalação de usuário e wrapper de sistema
                      (o wrapper de sistema é ignorado silenciosamente se
                      não houver root).
  -y, --yes           Não pede confirmação.
  -h, --help          Mostra esta ajuda.

Variáveis de ambiente:
  RAVENEYE_BIN_DIR, RAVENEYE_LIB_DIR, RAVENEYE_SYSTEM_BIN_DIR
      Mesmas variáveis aceitas por install.sh, caso os diretórios tenham
      sido customizados na instalação.
EOF
}

MODE=user
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --system-wrapper) MODE=system ;;
    --all) MODE=all ;;
    -y|--yes) ASSUME_YES=1 ;;
    *) echo "Opção desconhecida: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

is_termux_env() {
  case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac
}

# Sob sudo, $HOME normalmente é resetado para o home de root (a menos que
# se use 'sudo -E'/'sudo -H' de outro jeito), não o do usuário que rodou o
# install.sh. Sem isto, "sudo sh uninstall.sh" (ou --all) procura a
# instalação em /root/.local em vez de ~usuário/.local, não encontra nada e
# não remove a instalação de usuário — o mesmo efeito prático de um erro de
# permissão: nada é removido apesar de estar rodando como root.
resolve_target_home() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && ! is_termux_env; then
    getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6
  else
    printf '%s' "$HOME"
  fi
}

confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  printf '%s [y/N] ' "$1"
  read -r reply || reply=""
  case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

remove_user_install() {
  TARGET_HOME=$(resolve_target_home)
  BIN_DIR="${RAVENEYE_BIN_DIR:-$TARGET_HOME/.local/bin}"
  LIB_DIR="${RAVENEYE_LIB_DIR:-$TARGET_HOME/.local/share/raveneye}"
  if is_termux_env; then
    BIN_DIR="${RAVENEYE_BIN_DIR:-$PREFIX/bin}"
    LIB_DIR="${RAVENEYE_LIB_DIR:-$PREFIX/share/raveneye}"
  fi
  found=0
  [ -e "$BIN_DIR/raven" ] && found=1
  [ -d "$LIB_DIR" ] && found=1
  if [ "$found" = "0" ]; then
    echo "Nenhuma instalação de usuário encontrada em $BIN_DIR / $LIB_DIR."
    return 0
  fi
  echo "Isto vai remover:"
  [ -e "$BIN_DIR/raven" ] && echo "  $BIN_DIR/raven"
  [ -d "$LIB_DIR" ] && echo "  $LIB_DIR (código instalado + dependências vendorizadas)"
  if ! confirm "Confirmar remoção da instalação de usuário?"; then
    echo "Cancelado."
    return 1
  fi
  rm -f "$BIN_DIR/raven"
  rm -rf "$LIB_DIR"
  echo "Instalação de usuário removida."
}

remove_system_wrapper() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Remoção do wrapper de sistema requer root. Execute: sudo sh $0 --system-wrapper" >&2
    return 1
  fi
  SYSTEM_BIN_DIR=${RAVENEYE_SYSTEM_BIN_DIR:-/usr/local/bin}
  if [ ! -e "$SYSTEM_BIN_DIR/raven" ]; then
    echo "Nenhum wrapper de sistema encontrado em $SYSTEM_BIN_DIR."
    return 0
  fi
  if ! confirm "Remover $SYSTEM_BIN_DIR/raven?"; then
    echo "Cancelado."
    return 1
  fi
  rm -f "$SYSTEM_BIN_DIR/raven"
  echo "Wrapper de sistema removido."
}

case "$MODE" in
  user) remove_user_install ;;
  system) remove_system_wrapper ;;
  all)
    remove_user_install || true
    if [ "$(id -u)" -eq 0 ]; then
      remove_system_wrapper || true
    else
      echo "Pulando o wrapper de sistema (não é root). Rode depois: sudo sh $0 --system-wrapper"
    fi
    ;;
esac
