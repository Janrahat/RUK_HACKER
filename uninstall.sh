#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  RUK_HACKER — uninstaller
#  Usage:  bash uninstall.sh            (keeps reports + config)
#          bash uninstall.sh --purge    (also deletes config + reports)
#          bash uninstall.sh --dry-run  (show what would be removed)
# ============================================================
set -e

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${RUK_INSTALL_DIR:-$HOME/.local/share/ruk_hacker}"
BIN_DIR="${PREFIX:-/usr}/bin"
CONFIG_DIR="$HOME/.ruk_hacker"
REPORT_DIR="$HOME/ruk_reports"
PURGE=0
DRY=0

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help)
      echo "RUK_HACKER uninstaller"
      echo "  bash uninstall.sh             remove the tool, keep reports/config"
      echo "  bash uninstall.sh --purge     also delete ~/.ruk_hacker and ~/ruk_reports"
      echo "  bash uninstall.sh --dry-run   only print what would be deleted"
      exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

c_green='\033[1;32m'; c_yellow='\033[1;33m'; c_red='\033[1;31m'
c_cyan='\033[1;36m'; c_reset='\033[0m'
say()  { printf "${c_cyan}[*]${c_reset} %s\n" "$1"; }
ok()   { printf "${c_green}[+]${c_reset} %s\n" "$1"; }
warn() { printf "${c_yellow}[!]${c_reset} %s\n" "$1"; }

remove() {
  target="$1"
  if [ ! -e "$target" ]; then
    return 0
  fi
  if [ "$DRY" -eq 1 ]; then
    printf "${c_yellow}would remove${c_reset} %s\n" "$target"
    return 0
  fi
  rm -rf "$target" 2>/dev/null || { warn "could not remove $target (permission?)"; return 1; }
  ok "removed $target"
}

echo
say "Uninstalling RUK_HACKER"
echo

remove "$BIN_DIR/ruk_hacker"
remove "$BIN_DIR/ruk"
remove "$INSTALL_DIR"

# clean any __pycache__ left in a source checkout (safe, only if present)
if [ -d "$SRC_DIR/ruk_hacker" ]; then
  find "$SRC_DIR/ruk_hacker" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
fi

if [ "$PURGE" -eq 1 ]; then
  warn "Purge mode: deleting configuration and reports"
  remove "$CONFIG_DIR"
  remove "$REPORT_DIR"
else
  echo
  ok "Kept your data:"
  echo "     config : $CONFIG_DIR"
  echo "     reports: $REPORT_DIR"
  echo "     run 'bash uninstall.sh --purge' to delete them too"
fi

echo
ok "RUK_HACKER has been uninstalled."
echo "     System packages installed by the installer (python, nmap, …) were left in place."
echo
