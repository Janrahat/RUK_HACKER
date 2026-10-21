#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  RUK_HACKER — Termux installer
#  Usage:  bash install.sh          (install / upgrade)
#          bash install.sh --no-deps (skip package install)
# ============================================================
set -e

APP="RUK_HACKER"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${RUK_INSTALL_DIR:-$HOME/.local/share/ruk_hacker}"
BIN_DIR="${PREFIX:-/usr}/bin"
SKIP_DEPS=0

for arg in "$@"; do
  case "$arg" in
    --no-deps) SKIP_DEPS=1 ;;
    -h|--help)
      echo "RUK_HACKER installer"
      echo "  bash install.sh             install (asks before installing packages)"
      echo "  bash install.sh --no-deps   skip system package installation"
      echo "  RUK_INSTALL_DIR=... bash install.sh   custom install directory"
      exit 0 ;;
  esac
done

c_green='\033[1;32m'; c_yellow='\033[1;33m'; c_red='\033[1;31m'
c_cyan='\033[1;36m'; c_dim='\033[2m'; c_reset='\033[0m'

say()  { printf "${c_cyan}[*]${c_reset} %s\n" "$1"; }
ok()   { printf "${c_green}[+]${c_reset} %s\n" "$1"; }
warn() { printf "${c_yellow}[!]${c_reset} %s\n" "$1"; }
die()  { printf "${c_red}[x]${c_reset} %s\n" "$1"; exit 1; }

echo
printf "${c_green}"
cat <<'BANNER'
 ____  _   _ _  __   _   _    _    ____ _  _______ ____
|  _ \| | | | |/ /  | | | |  / \  / ___| |/ / ____|  _ \
| |_) | | | | ' /   | |_| | / _ \| |   | ' /|  _| | |_) |
|  _ <| |_| | . \   |  _  |/ ___ \ |___| . \| |___|  _ <
|_| \_\\___/|_|\_\  |_| |_/_/   \_\____|_|\_\_____|_| \_\
BANNER
printf "${c_reset}"
echo "        Termux Security Toolkit — installer"
echo "        Authorised testing only."
echo

# ---------- environment checks ----------
if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
  ok "Termux environment detected ($PREFIX)"
else
  warn "Not running inside Termux — continuing in portable Python mode"
fi

# ---------- python ----------
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  if [ "$SKIP_DEPS" -eq 1 ]; then
    die "python is not installed. Run: pkg install python"
  fi
  say "Installing python…"
  pkg update -y >/dev/null 2>&1 || true
  pkg install -y python || die "could not install python"
fi

if command -v python3 >/dev/null 2>&1; then PY_BIN="$(command -v python3)"; else PY_BIN="$(command -v python)"; fi
PY_VERSION="$("$PY_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ok "Python $PY_VERSION at $PY_BIN"
"$PY_BIN" - <<'PYCHECK' || die "Python 3.8 or newer is required"
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
PYCHECK

# ---------- optional external tools ----------
OPTIONAL_PKGS=""
for pair in "openssl:openssl" "curl:curl" "dig:dnsutils" "whois:whois" "nmap:nmap" "jq:jq"; do
  cmd="${pair%%:*}"; pkgname="${pair##*:}"
  command -v "$cmd" >/dev/null 2>&1 || OPTIONAL_PKGS="$OPTIONAL_PKGS $pkgname"
done

if [ -n "$OPTIONAL_PKGS" ] && [ "$SKIP_DEPS" -eq 0 ]; then
  warn "Optional tools not found:$OPTIONAL_PKGS"
  printf "    Install them now? [y/N] "
  read -r answer </dev/tty || answer="n"
  case "$answer" in
    y|Y|yes|YES)
      pkg install -y $OPTIONAL_PKGS || warn "some optional packages failed — core features still work"
      ;;
    *) warn "skipped — RUK_HACKER works without them" ;;
  esac
elif [ -z "$OPTIONAL_PKGS" ]; then
  ok "All optional tools present"
fi

# ---------- install files ----------
say "Installing to $INSTALL_DIR"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -R "$SRC_DIR/ruk_hacker" "$INSTALL_DIR/" 2>/dev/null || die "copy failed"
cp "$SRC_DIR/ruk_hacker.py" "$INSTALL_DIR/"
[ -f "$SRC_DIR/README.md" ] && cp "$SRC_DIR/README.md" "$INSTALL_DIR/"
[ -f "$SRC_DIR/LICENSE" ] && cp "$SRC_DIR/LICENSE" "$INSTALL_DIR/"
[ -f "$SRC_DIR/version.json" ] && cp "$SRC_DIR/version.json" "$INSTALL_DIR/"
find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
ok "Files installed"

# ---------- launcher ----------
mkdir -p "$BIN_DIR" 2>/dev/null || true
LAUNCHER="$BIN_DIR/ruk_hacker"
cat > "$LAUNCHER" <<EOF
#!$BIN_DIR/env bash
exec "$PY_BIN" "$INSTALL_DIR/ruk_hacker.py" "\$@"
EOF
chmod 755 "$LAUNCHER"
ok "Launcher created: $LAUNCHER"

# also expose a short alias
for alias_name in ruk; do
  if [ ! -e "$BIN_DIR/$alias_name" ]; then
    cat > "$BIN_DIR/$alias_name" <<EOF
#!$BIN_DIR/env bash
exec "$PY_BIN" "$INSTALL_DIR/ruk_hacker.py" "\$@"
EOF
    chmod 755 "$BIN_DIR/$alias_name"
    ok "Short alias created: $alias_name"
  fi
done

# ---------- config dir ----------
mkdir -p "$HOME/.ruk_hacker" "$HOME/ruk_reports"
ok "Reports will be saved to ~/ruk_reports"

# ---------- smoke test ----------
say "Running a quick self-test…"
if "$PY_BIN" "$INSTALL_DIR/ruk_hacker.py" version >/dev/null 2>&1; then
  ok "Self-test passed"
else
  warn "Self-test failed — run: $PY_BIN $INSTALL_DIR/ruk_hacker.py version"
fi

echo
printf "${c_green}────────────────────────────────────────────${c_reset}\n"
printf "${c_green}  RUK_HACKER installed successfully!${c_reset}\n"
printf "${c_green}────────────────────────────────────────────${c_reset}\n"
echo "  Start the interactive menu:   ruk_hacker"
echo "  Or the short alias:           ruk"
echo "  Quick scan:                   ruk_hacker scan example.com -p top"
echo "  Help:                         ruk_hacker --help"
echo
echo "  Uninstall later with:         bash uninstall.sh"
echo "  ⚠  Use only on systems you own or have written permission to test."
echo
