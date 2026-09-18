#!/usr/bin/env bash
# BD-OSINT v3 setup:  bash setup.sh [--test|--clean]
set -euo pipefail
cd "$(dirname "$0")"
GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; RED='\033[31m'; RESET='\033[0m'
say()  { echo -e "${CYAN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[x]${RESET} $*" >&2; exit 1; }

case "${1:-}" in
  --test) T=true ;; --clean) rm -rf .venv cache reports; echo "[clean] done"; exit 0 ;; "") T=false ;;
  *) die "Unknown option: $1" ;;
esac

command -v python3 >/dev/null || die "python3 not found"
python3 -c 'import sys; exit(0 if sys.version_info >= (3,10) else 1)' || die "Python 3.10+ required"
say "Creating venv..."; python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
mkdir -p cache reports wordlists
say "Smoke test..."; python3 -c "import bdosint; print(f'BD-OSINT v{bdosint.__version__} OK')"
if $T; then pytest -v; fi
echo -e "${GREEN}[OK] Setup complete.${RESET}"
echo "  source .venv/bin/activate"
echo "  python3 bdosint.py example.com.bd --profile passive"
