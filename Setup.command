#!/bin/zsh
set -eu
cd -- "${0:A:h}"
PY=
for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(sys.version_info >= (3, 10))' 2>/dev/null; then
    PY=$c
    break
  fi
done
if [[ -z $PY ]]; then
  printf 'Python 3.10 or newer is required; system python3 on this Mac is too old.\nInstall one with: brew install python@3\n'
  read 'reply?Press Enter to close. '
  exit 1
fi
"$PY" -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
if [[ ! -f config.json ]]; then
  cp config.example.json config.json
fi
if [[ -f Configure.command ]]; then
  printf '\nDouble-click Configure.command to auto-detect your devices,\nor edit config.json manually.\n'
else
  printf '\nEdit config.json with your interface and device IP addresses before running.\n'
fi
read 'reply?Press Enter to close. '
