#!/bin/bash
# Use only the distribution's script and an isolated system Python.
set -euo pipefail
script_path=${BASH_SOURCE[0]}
script_parent=.
if [[ $script_path == */* ]]; then
    script_parent=${script_path%/*}
fi
script_dir=$(CDPATH='' cd -- "$script_parent" && pwd -P)
exec /usr/bin/python3 -I -B "$script_dir/prepare_game.py" "$@"
