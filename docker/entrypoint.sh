#!/bin/sh
# First start: create the config, keys and token in /data. GRID_BOOTSTRAP (comma-separated multiaddrs),
# GRID_OBSERVER=1 and GRID_CAPACITY_GIB are honoured at init time only; edit /data/grid.toml afterwards.
set -e
CONFIG=/data/grid.toml
if [ ! -f "$CONFIG" ]; then
  FLAGS=""
  [ "${GRID_OBSERVER:-0}" = "1" ] && FLAGS="$FLAGS --observer"
  grid init --data-dir /data --config "$CONFIG" $FLAGS >/dev/null
  # inside a container the API must bind on all interfaces; publish 7777 only to localhost on the host
  sed -i 's/listen = "127.0.0.1:7777"/listen = "0.0.0.0:7777"/' "$CONFIG"
  if [ -n "${GRID_BOOTSTRAP:-}" ]; then
    LIST=$(printf '%s' "$GRID_BOOTSTRAP" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?", ":""), $i}}')
    sed -i "s|bootstrap = \[\]|bootstrap = [$LIST]|" "$CONFIG"
  fi
  if [ -n "${GRID_CAPACITY_GIB:-}" ]; then
    sed -i "s/capacity_gib = .*/capacity_gib = ${GRID_CAPACITY_GIB}/" "$CONFIG"
  fi
  echo "grid: initialised $CONFIG (token in /data/api.token)"
fi
if [ "$1" = "run" ]; then
  exec grid run --config "$CONFIG"
fi
exec grid --config "$CONFIG" "$@"
