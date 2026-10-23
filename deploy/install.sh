#!/bin/sh
# Install The Grid and join the Atlas.
#
#   curl -fsSL https://raw.githubusercontent.com/agentlinkprotocol/grid/main/deploy/install.sh | sh
#
# Environment variables (all optional):
#   GRID_VERSION     release to install, e.g. v0.1.0 (default: the latest versioned release)
#   GRID_BOOTSTRAP   comma-separated multiaddrs of nodes to join through
#                    (default: the project's bootstrap nodes built into the binary)
#   GRID_OBSERVER=1  enable observer mode (feeds the public Console)
#   GRID_CAPACITY_GIB declared storage capacity (default 10)
#   GRID_DATA_DIR    data directory (default /var/lib/grid; ~/.grid on macOS)
#   GRID_PREFIX      where to put the binaries (default /usr/local/bin)
#   GRID_NO_SERVICE=1 do not install / start the systemd service
#   GRID_TARBALL     local release tarball instead of downloading (offline installs, tests)
set -eu

REPO="agentlinkprotocol/grid"
VERSION="${GRID_VERSION:-}"
PREFIX="${GRID_PREFIX:-/usr/local/bin}"
BOOTSTRAP="${GRID_BOOTSTRAP:-}"
OBSERVER="${GRID_OBSERVER:-0}"
CAPACITY="${GRID_CAPACITY_GIB:-}"
NO_SERVICE="${GRID_NO_SERVICE:-0}"
TARBALL="${GRID_TARBALL:-}"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  linux)  DATA="${GRID_DATA_DIR:-/var/lib/grid}"; SUDO=$([ "$(id -u)" = 0 ] && echo "" || echo "sudo") ;;
  darwin) DATA="${GRID_DATA_DIR:-$HOME/.grid}"; SUDO=$([ -w "$PREFIX" ] && echo "" || echo "sudo"); NO_SERVICE=1 ;;
  *) die "unsupported OS: $OS (Linux and macOS are supported; use Docker elsewhere)" ;;
esac
case "$OS-$ARCH" in
  linux-x86_64)            TARGET=x86_64-unknown-linux-gnu ;;
  linux-aarch64|linux-arm64) TARGET=aarch64-unknown-linux-gnu ;;
  darwin-arm64)            TARGET=aarch64-apple-darwin ;;
  darwin-x86_64)           die "no Intel macOS build yet: cargo install from source, or run the Docker image" ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
need tar; need curl
[ -n "$SUDO" ] && need sudo

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

if [ -z "$TARBALL" ]; then
  if [ -z "$VERSION" ]; then
    say "Looking up the latest release of $REPO"
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || die "could not determine the latest release (no release published yet?) - set GRID_VERSION"
  fi
  ASSET="grid-$VERSION-$TARGET.tar.gz"
  URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
  say "Downloading $ASSET"
  curl -fsSL -o "$TMP/$ASSET" "$URL" || die "download failed: $URL"
  curl -fsSL -o "$TMP/$ASSET.sha256" "$URL.sha256" || die "checksum download failed"
  (cd "$TMP" && (command -v sha256sum >/dev/null 2>&1 && sha256sum -c "$ASSET.sha256" >/dev/null || shasum -a 256 -c "$ASSET.sha256" >/dev/null)) || die "checksum mismatch"
  TARBALL="$TMP/$ASSET"
else
  say "Installing from local tarball $TARBALL"
fi

tar -xzf "$TARBALL" -C "$TMP"
BIN_DIR=$(find "$TMP" -maxdepth 2 -name grid -type f | head -1 | xargs dirname)
[ -n "$BIN_DIR" ] || die "tarball does not contain the grid binary"

say "Installing binaries into $PREFIX"
$SUDO install -d "$PREFIX"
for b in grid grid-mapbuild grid-sim; do
  [ -f "$BIN_DIR/$b" ] && $SUDO install -m 0755 "$BIN_DIR/$b" "$PREFIX/$b"
done
"$PREFIX/grid" --version

if [ "$OS" = "linux" ]; then
  if ! id grid >/dev/null 2>&1; then
    say "Creating system user 'grid'"
    $SUDO useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin grid 2>/dev/null || $SUDO adduser --system --home "$DATA" --no-create-home --group grid
  fi
  $SUDO install -d -o grid -g grid -m 0750 "$DATA"
  # run a command as the grid user, whether we are root or a sudoer
  as_grid() {
    if [ "$(id -u)" = 0 ]; then
      if command -v runuser >/dev/null 2>&1; then runuser -u grid -- "$@"; else su -s /bin/sh grid -c "$*"; fi
    else
      sudo -u grid "$@"
    fi
  }
else
  install -d -m 0750 "$DATA"
  as_grid() { "$@"; }
fi

CONFIG="$DATA/grid.toml"
if [ ! -f "$CONFIG" ]; then
  say "Initialising $CONFIG"
  FLAGS=""; [ "$OBSERVER" = "1" ] && FLAGS="--observer"
  as_grid "$PREFIX/grid" init --data-dir "$DATA" --config "$CONFIG" $FLAGS >/dev/null
  if [ -n "$BOOTSTRAP" ]; then
    LIST=$(printf '%s' "$BOOTSTRAP" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?", ":""), $i}}')
    as_grid sed -i.bak "s|^bootstrap = \[\]|bootstrap = [$LIST]|" "$CONFIG" && as_grid rm -f "$CONFIG.bak"
  fi
  if [ -n "$CAPACITY" ]; then
    as_grid sed -i.bak "s/^capacity_gib = .*/capacity_gib = $CAPACITY/" "$CONFIG" && as_grid rm -f "$CONFIG.bak"
  fi
else
  say "Keeping existing $CONFIG"
fi

if [ "$OS" = "linux" ] && [ "$NO_SERVICE" != "1" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    say "Installing systemd service"
    UNIT_SRC="$BIN_DIR/grid.service"
    [ -f "$UNIT_SRC" ] || UNIT_SRC="$TMP/grid.service"
    [ -f "$UNIT_SRC" ] || curl -fsSL -o "$UNIT_SRC" "https://raw.githubusercontent.com/$REPO/main/deploy/grid.service"
    $SUDO sed "s|/var/lib/grid|$DATA|g; s|/usr/local/bin/grid|$PREFIX/grid|g" "$UNIT_SRC" > "$TMP/grid.service.final"
    $SUDO install -m 0644 "$TMP/grid.service.final" /etc/systemd/system/grid.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now grid
    sleep 2
    $SUDO systemctl --no-pager --lines=5 status grid || true
  else
    say "systemd not found: start the node with: sudo -u grid $PREFIX/grid run --config $CONFIG"
  fi
fi

cat <<MSG

The Grid is installed.

  config:     $CONFIG
  node key:   $DATA/node.key           (back it up: position and seniority are tied to it)
  API token:  $DATA/api.token          (anything that reads it can publish through your node)
  API:        http://127.0.0.1:7777    (grid status --config $CONFIG)
  firewall:   open 4001/udp and 4001/tcp

MSG
if [ "$OS" = "linux" ] && [ "$NO_SERVICE" != "1" ]; then
  echo "  logs:       journalctl -u grid -f"
else
  echo "  run:        grid run --config $CONFIG"
fi
