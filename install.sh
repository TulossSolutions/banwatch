#!/bin/sh
set -eu

# BanWatch installer
# Installs the CLI wrapper to /usr/local/bin and runtime code to /usr/local/lib/banwatch.
# Usage:
#   sudo sh install.sh
#   curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo sh
#
# Environment overrides:
#   PREFIX=/usr/local
#   BANWATCH_REF=main
#   BANWATCH_REPO=https://github.com/TulossSolutions/banwatch
#   RUN_SETUP=1
#   INSTALL_SYSTEMD=1
#   START_SERVICE=1

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"
LIB_ROOT="${LIB_ROOT:-$PREFIX/lib/banwatch}"
BANWATCH_REPO="${BANWATCH_REPO:-https://github.com/TulossSolutions/banwatch}"
BANWATCH_REF="${BANWATCH_REF:-main}"
RUN_SETUP="${RUN_SETUP:-0}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-0}"
START_SERVICE="${START_SERVICE:-0}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

as_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root, for example: sudo sh install.sh" >&2
        exit 1
    fi
}

make_temp_dir() {
    tmp="$(mktemp -d 2>/dev/null || mktemp -d -t banwatch)"
    echo "$tmp"
}

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

find_source_dir() {
    script_dir=""
    case "${0:-}" in
        */*) script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || script_dir="" ;;
    esac

    if [ -n "$script_dir" ] && [ -f "$script_dir/banwatch" ] && [ -d "$script_dir/banwatch_core" ]; then
        echo "$script_dir"
        return 0
    fi

    if [ -f "./banwatch" ] && [ -d "./banwatch_core" ]; then
        pwd
        return 0
    fi

    return 1
}

download_source() {
    need_cmd tar
    TMP_DIR="$(make_temp_dir)"
    archive="$TMP_DIR/banwatch.tar.gz"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$BANWATCH_REPO/archive/refs/heads/$BANWATCH_REF.tar.gz" -o "$archive"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$archive" "$BANWATCH_REPO/archive/refs/heads/$BANWATCH_REF.tar.gz"
    else
        echo "Missing curl or wget to download BanWatch." >&2
        exit 1
    fi

    tar -xzf "$archive" -C "$TMP_DIR"
    src="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'banwatch-*' | head -n 1)"
    if [ -z "$src" ] || [ ! -f "$src/banwatch" ] || [ ! -d "$src/banwatch_core" ]; then
        echo "Downloaded archive does not look like a BanWatch release." >&2
        exit 1
    fi
    echo "$src"
}

install_files() {
    src="$1"

    mkdir -p "$BIN_DIR" "$LIB_ROOT"
    rm -rf "$LIB_ROOT/banwatch_core"
    cp -R "$src/banwatch_core" "$LIB_ROOT/banwatch_core"

    cat > "$BIN_DIR/banwatch" <<EOF
#!/usr/bin/env python3
import sys
sys.path.insert(0, "$LIB_ROOT")
from banwatch_core.cli import main

if __name__ == "__main__":
    main()
EOF
    chmod 755 "$BIN_DIR/banwatch"

    if command -v python3 >/dev/null 2>&1; then
        python3 -m py_compile "$BIN_DIR/banwatch"
        python3 -m compileall -q "$LIB_ROOT/banwatch_core"
    else
        echo "Warning: python3 not found now; BanWatch requires Python 3.8+ at runtime." >&2
    fi
}

post_install() {
    "$BIN_DIR/banwatch" --version || true

    if [ "$RUN_SETUP" = "1" ]; then
        "$BIN_DIR/banwatch" setup
    else
        echo "Next: sudo banwatch setup"
    fi

    if [ "$INSTALL_SYSTEMD" = "1" ]; then
        "$BIN_DIR/banwatch" systemd
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload
            if [ "$START_SERVICE" = "1" ]; then
                systemctl enable --now banwatch
            else
                echo "Next: sudo systemctl enable --now banwatch"
            fi
        fi
    fi
}

as_root
need_cmd cp
need_cmd mkdir
need_cmd rm
trap cleanup EXIT INT TERM

if SRC_DIR="$(find_source_dir)"; then
    :
else
    SRC_DIR="$(download_source)"
fi

install_files "$SRC_DIR"
post_install

echo "BanWatch installed."
