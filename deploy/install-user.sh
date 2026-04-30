#!/usr/bin/env bash
#
# Zabbix MCP Server - User-mode installer (no root required)
# Copyright (C) 2026 initMAX s.r.o.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Installs zabbix-mcp-server as a user-level background service.
# No sudo/root required. Designed for developers running the server locally.
#
#   macOS  — LaunchAgent  (~Library/LaunchAgents/)
#   Linux  — systemd user (~/.config/systemd/user/)
#
# Usage:
#   ./deploy/install-user.sh              # install
#   ./deploy/install-user.sh update       # update (git pull + pip + restart)
#   ./deploy/install-user.sh uninstall    # stop and remove service files
#   ./deploy/install-user.sh -h           # show help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="zabbix-mcp-server"
VENV="$SCRIPT_DIR/.venv"
CONFIG_FILE="$SCRIPT_DIR/config.toml"
LOG_DIR="$SCRIPT_DIR/logs"
PYTHON_BIN=""

# macOS
PLIST_LABEL="com.initmax.zabbix-mcp-server"
PLIST_FILE="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"

# Linux
SYSTEMD_UNIT_FILE="$HOME/.config/systemd/user/${SERVICE_NAME}.service"

OS="$(uname -s)"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
info()  { echo -e "\e[1;34m>>>\e[0m $*"; }
ok()    { echo -e "\e[1;32m>>>\e[0m $*"; }
warn()  { echo -e "\e[1;33m>>>\e[0m $*"; }
error() { echo -e "\e[1;31m>>>\e[0m $*" >&2; }

show_help() {
    cat <<HELP
Zabbix MCP Server — User-mode installer

  ./deploy/install-user.sh              Install as user-level service
  ./deploy/install-user.sh update       Update (git pull + pip + restart)
  ./deploy/install-user.sh uninstall    Stop and remove service files
  ./deploy/install-user.sh -h           Show this help

No root required. Runs as the current user ($USER).

Supported platforms:
  macOS  LaunchAgent  — $PLIST_FILE
  Linux  systemd user — $SYSTEMD_UNIT_FILE
HELP
}

find_python() {
    local candidates=("python3.13" "python3.12" "python3.11" "python3.10" "python3")
    local min_minor=10
    for candidate in "${candidates[@]}"; do
        if command -v "$candidate" &>/dev/null; then
            local ver minor
            ver=$("$candidate" --version 2>&1)
            minor=$(echo "$ver" | sed -n 's/Python 3\.\([0-9]*\)\..*/\1/p')
            if [[ -n "$minor" && "$minor" -ge "$min_minor" ]]; then
                PYTHON_BIN="$candidate"
                info "Using $candidate ($ver)"
                return 0
            fi
        fi
    done
    error "Python >=3.10 not found. Install it via your package manager."
    exit 1
}

setup_venv() {
    if [[ ! -x "$VENV/bin/python" || ! -x "$VENV/bin/pip" ]]; then
        [[ -d "$VENV" ]] && rm -rf "$VENV"
        info "Creating virtualenv..."
        if ! "$PYTHON_BIN" -m venv "$VENV" 2>/dev/null; then
            # Debian/Ubuntu: python3-venv is a separate package
            local pkg="python3-venv"
            command -v apt-get &>/dev/null && pkg="python${PYTHON_BIN##python}-venv" || true
            error "Failed to create virtualenv. On Debian/Ubuntu, run:"
            error "  sudo apt-get install -y $pkg"
            exit 1
        fi
    fi
    info "Installing / upgrading package..."
    "$VENV/bin/pip" install -e "$SCRIPT_DIR" -q
    ok "Package ready: $("$VENV/bin/zabbix-mcp-server" --version)"
}

setup_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        warn "Config already exists — not overwriting: $CONFIG_FILE"
        return
    fi
    local example="$SCRIPT_DIR/config.example.toml"
    if [[ ! -f "$example" ]]; then
        error "config.example.toml not found in $SCRIPT_DIR"
        exit 1
    fi
    info "Copying example config to $CONFIG_FILE ..."
    cp "$example" "$CONFIG_FILE"
    # Redirect log_file to user-writable path (default /var/log/... requires root)
    sed -i.bak "s|^log_file = .*|log_file = \"${LOG_DIR}/server.log\"|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
    ok "Config created. Edit before starting: $CONFIG_FILE"
}

# --------------------------------------------------------------------------- #
# macOS — LaunchAgent
# --------------------------------------------------------------------------- #
install_launchd() {
    mkdir -p "$LOG_DIR" "$(dirname "$PLIST_FILE")"
    cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${VENV}/bin/zabbix-mcp-server</string>
        <string>--config</string>
        <string>${CONFIG_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${SCRIPT_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/server.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/server.log</string>
</dict>
</plist>
PLIST
    # bootstrap is preferred on macOS 10.15+; fall back to load for older systems
    launchctl bootstrap "gui/$(id -u)" "$PLIST_FILE" 2>/dev/null || launchctl load "$PLIST_FILE"
    ok "LaunchAgent loaded: $PLIST_LABEL"
}

uninstall_launchd() {
    if [[ -f "$PLIST_FILE" ]]; then
        launchctl unload "$PLIST_FILE" 2>/dev/null || true
        rm -f "$PLIST_FILE"
        ok "LaunchAgent removed."
    else
        warn "LaunchAgent plist not found — nothing to remove."
    fi
}

restart_launchd() {
    if [[ ! -f "$PLIST_FILE" ]]; then
        warn "LaunchAgent not installed yet — skipping restart."
        return
    fi
    launchctl kickstart -k "gui/$(id -u)/${PLIST_LABEL}" 2>/dev/null || \
        { launchctl unload "$PLIST_FILE" 2>/dev/null || true
          launchctl load "$PLIST_FILE"; }
}

# --------------------------------------------------------------------------- #
# Linux — systemd --user
# --------------------------------------------------------------------------- #
install_systemd_user() {
    mkdir -p "$LOG_DIR" "$(dirname "$SYSTEMD_UNIT_FILE")"
    cat > "$SYSTEMD_UNIT_FILE" <<UNIT
[Unit]
Description=Zabbix MCP Server (user mode)
After=network.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV}/bin/zabbix-mcp-server --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/server.log
StandardError=append:${LOG_DIR}/server.log

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE_NAME"
    ok "systemd user service enabled and started: $SERVICE_NAME"
    # Enable linger so the service survives logout (requires loginctl)
    if command -v loginctl &>/dev/null; then
        if loginctl enable-linger "$(id -un)" 2>/dev/null; then
            ok "Linger enabled — service will survive logout."
        else
            warn "Could not enable linger. Service stops on logout."
        fi
    fi
}

uninstall_systemd_user() {
    if [[ -f "$SYSTEMD_UNIT_FILE" ]]; then
        systemctl --user disable --now "$SERVICE_NAME" 2>/dev/null || true
        rm -f "$SYSTEMD_UNIT_FILE"
        systemctl --user daemon-reload
        ok "systemd user service removed."
    else
        warn "systemd user service not found — nothing to remove."
    fi
}

restart_systemd_user() {
    if [[ ! -f "$SYSTEMD_UNIT_FILE" ]]; then
        warn "systemd user service not installed yet — skipping restart."
        return
    fi
    systemctl --user restart "$SERVICE_NAME"
}

# --------------------------------------------------------------------------- #
# OS dispatch
# --------------------------------------------------------------------------- #
service_install()   { if [[ "$OS" == "Darwin" ]]; then install_launchd;       else install_systemd_user;   fi; }
service_uninstall() { if [[ "$OS" == "Darwin" ]]; then uninstall_launchd;     else uninstall_systemd_user; fi; }
service_restart()   { if [[ "$OS" == "Darwin" ]]; then restart_launchd;       else restart_systemd_user;   fi; }

# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #
do_install() {
    info "=== Zabbix MCP Server — User-mode Install ==="
    echo
    find_python
    setup_venv
    setup_config
    service_install
    echo
    ok "=== Installation complete ==="
    echo
    echo "  Config:       $CONFIG_FILE"
    echo "  Logs:         $LOG_DIR/server.log"
    echo "  Health check: curl http://127.0.0.1:8080/health"
    echo
    echo "  Edit config, then restart:"
    if [[ "$OS" == "Darwin" ]]; then
        echo "    launchctl kickstart -k gui/\$(id -u)/${PLIST_LABEL}"
    else
        echo "    systemctl --user restart $SERVICE_NAME"
    fi
    echo
}

do_update() {
    info "=== Zabbix MCP Server — Update ==="
    echo
    local old_ver
    old_ver=$("$VENV/bin/zabbix-mcp-server" --version 2>/dev/null || echo "unknown")
    info "Current version: $old_ver"
    info "Pulling latest from git..."
    git -C "$SCRIPT_DIR" pull
    find_python
    setup_venv
    service_restart
    local new_ver
    new_ver=$("$VENV/bin/zabbix-mcp-server" --version 2>/dev/null || echo "unknown")
    echo
    ok "Updated: $old_ver → $new_ver"
    echo
}

do_uninstall() {
    info "=== Zabbix MCP Server — Uninstall ==="
    echo
    service_uninstall
    warn "Virtualenv and config left in place: $SCRIPT_DIR"
    warn "Remove manually if no longer needed."
    echo
    ok "=== Uninstall complete ==="
    echo
}

# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
if [[ "$OS" != "Darwin" && "$OS" != "Linux" ]]; then
    error "Unsupported OS: $OS (supported: macOS, Linux)"
    exit 1
fi

case "${1:-install}" in
    install)   do_install   ;;
    update)    do_update    ;;
    uninstall) do_uninstall ;;
    -h|--help) show_help    ;;
    *)
        error "Unknown command: ${1}"
        echo
        show_help
        exit 1
        ;;
esac
