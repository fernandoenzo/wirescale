#!/bin/sh

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" 1>&2
  exec sudo sh "$0" "$@"
fi

UNIT='wirescaled'
SERVICE="$UNIT.service"
SOCKET="$UNIT.socket"

systemctl stop "$SERVICE" > /dev/null 2>&1 || true
systemctl stop "$SOCKET" > /dev/null 2>&1 || true
systemctl disable "$SERVICE" > /dev/null 2>&1 || true
systemctl disable "$SOCKET" > /dev/null 2>&1 || true
rm -rf "/etc/systemd/system/$SERVICE" > /dev/null 2>&1 || true
rm -rf "/etc/systemd/system/$SOCKET" > /dev/null 2>&1 || true
rm -rf "/etc/bash_completion.d/wirescale-completion" > /dev/null 2>&1 || true
rm -rf "/etc/iproute2/rt_tables.d/wirescale.conf" > /dev/null 2>&1 || true
systemctl daemon-reload

PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx uninstall wirescale || true

echo "Success! Wirescale has been uninstalled"
